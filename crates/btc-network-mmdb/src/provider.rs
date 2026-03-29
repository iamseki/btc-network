use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::path::PathBuf;

use btc_network::crawler::{CrawlEndpoint, IpEnrichment, IpEnrichmentProvider};
use maxminddb::geoip2;
use maxminddb::{MaxMindDbError, Reader};

use crate::config::MmdbEnrichmentConfig;

/// Error returned when the MMDB adapter cannot load its local datasets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmdbEnrichmentInitError {
    database_kind: &'static str,
    path: PathBuf,
    message: String,
}

impl MmdbEnrichmentInitError {
    fn open(database_kind: &'static str, path: PathBuf, error: MaxMindDbError) -> Self {
        Self {
            database_kind,
            path,
            message: error.to_string(),
        }
    }

    fn invalid_type(
        database_kind: &'static str,
        path: PathBuf,
        expected: &'static str,
        actual: &str,
    ) -> Self {
        Self {
            database_kind,
            path,
            message: format!("expected {expected} MMDB, found database_type={actual}"),
        }
    }
}

impl Display for MmdbEnrichmentInitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to open {} MMDB at {}: {}",
            self.database_kind,
            self.path.display(),
            self.message
        )
    }
}

impl Error for MmdbEnrichmentInitError {}

/// Local MMDB-backed implementation of the shared `IpEnrichmentProvider`.
///
/// The adapter performs eager filesystem loading and then serves synchronous
/// ASN, country, and prefix lookups for routable IPv4 and IPv6 endpoints.
#[derive(Debug)]
pub struct MmdbIpEnrichmentProvider {
    readers: Option<LoadedReaders>,
}

#[derive(Debug)]
struct LoadedReaders {
    asn_reader: Reader<Vec<u8>>,
    country_reader: Reader<Vec<u8>>,
}

impl MmdbIpEnrichmentProvider {
    /// Loads both required MMDB datasets from disk.
    pub fn new(config: MmdbEnrichmentConfig) -> Result<Self, MmdbEnrichmentInitError> {
        let asn_reader = Reader::open_readfile(config.asn_db_path()).map_err(|error| {
            MmdbEnrichmentInitError::open("ASN", config.asn_db_path().to_path_buf(), error)
        })?;
        validate_database_type(
            "ASN",
            config.asn_db_path().to_path_buf(),
            &asn_reader,
            is_asn_database_type,
            "an ASN-compatible",
        )?;
        let country_reader = Reader::open_readfile(config.country_db_path()).map_err(|error| {
            MmdbEnrichmentInitError::open("country", config.country_db_path().to_path_buf(), error)
        })?;
        validate_database_type(
            "country",
            config.country_db_path().to_path_buf(),
            &country_reader,
            is_country_database_type,
            "a country-compatible",
        )?;

        Ok(Self {
            readers: Some(LoadedReaders {
                asn_reader,
                country_reader,
            }),
        })
    }

    /// Builds a provider that reports enrichment as unavailable.
    pub fn unavailable() -> Self {
        Self { readers: None }
    }

    fn enrich_ip(
        &self,
        ip_addr: IpAddr,
        asn_reader: &Reader<Vec<u8>>,
        country_reader: &Reader<Vec<u8>>,
    ) -> IpEnrichment {
        let asn_lookup = match lookup_asn(asn_reader, ip_addr) {
            Ok(lookup) => lookup,
            Err(_) => return IpEnrichment::lookup_failed(),
        };

        let country_lookup = match lookup_country(country_reader, ip_addr) {
            Ok(lookup) => lookup,
            Err(_) => return IpEnrichment::lookup_failed(),
        };

        let prefix = asn_lookup.prefix.or(country_lookup.prefix);
        let asn = asn_lookup.asn;
        let asn_organization = asn_lookup.asn_organization;
        let country = country_lookup.country;

        if asn.is_none() && asn_organization.is_none() && country.is_none() && prefix.is_none() {
            return IpEnrichment::lookup_failed();
        }

        IpEnrichment::matched(asn, asn_organization, country, prefix)
    }
}

impl IpEnrichmentProvider for MmdbIpEnrichmentProvider {
    fn enrich(&self, endpoint: &CrawlEndpoint) -> IpEnrichment {
        if !endpoint.supports_ip_enrichment() {
            return IpEnrichment::not_applicable();
        }

        let Some(ip_addr) = endpoint.ip_addr else {
            return IpEnrichment::not_applicable();
        };

        match &self.readers {
            Some(readers) => self.enrich_ip(ip_addr, &readers.asn_reader, &readers.country_reader),
            None => IpEnrichment::unavailable(),
        }
    }
}

#[derive(Default)]
struct AsnLookup {
    asn: Option<u32>,
    asn_organization: Option<String>,
    prefix: Option<String>,
}

#[derive(Default)]
struct CountryLookup {
    country: Option<String>,
    prefix: Option<String>,
}

fn lookup_asn(reader: &Reader<Vec<u8>>, ip_addr: IpAddr) -> Result<AsnLookup, MaxMindDbError> {
    let lookup = reader.lookup(ip_addr)?;
    if !lookup.has_data() {
        return Ok(AsnLookup::default());
    }

    let prefix = Some(lookup.network()?.to_string());
    let record: geoip2::Asn<'_> = lookup
        .decode()?
        .ok_or_else(|| MaxMindDbError::invalid_input("ASN lookup returned no record"))?;

    Ok(AsnLookup {
        asn: record.autonomous_system_number,
        asn_organization: record.autonomous_system_organization.map(ToOwned::to_owned),
        prefix,
    })
}

fn lookup_country(
    reader: &Reader<Vec<u8>>,
    ip_addr: IpAddr,
) -> Result<CountryLookup, MaxMindDbError> {
    let lookup = reader.lookup(ip_addr)?;
    if !lookup.has_data() {
        return Ok(CountryLookup::default());
    }

    let prefix = Some(lookup.network()?.to_string());
    let record: geoip2::Country<'_> = lookup
        .decode()?
        .ok_or_else(|| MaxMindDbError::invalid_input("country lookup returned no record"))?;

    Ok(CountryLookup {
        country: record
            .country
            .iso_code
            .or(record.registered_country.iso_code)
            .map(ToOwned::to_owned),
        prefix,
    })
}

fn validate_database_type(
    database_kind: &'static str,
    path: PathBuf,
    reader: &Reader<Vec<u8>>,
    predicate: fn(&str) -> bool,
    expected: &'static str,
) -> Result<(), MmdbEnrichmentInitError> {
    let database_type = reader.metadata.database_type.as_str();
    if predicate(database_type) {
        return Ok(());
    }

    Err(MmdbEnrichmentInitError::invalid_type(
        database_kind,
        path,
        expected,
        database_type,
    ))
}

fn is_asn_database_type(database_type: &str) -> bool {
    database_type.contains("ASN")
}

fn is_country_database_type(database_type: &str) -> bool {
    database_type.contains("Country")
        || database_type.contains("City")
        || database_type.contains("Enterprise")
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_network::crawler::{CrawlNetwork, IpEnrichmentStatus};
    use maxminddb::Reader;
    use maxminddb_writer::paths::IpAddrWithMask;
    use maxminddb_writer::{Database, metadata};
    use serde::Serialize;
    use std::fs::File;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::{env, fs};

    #[derive(Serialize)]
    struct AsnFixture<'a> {
        autonomous_system_number: u32,
        autonomous_system_organization: &'a str,
    }

    #[derive(Serialize)]
    struct CountryIsoFixture<'a> {
        iso_code: &'a str,
    }

    #[derive(Serialize)]
    struct CountryFixture<'a> {
        country: CountryIsoFixture<'a>,
    }

    #[test]
    fn unavailable_provider_returns_unavailable() {
        let provider = MmdbIpEnrichmentProvider::unavailable();
        let endpoint = CrawlEndpoint::new(
            "1.1.1.7",
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7))),
        );

        assert_eq!(
            provider.enrich(&endpoint).status,
            IpEnrichmentStatus::Unavailable
        );
    }

    #[test]
    fn non_routable_endpoint_returns_not_applicable() {
        let provider = MmdbIpEnrichmentProvider::unavailable();
        let endpoint = CrawlEndpoint::new(
            "10.0.0.7",
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
        );

        assert_eq!(
            provider.enrich(&endpoint).status,
            IpEnrichmentStatus::NotApplicable
        );
    }

    #[test]
    fn enriches_routable_ipv4_endpoint_from_mmdb() {
        let fixture = TestFixtureDir::new();
        let asn_path = fixture.write_asn_db(
            "asn-v4.mmdb",
            metadata::IpVersion::V4,
            &[(
                "1.1.1.0/24",
                AsnFixture {
                    autonomous_system_number: 13335,
                    autonomous_system_organization: "Cloudflare, Inc.",
                },
            )],
        );
        let country_path = fixture.write_country_db(
            "country-v4.mmdb",
            metadata::IpVersion::V4,
            &[(
                "1.1.1.0/24",
                CountryFixture {
                    country: CountryIsoFixture { iso_code: "AU" },
                },
            )],
        );

        let provider =
            MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(asn_path, country_path))
                .expect("provider");
        let endpoint = CrawlEndpoint::new(
            "1.1.1.7",
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7))),
        );

        let enrichment = provider.enrich(&endpoint);

        assert_eq!(enrichment.status, IpEnrichmentStatus::Matched);
        assert_eq!(enrichment.asn, Some(13335));
        assert_eq!(
            enrichment.asn_organization.as_deref(),
            Some("Cloudflare, Inc.")
        );
        assert_eq!(enrichment.country.as_deref(), Some("AU"));
        assert_eq!(enrichment.prefix.as_deref(), Some("1.1.1.0/24"));
    }

    #[test]
    fn enriches_routable_ipv6_endpoint_from_mmdb() {
        let fixture = TestFixtureDir::new();
        let asn_path = fixture.write_asn_db(
            "asn-v6.mmdb",
            metadata::IpVersion::V6,
            &[(
                "2606:4700:4700::/48",
                AsnFixture {
                    autonomous_system_number: 13335,
                    autonomous_system_organization: "Cloudflare, Inc.",
                },
            )],
        );
        let country_path = fixture.write_country_db(
            "country-v6.mmdb",
            metadata::IpVersion::V6,
            &[(
                "2606:4700:4700::/48",
                CountryFixture {
                    country: CountryIsoFixture { iso_code: "US" },
                },
            )],
        );

        let provider =
            MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(asn_path, country_path))
                .expect("provider");
        let endpoint = CrawlEndpoint::new(
            "2606:4700:4700::1111",
            8333,
            CrawlNetwork::Ipv6,
            Some(IpAddr::V6(
                "2606:4700:4700::1111".parse::<Ipv6Addr>().expect("ipv6"),
            )),
        );

        let enrichment = provider.enrich(&endpoint);

        assert_eq!(enrichment.status, IpEnrichmentStatus::Matched);
        assert_eq!(enrichment.asn, Some(13335));
        assert_eq!(enrichment.country.as_deref(), Some("US"));
        assert_eq!(enrichment.prefix.as_deref(), Some("2606:4700:4700::/48"));
    }

    #[test]
    fn returns_partial_match_when_only_asn_database_has_a_record() {
        let fixture = TestFixtureDir::new();
        let asn_path = fixture.write_asn_db(
            "asn-only.mmdb",
            metadata::IpVersion::V4,
            &[(
                "9.9.9.0/24",
                AsnFixture {
                    autonomous_system_number: 19281,
                    autonomous_system_organization: "Quad9",
                },
            )],
        );
        let country_path = fixture.write_empty_typed_db(
            "country-empty.mmdb",
            metadata::IpVersion::V4,
            "GeoLite2-Country",
        );
        let provider =
            MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(asn_path, country_path))
                .expect("provider");
        let endpoint = CrawlEndpoint::new(
            "9.9.9.9",
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        );

        let enrichment = provider.enrich(&endpoint);

        assert_eq!(enrichment.status, IpEnrichmentStatus::Matched);
        assert_eq!(enrichment.asn, Some(19281));
        assert_eq!(enrichment.asn_organization.as_deref(), Some("Quad9"));
        assert_eq!(enrichment.country, None);
        assert_eq!(enrichment.prefix.as_deref(), Some("9.9.9.0/24"));
    }

    #[test]
    fn returns_lookup_failed_when_database_has_no_matching_record() {
        let fixture = TestFixtureDir::new();
        let asn_path =
            fixture.write_empty_typed_db("asn-empty.mmdb", metadata::IpVersion::V4, "GeoLite2-ASN");
        let country_path = fixture.write_empty_typed_db(
            "country-empty.mmdb",
            metadata::IpVersion::V4,
            "GeoLite2-Country",
        );
        let provider =
            MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(asn_path, country_path))
                .expect("provider");
        let endpoint = CrawlEndpoint::new(
            "8.8.8.8",
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );

        assert_eq!(
            provider.enrich(&endpoint).status,
            IpEnrichmentStatus::LookupFailed
        );
    }

    #[test]
    fn returns_init_error_for_missing_database_file() {
        let error = MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(
            "/tmp/does-not-exist-asn.mmdb",
            "/tmp/does-not-exist-country.mmdb",
        ))
        .expect_err("missing files should fail");

        assert!(error.to_string().contains("failed to open ASN MMDB"));
    }

    #[test]
    fn rejects_country_dataset_used_as_asn_database() {
        let fixture = TestFixtureDir::new();
        let asn_path = fixture.write_country_db(
            "wrong-asn.mmdb",
            metadata::IpVersion::V4,
            &[(
                "1.1.1.0/24",
                CountryFixture {
                    country: CountryIsoFixture { iso_code: "AU" },
                },
            )],
        );
        let country_path = fixture.write_country_db("country.mmdb", metadata::IpVersion::V4, &[]);

        let error =
            MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(asn_path, country_path))
                .expect_err("wrong ASN dataset type should fail");

        assert!(
            error
                .to_string()
                .contains("expected an ASN-compatible MMDB, found database_type=GeoLite2-Country")
        );
    }

    #[test]
    fn rejects_asn_dataset_used_as_country_database() {
        let fixture = TestFixtureDir::new();
        let asn_path = fixture.write_asn_db("asn.mmdb", metadata::IpVersion::V4, &[]);
        let country_path = fixture.write_asn_db(
            "wrong-country.mmdb",
            metadata::IpVersion::V4,
            &[(
                "1.1.1.0/24",
                AsnFixture {
                    autonomous_system_number: 13335,
                    autonomous_system_organization: "Cloudflare, Inc.",
                },
            )],
        );

        let error =
            MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(asn_path, country_path))
                .expect_err("wrong country dataset type should fail");

        assert!(
            error
                .to_string()
                .contains("expected a country-compatible MMDB, found database_type=GeoLite2-ASN")
        );
    }

    struct TestFixtureDir {
        root: PathBuf,
    }

    impl TestFixtureDir {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);

            let root = env::temp_dir().join(format!(
                "btc-network-mmdb-tests-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).expect("create temp dir");

            Self { root }
        }

        fn write_empty_typed_db(
            &self,
            file_name: &str,
            ip_version: metadata::IpVersion,
            database_type: &str,
        ) -> PathBuf {
            let mut db = Database::default();
            db.metadata.ip_version = ip_version;
            db.metadata.database_type = database_type.to_string();
            self.write_db(file_name, &db)
        }

        fn write_asn_db(
            &self,
            file_name: &str,
            ip_version: metadata::IpVersion,
            entries: &[(&str, AsnFixture<'_>)],
        ) -> PathBuf {
            let mut db = Database::default();
            db.metadata.ip_version = ip_version;
            db.metadata.database_type = "GeoLite2-ASN".to_string();

            for (network, value) in entries {
                let data = db.insert_value(value).expect("insert ASN fixture");
                db.insert_node(network.parse::<IpAddrWithMask>().expect("CIDR"), data);
            }

            self.write_db(file_name, &db)
        }

        fn write_country_db(
            &self,
            file_name: &str,
            ip_version: metadata::IpVersion,
            entries: &[(&str, CountryFixture<'_>)],
        ) -> PathBuf {
            let mut db = Database::default();
            db.metadata.ip_version = ip_version;
            db.metadata.database_type = "GeoLite2-Country".to_string();

            for (network, value) in entries {
                let data = db.insert_value(value).expect("insert country fixture");
                db.insert_node(network.parse::<IpAddrWithMask>().expect("CIDR"), data);
            }

            self.write_db(file_name, &db)
        }

        fn write_db(&self, file_name: &str, db: &Database) -> PathBuf {
            let path = self.root.join(file_name);
            let file = File::create(&path).expect("create mmdb fixture");
            db.write_to(file).expect("write mmdb fixture");

            let _ = Reader::open_readfile(&path).expect("reopen mmdb fixture");

            path
        }
    }

    impl Drop for TestFixtureDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
