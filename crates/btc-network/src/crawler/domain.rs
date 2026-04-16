use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use uuid::Uuid;

use super::types::{CrawlerConfig, NodeState};

/// Stable identifier for one crawler run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CrawlRunId(Uuid);

impl CrawlRunId {
    /// Creates a crawl run identifier from a caller-provided UUID.
    pub fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Generates a new time-ordered identifier.
    pub fn now_v7() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parses a crawl run identifier from its canonical UUID string.
    pub fn parse_str(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    /// Builds a deterministic identifier from a fixed integer.
    pub fn from_u128(value: u128) -> Self {
        Self(Uuid::from_u128(value))
    }

    /// Returns the identifier as a UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Display for CrawlRunId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Stable identifier for one persisted node observation row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObservationId(Uuid);

impl ObservationId {
    /// Creates an observation identifier from a caller-provided UUID.
    pub fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Generates a new time-ordered identifier.
    pub fn now_v7() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parses an observation identifier from its canonical UUID string.
    pub fn parse_str(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    /// Builds a deterministic identifier from a fixed integer.
    pub fn from_u128(value: u128) -> Self {
        Self(Uuid::from_u128(value))
    }

    /// Returns the identifier as a UUID value.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Display for ObservationId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Lifecycle phase of a crawler run.
/// The run ends in a terminal `Finished` phase. The reason for ending is
/// represented separately by `stop_reason` and `failure_reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrawlPhase {
    Bootstrap,
    Crawling,
    Draining,
    Finished,
}

/// Network family inferred for a discovered endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrawlNetwork {
    Ipv4,
    Ipv6,
    TorV2,
    TorV3,
    I2p,
    Cjdns,
    Yggdrasil,
    Unknown,
}

impl CrawlNetwork {
    /// Returns whether endpoints in this network family can use IP-based
    /// enrichment such as ASN and country lookup.
    pub fn supports_ip_enrichment(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }

    pub fn as_storage_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::TorV2 => "tor_v2",
            Self::TorV3 => "tor_v3",
            Self::I2p => "i2p",
            Self::Cjdns => "cjdns",
            Self::Yggdrasil => "yggdrasil",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_storage_str(value: &str) -> Option<Self> {
        match value {
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "tor_v2" => Some(Self::TorV2),
            "tor_v3" => Some(Self::TorV3),
            "i2p" => Some(Self::I2p),
            "cjdns" => Some(Self::Cjdns),
            "yggdrasil" => Some(Self::Yggdrasil),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Canonical crawler endpoint representation used across discovery, storage,
/// and recovery flows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrawlEndpoint {
    pub canonical: String,
    pub host: String,
    pub port: u16,
    pub network: CrawlNetwork,
    pub ip_addr: Option<IpAddr>,
}

impl CrawlEndpoint {
    /// Builds an endpoint from normalized host, port, network, and optional IP.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        network: CrawlNetwork,
        ip_addr: Option<IpAddr>,
    ) -> Self {
        let host = host.into();
        let canonical = match ip_addr {
            Some(IpAddr::V6(_)) => format!("[{host}]:{port}"),
            _ => format!("{host}:{port}"),
        };

        Self {
            canonical,
            host,
            port,
            network,
            ip_addr,
        }
    }

    /// Converts a socket address into a crawler endpoint with canonical
    /// network-family metadata.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::new(
                v4.ip().to_string(),
                v4.port(),
                CrawlNetwork::Ipv4,
                Some(IpAddr::V4(*v4.ip())),
            ),
            SocketAddr::V6(v6) => Self::new(
                v6.ip().to_string(),
                v6.port(),
                CrawlNetwork::Ipv6,
                Some(IpAddr::V6(*v6.ip())),
            ),
        }
    }

    /// Returns whether this endpoint should receive IP-based enrichment.
    ///
    /// Overlay networks and non-routable IP ranges bypass enrichment by design.
    pub fn supports_ip_enrichment(&self) -> bool {
        self.network.supports_ip_enrichment()
            && self.ip_addr.is_some_and(is_routable_for_enrichment)
    }

    /// Returns a socket address when the endpoint includes a concrete IP.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.ip_addr
            .map(|ip_addr| SocketAddr::new(ip_addr, self.port))
    }

    pub fn from_stored(
        canonical: impl Into<String>,
        network: CrawlNetwork,
    ) -> Result<Self, String> {
        let canonical = canonical.into();
        let (host, port) = parse_stored_endpoint(&canonical)?;
        let ip_addr = match network {
            CrawlNetwork::Ipv4 => host.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
            CrawlNetwork::Ipv6 => host.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
            _ => None,
        };

        Ok(Self {
            canonical,
            host,
            port,
            network,
            ip_addr,
        })
    }
}

fn parse_stored_endpoint(canonical: &str) -> Result<(String, u16), String> {
    if let Some(rest) = canonical.strip_prefix('[') {
        let Some((host, port)) = rest.rsplit_once("]:") else {
            return Err(format!("invalid stored endpoint: {canonical}"));
        };
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("invalid stored endpoint port: {canonical}"))?;
        return Ok((host.to_string(), port));
    }

    let Some((host, port)) = canonical.rsplit_once(':') else {
        return Err(format!("invalid stored endpoint: {canonical}"));
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid stored endpoint port: {canonical}"))?;
    Ok((host.to_string(), port))
}

impl From<SocketAddr> for CrawlEndpoint {
    fn from(value: SocketAddr) -> Self {
        Self::from_socket_addr(value)
    }
}

fn is_routable_for_enrichment(ip_addr: IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ip) => is_routable_ipv4(ip),
        IpAddr::V6(ip) => is_routable_ipv6(ip),
    }
}

fn is_routable_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();

    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_documentation()
        && !ip.is_multicast()
        && !ip.is_unspecified()
        && !(a == 100 && (64..=127).contains(&b))
}

fn is_routable_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();

    !(ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

/// Stage at which a node visit failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureClassification {
    Connect,
    Handshake,
    PeerDiscovery,
    Io,
    Other(String),
}

/// Outcome of IP enrichment for one observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpEnrichmentStatus {
    Matched,
    NotApplicable,
    Unavailable,
    LookupFailed,
}

/// IP-derived enrichment attached to a crawler observation.
///
/// BNDD-0005 keeps ASN, country, and prefix as enrichment-derived fields rather
/// than protocol-derived fields, so they remain optional here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpEnrichment {
    pub status: IpEnrichmentStatus,
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub country: Option<String>,
    pub prefix: Option<String>,
}

impl IpEnrichment {
    /// Creates a successful enrichment payload.
    pub fn matched(
        asn: Option<u32>,
        asn_organization: Option<String>,
        country: Option<String>,
        prefix: Option<String>,
    ) -> Self {
        Self {
            status: IpEnrichmentStatus::Matched,
            asn,
            asn_organization,
            country,
            prefix,
        }
    }

    /// Creates an enrichment payload for endpoints where lookup does not apply.
    pub fn not_applicable() -> Self {
        Self {
            status: IpEnrichmentStatus::NotApplicable,
            asn: None,
            asn_organization: None,
            country: None,
            prefix: None,
        }
    }

    /// Creates an enrichment payload for runs where lookup support is disabled.
    pub fn unavailable() -> Self {
        Self {
            status: IpEnrichmentStatus::Unavailable,
            asn: None,
            asn_organization: None,
            country: None,
            prefix: None,
        }
    }

    pub fn lookup_failed() -> Self {
        Self {
            status: IpEnrichmentStatus::LookupFailed,
            asn: None,
            asn_organization: None,
            country: None,
            prefix: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNodeObservation {
    pub observed_at: DateTime<Utc>,
    pub crawl_run_id: CrawlRunId,
    pub endpoint: CrawlEndpoint,
    pub protocol_version: Option<i32>,
    pub services: Option<u64>,
    pub user_agent: Option<String>,
    pub start_height: Option<i32>,
    pub relay: Option<bool>,
    pub discovered_peer_addresses_count: usize,
    pub latency: Option<Duration>,
    pub failure_classification: Option<FailureClassification>,
}

impl RawNodeObservation {
    pub fn from_success(
        observed_at: DateTime<Utc>,
        crawl_run_id: CrawlRunId,
        endpoint: CrawlEndpoint,
        state: &NodeState,
        discovered_peer_addresses_count: usize,
        latency: Duration,
    ) -> Self {
        Self {
            observed_at,
            crawl_run_id,
            endpoint,
            protocol_version: Some(state.version),
            services: Some(state.services),
            user_agent: Some(state.user_agent.clone()),
            start_height: Some(state.start_height),
            relay: state.relay,
            discovered_peer_addresses_count,
            latency: Some(latency),
            failure_classification: None,
        }
    }

    pub fn from_failure(
        observed_at: DateTime<Utc>,
        crawl_run_id: CrawlRunId,
        endpoint: CrawlEndpoint,
        classification: FailureClassification,
        latency: Duration,
    ) -> Self {
        Self {
            observed_at,
            crawl_run_id,
            endpoint,
            protocol_version: None,
            services: None,
            user_agent: None,
            start_height: None,
            relay: None,
            discovered_peer_addresses_count: 0,
            latency: Some(latency),
            failure_classification: Some(classification),
        }
    }

    pub fn supports_ip_enrichment(&self) -> bool {
        self.endpoint.supports_ip_enrichment()
    }

    pub fn into_persisted(
        self,
        observation_id: ObservationId,
        enrichment: IpEnrichment,
    ) -> PersistedNodeObservation {
        PersistedNodeObservation {
            observation_id,
            raw: self,
            enrichment,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedNodeObservation {
    pub observation_id: ObservationId,
    pub raw: RawNodeObservation,
    pub enrichment: IpEnrichment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlRunMetrics {
    pub frontier_size: usize,
    pub in_flight_work: usize,
    pub scheduled_tasks: usize,
    pub successful_handshakes: usize,
    pub failed_tasks: usize,
    pub unique_nodes: usize,
    pub persisted_observation_rows: usize,
    pub writer_backlog: usize,
}

/// A durable snapshot of a crawl run at a specific point in time.
///
/// `checkpointed_at` records the wall-clock time of the snapshot. Because multiple
/// checkpoints can be written with the same persisted timestamp resolution,
/// `checkpoint_sequence` provides the deterministic per-run ordering key for
/// "latest checkpoint" reads and run-summary aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlRunCheckpoint {
    pub run_id: CrawlRunId,
    pub phase: CrawlPhase,
    pub checkpointed_at: DateTime<Utc>,
    /// Monotonic per-run sequence used to break ties when two checkpoints share
    /// the same persisted `checkpointed_at` value.
    pub checkpoint_sequence: u64,
    pub started_at: DateTime<Utc>,
    pub stop_reason: Option<String>,
    pub failure_reason: Option<String>,
    pub metrics: CrawlRunMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartCrawlRequest {
    pub config: CrawlerConfig,
    pub seed_nodes: Vec<CrawlEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopCrawlRequest {
    pub run_id: CrawlRunId,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountNodesByAsnRow {
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub verified_nodes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn sample_raw_observation(endpoint: CrawlEndpoint) -> RawNodeObservation {
        RawNodeObservation {
            observed_at: Utc::now(),
            crawl_run_id: CrawlRunId::from_u128(1),
            endpoint,
            protocol_version: Some(70016),
            services: Some(1),
            user_agent: Some("/Satoshi:27.0.0/".to_string()),
            start_height: Some(900_000),
            relay: Some(true),
            discovered_peer_addresses_count: 8,
            latency: Some(Duration::from_millis(150)),
            failure_classification: None,
        }
    }

    #[test]
    fn endpoint_from_ipv4_socket_addr_is_enrichment_eligible() {
        let endpoint = CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 7),
            8333,
        )));

        assert_eq!(endpoint.network, CrawlNetwork::Ipv4);
        assert_eq!(endpoint.canonical, "1.1.1.7:8333");
        assert_eq!(
            endpoint.ip_addr,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7)))
        );
        assert!(endpoint.supports_ip_enrichment());
    }

    #[test]
    fn endpoint_from_ipv6_socket_addr_uses_bracketed_canonical_form() {
        let endpoint = CrawlEndpoint::from_socket_addr(SocketAddr::V6(SocketAddrV6::new(
            "2606:4700:4700::1111".parse().expect("public ipv6"),
            8333,
            0,
            0,
        )));

        assert_eq!(endpoint.network, CrawlNetwork::Ipv6);
        assert_eq!(endpoint.canonical, "[2606:4700:4700::1111]:8333");
        assert!(endpoint.supports_ip_enrichment());
    }

    #[test]
    fn overlay_endpoint_is_not_enrichment_eligible() {
        let endpoint = CrawlEndpoint::new("exampleonionaddress", 8333, CrawlNetwork::TorV3, None);
        let observation = sample_raw_observation(endpoint);

        assert!(!observation.supports_ip_enrichment());
    }

    #[test]
    fn cjdns_endpoint_is_not_enrichment_eligible_even_with_ipv6_address() {
        let endpoint = CrawlEndpoint::new(
            "fc00::1",
            8333,
            CrawlNetwork::Cjdns,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        );

        assert!(!endpoint.supports_ip_enrichment());
        assert_eq!(
            endpoint.socket_addr(),
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333))
        );
    }

    #[test]
    fn non_routable_ipv4_endpoint_is_not_enrichment_eligible() {
        let endpoint = CrawlEndpoint::new(
            "10.0.0.2",
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        );

        assert!(!endpoint.supports_ip_enrichment());
    }

    #[test]
    fn matched_enrichment_preserves_supplied_fields() {
        let enrichment = IpEnrichment::matched(
            Some(64512),
            Some("Example ASN".to_string()),
            Some("US".to_string()),
            Some("203.0.113.0/24".to_string()),
        );

        assert_eq!(enrichment.status, IpEnrichmentStatus::Matched);
        assert_eq!(enrichment.asn, Some(64512));
        assert_eq!(enrichment.country.as_deref(), Some("US"));
    }

    #[test]
    fn into_persisted_preserves_raw_observation_and_enrichment_boundary() {
        let raw = sample_raw_observation(CrawlEndpoint::from_socket_addr(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 8333),
        )));
        let observed_at = raw.observed_at;
        let crawl_run_id = raw.crawl_run_id.clone();
        let endpoint = raw.endpoint.clone();
        let enrichment = IpEnrichment::matched(
            Some(64513),
            Some("Example Provider".to_string()),
            Some("DE".to_string()),
            Some("198.51.100.0/24".to_string()),
        );

        let persisted = raw.into_persisted(ObservationId::from_u128(1), enrichment.clone());

        assert_eq!(persisted.observation_id, ObservationId::from_u128(1));
        assert_eq!(persisted.raw.observed_at, observed_at);
        assert_eq!(persisted.raw.crawl_run_id, crawl_run_id);
        assert_eq!(persisted.raw.endpoint, endpoint);
        assert_eq!(persisted.enrichment, enrichment);
    }
}
