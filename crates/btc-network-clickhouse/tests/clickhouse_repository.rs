use std::error::Error;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use ::clickhouse::Row;
use btc_network::crawler::{
    BatchId, CountNodesByAsnRow, CrawlEndpoint, CrawlNetwork, CrawlPhase, CrawlRunCheckpoint,
    CrawlRunId, CrawlRunMetrics, CrawlerAnalyticsReader, CrawlerRepository, HandshakeStatus,
    IpEnrichment, IpEnrichmentProvider, ObservationConfidence, ObservationId,
    PersistedNodeObservation, RawNodeObservation,
};
use btc_network_clickhouse::{
    ClickHouseConnectionConfig, ClickHouseCrawlerRepository, ClickHouseMigrationRunner,
};
use btc_network_mmdb::{MmdbEnrichmentConfig, MmdbIpEnrichmentProvider};
use chrono::{Duration, Utc};
use maxminddb_writer::paths::IpAddrWithMask;
use maxminddb_writer::{Database, metadata};
use serde::Deserialize;
use serde::Serialize;
use testcontainers_modules::{
    clickhouse,
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const TEST_CLICKHOUSE_PASSWORD: &str = "btc-network-test";

struct TestDatabase {
    _container: ContainerAsync<clickhouse::ClickHouse>,
    config: ClickHouseConnectionConfig,
}

impl TestDatabase {
    async fn start() -> TestResult<Self> {
        let container = clickhouse::ClickHouse::default()
            .with_tag("25.3")
            .with_env_var("CLICKHOUSE_PASSWORD", TEST_CLICKHOUSE_PASSWORD)
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container
            .get_host_port_ipv4(clickhouse::CLICKHOUSE_PORT)
            .await?;
        let url = format!("http://{host}:{port}");
        let config = ClickHouseConnectionConfig::new(url, unique_database_name())
            .with_user("default")
            .with_password(TEST_CLICKHOUSE_PASSWORD);

        Ok(Self {
            _container: container,
            config,
        })
    }

    async fn apply_migrations(&self) -> TestResult {
        ClickHouseMigrationRunner::new(&self.config)
            .apply_all()
            .await
            .map(|_| ())
            .map_err(Into::into)
    }
}

#[derive(Debug, Row, Deserialize)]
#[clickhouse(crate = "::clickhouse")]
struct TableNameRow {
    name: String,
}

#[derive(Debug, Row, Deserialize)]
#[clickhouse(crate = "::clickhouse")]
struct PersistedObservationRow {
    endpoint: String,
    enrichment_status: String,
    asn: Option<u32>,
    country: Option<String>,
    prefix: Option<String>,
}

#[derive(Serialize)]
struct AsnFixture<'a> {
    autonomous_system_number: u32,
    autonomous_system_organization: &'a str,
}

#[derive(Serialize)]
struct CountryCodeFixture<'a> {
    country_code: &'a str,
}

struct TestFixtureDir {
    root: PathBuf,
}

impl TestFixtureDir {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let root = env::temp_dir().join(format!(
            "btc-network-clickhouse-tests-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("create temp dir");

        Self { root }
    }

    fn write_asn_db(&self, file_name: &str, entries: &[(&str, AsnFixture<'_>)]) -> PathBuf {
        let mut db = Database::default();
        db.metadata.ip_version = metadata::IpVersion::V4;
        db.metadata.database_type = "GeoLite2-ASN".to_string();

        for (network, value) in entries {
            let data = db.insert_value(value).expect("insert ASN fixture");
            db.insert_node(network.parse::<IpAddrWithMask>().expect("CIDR"), data);
        }

        self.write_db(file_name, &db)
    }

    fn write_country_code_db(
        &self,
        file_name: &str,
        database_type: &str,
        entries: &[(&str, CountryCodeFixture<'_>)],
    ) -> PathBuf {
        let mut db = Database::default();
        db.metadata.ip_version = metadata::IpVersion::V4;
        db.metadata.database_type = database_type.to_string();

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
        path
    }
}

impl Drop for TestFixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn migrations_apply_idempotently_and_create_expected_tables() -> TestResult {
    let db = TestDatabase::start().await?;
    let runner = ClickHouseMigrationRunner::new(&db.config);

    let first_report = runner.apply_all().await?;
    let second_report = runner.apply_all().await?;
    let applied = runner.applied_migrations().await?;

    assert_eq!(
        first_report.applied_versions,
        vec!["20260329000100", "20260329000200"]
    );
    assert!(first_report.skipped_versions.is_empty());
    assert!(second_report.applied_versions.is_empty());
    assert_eq!(
        second_report.skipped_versions,
        vec!["20260329000100", "20260329000200"]
    );
    assert_eq!(
        applied
            .iter()
            .map(|row| row.version.as_str())
            .collect::<Vec<_>>(),
        vec!["20260329000100", "20260329000200"]
    );

    let tables = db
        .config
        .client()
        .query("SELECT ?fields FROM system.tables WHERE database = ? ORDER BY name")
        .bind(db.config.database())
        .fetch_all::<TableNameRow>()
        .await?;

    let table_names = tables.into_iter().map(|row| row.name).collect::<Vec<_>>();
    assert!(table_names.contains(&"crawler_run_checkpoints".to_string()));
    assert!(table_names.contains(&"node_observations".to_string()));
    assert!(table_names.contains(&"schema_migrations".to_string()));

    Ok(())
}

#[tokio::test]
async fn repository_round_trips_live_clickhouse_state() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = ClickHouseCrawlerRepository::new(&db.config);

    let run_id = CrawlRunId::new("run-live-1");
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_verified_observation(
                &run_id,
                "1.1.1.7",
                "observation-a1",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_verified_observation(
                &run_id,
                "1.1.1.8",
                "observation-b1",
                base_time + Duration::seconds(1),
                None,
                None,
                None,
            ),
            sample_verified_observation(
                &run_id,
                "1.1.1.9",
                "observation-c1",
                base_time + Duration::seconds(2),
                Some(64513),
                Some("Transit ASN"),
                Some("DE"),
            ),
            sample_failed_observation(
                &run_id,
                "1.1.1.9",
                "observation-c2",
                base_time + Duration::seconds(3),
            ),
        ])
        .await?;

    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id,
            CrawlPhase::Crawling,
            base_time + Duration::seconds(4),
            1,
            None,
        ))
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id,
            CrawlPhase::Draining,
            base_time + Duration::seconds(5),
            2,
            Some("stop requested".to_string()),
        ))
        .await?;

    let latest = repository
        .get_run_checkpoint(&run_id)
        .await?
        .expect("checkpoint");
    assert_eq!(latest.phase, CrawlPhase::Draining);
    assert_eq!(latest.stop_reason.as_deref(), Some("stop requested"));
    assert_eq!(
        latest.resume_state.as_deref(),
        Some("{\"seen_nodes\":[],\"pending_nodes\":[],\"in_flight_nodes\":[],\"node_states\":[]}")
    );

    let runs = repository.list_runs().await?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].phase, CrawlPhase::Draining);
    assert_eq!(
        runs[0].resume_state.as_deref(),
        Some("{\"seen_nodes\":[],\"pending_nodes\":[],\"in_flight_nodes\":[],\"node_states\":[]}")
    );

    let mut counts = CrawlerRepository::count_nodes_by_asn(&repository).await?;
    counts.sort_by(|left, right| {
        left.asn
            .cmp(&right.asn)
            .then(left.verified_nodes.cmp(&right.verified_nodes))
    });

    assert_eq!(
        counts,
        vec![
            CountNodesByAsnRow {
                asn: None,
                asn_organization: None,
                verified_nodes: 1,
            },
            CountNodesByAsnRow {
                asn: Some(64512),
                asn_organization: Some("Example ASN".to_string()),
                verified_nodes: 1,
            },
        ]
    );

    Ok(())
}

#[tokio::test]
async fn repository_uses_checkpoint_sequence_to_break_timestamp_ties() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = ClickHouseCrawlerRepository::new(&db.config);

    let run_id = CrawlRunId::new("run-live-tied");
    let tied_time = Utc::now();

    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id,
            CrawlPhase::Crawling,
            tied_time,
            1,
            None,
        ))
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id,
            CrawlPhase::Failed,
            tied_time,
            2,
            Some("checkpoint tie".to_string()),
        ))
        .await?;

    let latest = repository
        .get_run_checkpoint(&run_id)
        .await?
        .expect("checkpoint");
    assert_eq!(latest.phase, CrawlPhase::Failed);
    assert_eq!(latest.checkpoint_sequence, 2);
    assert_eq!(latest.stop_reason.as_deref(), Some("checkpoint tie"));
    assert_eq!(
        latest.resume_state.as_deref(),
        Some("{\"seen_nodes\":[],\"pending_nodes\":[],\"in_flight_nodes\":[],\"node_states\":[]}")
    );

    let runs = repository.list_runs().await?;
    let run = runs
        .into_iter()
        .find(|checkpoint| checkpoint.run_id == run_id)
        .expect("run summary");
    assert_eq!(run.phase, CrawlPhase::Failed);
    assert_eq!(run.checkpoint_sequence, 2);
    assert_eq!(run.stop_reason.as_deref(), Some("checkpoint tie"));
    assert_eq!(
        run.resume_state.as_deref(),
        Some("{\"seen_nodes\":[],\"pending_nodes\":[],\"in_flight_nodes\":[],\"node_states\":[]}")
    );
    assert_eq!(run.metrics.unique_nodes, 6);
    assert_eq!(run.metrics.persisted_observation_rows, 8);

    Ok(())
}

#[tokio::test]
async fn repository_persists_real_mmdb_enrichment_and_non_routable_not_applicable() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = ClickHouseCrawlerRepository::new(&db.config);
    let fixture = TestFixtureDir::new();
    let asn_path = fixture.write_asn_db(
        "asn.mmdb",
        &[(
            "1.1.1.0/24",
            AsnFixture {
                autonomous_system_number: 13335,
                autonomous_system_organization: "Cloudflare, Inc.",
            },
        )],
    );
    let country_path = fixture.write_country_code_db(
        "country.mmdb",
        "country ipvAll",
        &[("1.1.1.0/24", CountryCodeFixture { country_code: "AU" })],
    );
    let provider =
        MmdbIpEnrichmentProvider::new(MmdbEnrichmentConfig::new(asn_path, country_path))?;

    let run_id = CrawlRunId::new("run-mmdb-live-1");
    let observed_at = Utc::now();
    let public_endpoint = CrawlEndpoint::new(
        "1.1.1.7",
        8333,
        CrawlNetwork::Ipv4,
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7))),
    );
    let private_endpoint = CrawlEndpoint::new(
        "10.0.0.7",
        8333,
        CrawlNetwork::Ipv4,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
    );

    repository
        .insert_observations_stream(vec![
            sample_verified_observation_for_endpoint(
                &run_id,
                &public_endpoint,
                "observation-mmdb-public",
                observed_at,
                provider.enrich(&public_endpoint),
            ),
            sample_verified_observation_for_endpoint(
                &run_id,
                &private_endpoint,
                "observation-mmdb-private",
                observed_at + Duration::seconds(1),
                provider.enrich(&private_endpoint),
            ),
        ])
        .await?;

    let rows = db
        .config
        .client()
        .query("SELECT ?fields FROM node_observations ORDER BY endpoint ASC")
        .fetch_all::<PersistedObservationRow>()
        .await?;

    assert_eq!(rows.len(), 2);

    assert_eq!(rows[0].endpoint, public_endpoint.canonical);
    assert_eq!(rows[0].enrichment_status, "matched");
    assert_eq!(rows[0].asn, Some(13335));
    assert_eq!(rows[0].country.as_deref(), Some("AU"));
    assert_eq!(rows[0].prefix.as_deref(), Some("1.1.1.0/24"));

    assert_eq!(rows[1].endpoint, private_endpoint.canonical);
    assert_eq!(rows[1].enrichment_status, "not_applicable");
    assert_eq!(rows[1].asn, None);
    assert_eq!(rows[1].country, None);
    assert_eq!(rows[1].prefix, None);

    Ok(())
}

#[tokio::test]
async fn analytics_reader_lists_runs_with_derived_percentages() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = ClickHouseCrawlerRepository::new(&db.config);
    let base_time = Utc::now();

    repository
        .insert_run_checkpoint(sample_checkpoint(
            &CrawlRunId::new("run-older"),
            CrawlPhase::Completed,
            base_time,
            1,
            Some("idle timeout".to_string()),
        ))
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &CrawlRunId::new("run-newer"),
            CrawlPhase::Failed,
            base_time + Duration::seconds(5),
            1,
            Some("checkpoint failure".to_string()),
        ))
        .await?;

    let runs = CrawlerAnalyticsReader::list_crawl_runs(&repository, 1).await?;

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, "run-newer");
    assert_eq!(runs[0].phase, "failed");
    assert_eq!(runs[0].success_pct, 133.33);
    assert_eq!(runs[0].scheduled_pct, 50.0);
    assert_eq!(runs[0].unscheduled_gap, 3);

    Ok(())
}

#[tokio::test]
async fn analytics_reader_returns_run_detail_with_failure_and_network_breakdowns() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = ClickHouseCrawlerRepository::new(&db.config);
    let run_id = CrawlRunId::new("run-detail-1");
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_verified_observation(
                &run_id,
                "1.1.1.7",
                "observation-a1",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_failed_observation(
                &run_id,
                "1.1.1.9",
                "observation-a2",
                base_time + Duration::seconds(1),
            ),
        ])
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id,
            CrawlPhase::Crawling,
            base_time + Duration::seconds(2),
            1,
            None,
        ))
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id,
            CrawlPhase::Failed,
            base_time + Duration::seconds(3),
            2,
            Some("checkpoint failure".to_string()),
        ))
        .await?;

    let detail = CrawlerAnalyticsReader::get_crawl_run(&repository, &run_id, 10)
        .await?
        .expect("run detail");

    assert_eq!(detail.run.run_id, "run-detail-1");
    assert_eq!(detail.run.phase, "failed");
    assert_eq!(detail.checkpoints.len(), 2);
    assert_eq!(detail.checkpoints[0].phase, "failed");
    assert_eq!(detail.failure_counts.len(), 1);
    assert_eq!(detail.failure_counts[0].classification, "handshake");
    assert_eq!(detail.failure_counts[0].observations, 1);
    assert_eq!(detail.network_outcomes.len(), 1);
    assert_eq!(detail.network_outcomes[0].network_type, "ipv4");
    assert_eq!(detail.network_outcomes[0].observations, 2);
    assert_eq!(detail.network_outcomes[0].verified_nodes, 1);
    assert_eq!(detail.network_outcomes[0].failed_nodes, 1);
    assert_eq!(detail.network_outcomes[0].verified_pct, 50.0);

    Ok(())
}

#[tokio::test]
async fn analytics_reader_limits_asn_counts() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = ClickHouseCrawlerRepository::new(&db.config);
    let run_id = CrawlRunId::new("run-asn-limit");
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_verified_observation(
                &run_id,
                "1.1.1.7",
                "observation-a1",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_verified_observation(
                &run_id,
                "8.8.8.8",
                "observation-a2",
                base_time + Duration::seconds(1),
                Some(15169),
                Some("Google LLC"),
                Some("US"),
            ),
        ])
        .await?;

    let counts = CrawlerAnalyticsReader::count_nodes_by_asn(&repository, 1).await?;

    assert_eq!(counts.len(), 1);
    assert_eq!(counts[0].verified_nodes, 1);

    Ok(())
}

fn unique_database_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after unix epoch")
        .as_nanos();
    format!("btc_network_test_{nanos}")
}

fn sample_verified_observation(
    run_id: &CrawlRunId,
    host: &str,
    observation_id: &str,
    observed_at: chrono::DateTime<Utc>,
    asn: Option<u32>,
    asn_organization: Option<&str>,
    country: Option<&str>,
) -> PersistedNodeObservation {
    RawNodeObservation {
        observed_at,
        crawl_run_id: run_id.clone(),
        endpoint: CrawlEndpoint::new(
            host,
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(host.parse::<Ipv4Addr>().expect("valid ipv4"))),
        ),
        handshake_status: HandshakeStatus::Succeeded,
        confidence: ObservationConfidence::Verified,
        protocol_version: Some(70016),
        services: Some(1),
        user_agent: Some("/Satoshi:27.0.0/".to_string()),
        start_height: Some(900_000),
        relay: Some(true),
        discovered_count: 8,
        latency: Some(std::time::Duration::from_millis(125)),
        failure_classification: None,
    }
    .into_persisted(
        ObservationId::new(observation_id),
        BatchId::new(format!("batch-{observation_id}")),
        IpEnrichment::matched(
            asn,
            asn_organization.map(ToString::to_string),
            country.map(ToString::to_string),
            asn.map(|_| format!("{host}/24")),
        ),
    )
}

fn sample_verified_observation_for_endpoint(
    run_id: &CrawlRunId,
    endpoint: &CrawlEndpoint,
    observation_id: &str,
    observed_at: chrono::DateTime<Utc>,
    enrichment: IpEnrichment,
) -> PersistedNodeObservation {
    RawNodeObservation {
        observed_at,
        crawl_run_id: run_id.clone(),
        endpoint: endpoint.clone(),
        handshake_status: HandshakeStatus::Succeeded,
        confidence: ObservationConfidence::Verified,
        protocol_version: Some(70016),
        services: Some(1),
        user_agent: Some("/Satoshi:27.0.0/".to_string()),
        start_height: Some(900_000),
        relay: Some(true),
        discovered_count: 8,
        latency: Some(std::time::Duration::from_millis(125)),
        failure_classification: None,
    }
    .into_persisted(
        ObservationId::new(observation_id),
        BatchId::new(format!("batch-{observation_id}")),
        enrichment,
    )
}

fn sample_failed_observation(
    run_id: &CrawlRunId,
    host: &str,
    observation_id: &str,
    observed_at: chrono::DateTime<Utc>,
) -> PersistedNodeObservation {
    RawNodeObservation {
        observed_at,
        crawl_run_id: run_id.clone(),
        endpoint: CrawlEndpoint::new(
            host,
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(host.parse::<Ipv4Addr>().expect("valid ipv4"))),
        ),
        handshake_status: HandshakeStatus::Failed,
        confidence: ObservationConfidence::Failed,
        protocol_version: None,
        services: None,
        user_agent: None,
        start_height: None,
        relay: None,
        discovered_count: 0,
        latency: Some(std::time::Duration::from_millis(300)),
        failure_classification: Some(btc_network::crawler::FailureClassification::Handshake),
    }
    .into_persisted(
        ObservationId::new(observation_id),
        BatchId::new(format!("batch-{observation_id}")),
        IpEnrichment::matched(
            Some(64513),
            Some("Transit ASN".to_string()),
            Some("DE".to_string()),
            Some(format!("{host}/24")),
        ),
    )
}

fn sample_checkpoint(
    run_id: &CrawlRunId,
    phase: CrawlPhase,
    checkpointed_at: chrono::DateTime<Utc>,
    checkpoint_sequence: u64,
    stop_reason: Option<String>,
) -> CrawlRunCheckpoint {
    CrawlRunCheckpoint {
        run_id: run_id.clone(),
        phase,
        checkpointed_at,
        checkpoint_sequence,
        started_at: checkpointed_at - Duration::seconds(10),
        stop_reason,
        failure_reason: None,
        metrics: CrawlRunMetrics {
            frontier_size: 1,
            in_flight_work: 2,
            scheduled_tasks: 3,
            successful_handshakes: 4,
            failed_tasks: 1,
            queued_nodes_total: 5,
            unique_nodes: 6,
            discovered_node_states: 7,
            persisted_observation_rows: 8,
            writer_backlog: 0,
        },
        resume_state: Some(
            "{\"seen_nodes\":[],\"pending_nodes\":[],\"in_flight_nodes\":[],\"node_states\":[]}"
                .to_string(),
        ),
        caller: Some("integration-test".to_string()),
    }
}
