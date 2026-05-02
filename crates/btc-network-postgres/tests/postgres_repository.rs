use std::error::Error;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};
use std::{env, fs};

use btc_network::crawler::{
    CountNodesByAsnRow, CrawlEndpoint, CrawlNetwork, CrawlPhase, CrawlRunCheckpoint, CrawlRunId,
    CrawlRunMetrics, Crawler, CrawlerAnalyticsReader, CrawlerConfig, CrawlerRepository,
    IpEnrichment, IpEnrichmentProvider, PersistedNodeObservation, RawNodeObservation,
    UnreachableNodeUpdate, UnreachableNodeUpdateKind,
};
use btc_network::wire::{self, Command};
use btc_network_mmdb::{MmdbEnrichmentConfig, MmdbIpEnrichmentProvider};
use btc_network_postgres::{
    PostgresConnectionConfig, PostgresCrawlerRepository, PostgresMigrationRunner,
};
use chrono::{Duration, Utc};
use maxminddb_writer::paths::IpAddrWithMask;
use maxminddb_writer::{Database, metadata};
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::{PgPool, Postgres};
use testcontainers_modules::{
    postgres,
    testcontainers::{ContainerAsync, ImageExt, core::Mount, runners::AsyncRunner},
};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::task::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const TEST_POSTGRES_PASSWORD: &str = "btc-network-test";
const TEST_POSTGRES_USER: &str = "postgres";

fn run_id(value: u128) -> CrawlRunId {
    CrawlRunId::from_u128(value)
}

struct UnavailableEnrichmentProvider;

impl IpEnrichmentProvider for UnavailableEnrichmentProvider {
    fn enrich(&self, _endpoint: &CrawlEndpoint) -> IpEnrichment {
        IpEnrichment::unavailable()
    }
}

struct TestDatabase {
    container: Option<ContainerAsync<postgres::Postgres>>,
    config: PostgresConnectionConfig,
    socket_dir: Option<SocketDir>,
}

struct SocketDir {
    actual: PathBuf,
    link: PathBuf,
}

impl TestDatabase {
    async fn start() -> TestResult<Self> {
        let database = unique_database_name();
        // Use a Unix socket on Unix hosts so tests do not depend on Docker's
        // host-port forwarding, which can be unavailable in nested/containerized
        // development environments.
        let socket_dir = create_socket_dir();
        let mut postgres = postgres::Postgres::default()
            .with_tag("18")
            .with_env_var("POSTGRES_DB", database.clone())
            .with_env_var("POSTGRES_PASSWORD", TEST_POSTGRES_PASSWORD)
            .with_env_var("POSTGRES_USER", TEST_POSTGRES_USER);

        if let Some(socket_dir) = socket_dir.as_ref() {
            postgres = postgres.with_mount(Mount::bind_mount(
                socket_dir.actual.to_string_lossy(),
                "/var/run/postgresql",
            ));
        }

        let container = postgres.start().await?;
        let url = if let Some(socket_dir) = socket_dir.as_ref() {
            format!(
                "postgresql://{TEST_POSTGRES_USER}:{TEST_POSTGRES_PASSWORD}@{}/{database}",
                encode_socket_host(&socket_dir.link)
            )
        } else {
            let host = container.get_host().await?;
            let port = container.get_host_port_ipv4(5432).await?;
            format!(
                "postgresql://{TEST_POSTGRES_USER}:{TEST_POSTGRES_PASSWORD}@{host}:{port}/{database}"
            )
        };

        Ok(Self {
            container: Some(container),
            config: PostgresConnectionConfig::new(url).with_max_connections(8),
            socket_dir,
        })
    }

    async fn apply_migrations(&self) -> TestResult {
        PostgresMigrationRunner::new(&self.config)?
            .apply_all()
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    async fn connect(&self) -> TestResult<PgPool> {
        Ok(PgPool::connect(self.config.url()).await?)
    }
}

fn encode_socket_host(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('/', "%2F")
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        if let (Some(container), Some(_socket_dir)) = (&self.container, &self.socket_dir) {
            let _ = std::process::Command::new("docker")
                .args([
                    "exec",
                    container.id(),
                    "sh",
                    "-c",
                    "rm -f /var/run/postgresql/.s.PGSQL.5432*; chmod 0777 /var/run/postgresql",
                ])
                .status();
        }
        drop(self.container.take());
        if let Some(socket_dir) = self.socket_dir.take() {
            let _ = fs::remove_dir_all(socket_dir.actual);
            let _ = fs::remove_file(socket_dir.link);
        }
    }
}

#[cfg(unix)]
fn create_socket_dir() -> Option<SocketDir> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);
    let unique = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    let socket_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test-postgres-sockets");
    fs::create_dir_all(&socket_root).expect("create postgres socket root");

    let actual = socket_root.join(format!("socket-{unique}"));
    let link = env::temp_dir().join(format!("bnpg-{}-{unique}", std::process::id()));

    fs::create_dir_all(&actual).expect("create postgres socket dir");
    fs::set_permissions(&actual, fs::Permissions::from_mode(0o777))
        .expect("chmod postgres socket dir");
    let _ = fs::remove_file(&link);
    symlink(&actual, &link).expect("symlink postgres socket dir");

    Some(SocketDir { actual, link })
}

#[cfg(not(unix))]
fn create_socket_dir() -> Option<SocketDir> {
    None
}

struct TestFixtureDir {
    root: PathBuf,
}

impl TestFixtureDir {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let root = env::temp_dir().join(format!(
            "btc-network-postgres-tests-{}-{}",
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

#[derive(serde::Serialize)]
struct AsnFixture<'a> {
    autonomous_system_number: u32,
    autonomous_system_organization: &'a str,
}

#[derive(serde::Serialize)]
struct CountryCodeFixture<'a> {
    country_code: &'a str,
}

#[tokio::test]
async fn migrations_apply_idempotently_and_create_expected_tables() -> TestResult {
    let db = TestDatabase::start().await?;
    let runner = PostgresMigrationRunner::new(&db.config)?;

    let first_report = runner.apply_all().await?;
    let second_report = runner.apply_all().await?;
    let applied = runner.applied_migrations().await?;

    assert_eq!(
        first_report.applied_versions,
        vec!["20260404000100", "20260404000200", "20260426000100",]
    );
    assert!(first_report.skipped_versions.is_empty());
    assert!(second_report.applied_versions.is_empty());
    assert_eq!(
        second_report.skipped_versions,
        vec!["20260404000100", "20260404000200", "20260426000100",]
    );
    assert_eq!(
        applied
            .iter()
            .map(|row| row.version.as_str())
            .collect::<Vec<_>>(),
        vec!["20260404000100", "20260404000200", "20260426000100",]
    );

    let client = db.connect().await?;
    let rows = query::<Postgres>(
        "
SELECT tablename
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename
",
    )
    .fetch_all(&client)
    .await?;
    let table_names = rows
        .into_iter()
        .map(|row| row.get::<String, _>("tablename"))
        .collect::<Vec<_>>();

    assert!(table_names.contains(&"crawler_run_checkpoints".to_string()));
    assert!(table_names.contains(&"node_observations".to_string()));
    assert!(table_names.contains(&"schema_migrations".to_string()));
    assert!(table_names.contains(&"unreachable_nodes".to_string()));

    Ok(())
}

#[tokio::test]
async fn repository_round_trips_live_postgres_state() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;

    let run_id = run_id(1);
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_verified_observation(
                &run_id,
                "1.1.1.7",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_verified_observation(
                &run_id,
                "1.1.1.8",
                base_time + Duration::seconds(1),
                None,
                None,
                None,
            ),
            sample_verified_observation(
                &run_id,
                "1.1.1.9",
                base_time + Duration::seconds(2),
                Some(64513),
                Some("Transit ASN"),
                Some("DE"),
            ),
            sample_failed_observation(&run_id, "1.1.1.9", base_time + Duration::seconds(3)),
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

    let runs = repository.list_runs().await?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].phase, CrawlPhase::Draining);

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
async fn repository_loads_and_updates_unreachable_nodes() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;
    let run_id = run_id(12);
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_connect_failed_observation(
                &run_id,
                "1.1.1.10",
                base_time - Duration::minutes(1),
            ),
            sample_failed_observation(&run_id, "1.1.1.14", base_time - Duration::seconds(30)),
            sample_verified_observation(
                &run_id,
                "1.1.1.11",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
        ])
        .await?;

    let mut loaded = repository
        .load_unreachable_nodes(base_time - Duration::hours(1))
        .await?;
    loaded.sort_by(|left, right| left.canonical.cmp(&right.canonical));

    assert!(
        loaded.is_empty(),
        "failed observations alone should not populate active unreachable state"
    );

    let recorded = CrawlEndpoint::new(
        "1.1.1.12",
        8333,
        CrawlNetwork::Ipv4,
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 12))),
    );
    repository
        .apply_unreachable_node_updates(vec![UnreachableNodeUpdate {
            endpoint: recorded.clone(),
            crawl_run_id: run_id,
            observed_at: base_time + Duration::seconds(1),
            failure_classification: Some(btc_network::crawler::FailureClassification::Connect),
            kind: UnreachableNodeUpdateKind::Record,
        }])
        .await?;

    let client = db.connect().await?;
    let row = query::<Postgres>(
        "
SELECT
    endpoint,
    network_type,
    last_crawl_run_id,
    last_failure_classification,
    failure_count,
    recovered_at
FROM unreachable_nodes
WHERE endpoint = $1
",
    )
    .bind(recorded.canonical.as_str())
    .fetch_one(&client)
    .await?;

    assert_eq!(row.get::<String, _>("endpoint"), recorded.canonical);
    assert_eq!(row.get::<String, _>("network_type"), "ipv4");
    assert_eq!(
        row.get::<uuid::Uuid, _>("last_crawl_run_id"),
        run_id.as_uuid()
    );
    assert_eq!(
        row.get::<String, _>("last_failure_classification"),
        "connect"
    );
    assert_eq!(row.get::<i64, _>("failure_count"), 1);
    assert!(
        row.get::<Option<chrono::DateTime<Utc>>, _>("recovered_at")
            .is_none()
    );

    let loaded = repository
        .load_unreachable_nodes(base_time - Duration::hours(1))
        .await?;
    assert!(
        loaded
            .iter()
            .any(|endpoint| endpoint.canonical == recorded.canonical)
    );

    let handshake_recorded = CrawlEndpoint::new(
        "1.1.1.13",
        8333,
        CrawlNetwork::Ipv4,
        Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 13))),
    );
    repository
        .apply_unreachable_node_updates(vec![UnreachableNodeUpdate {
            endpoint: handshake_recorded.clone(),
            crawl_run_id: run_id,
            observed_at: base_time + Duration::seconds(1),
            failure_classification: Some(btc_network::crawler::FailureClassification::Handshake),
            kind: UnreachableNodeUpdateKind::Record,
        }])
        .await?;

    let loaded = repository
        .load_unreachable_nodes(base_time - Duration::hours(1))
        .await?;
    assert!(
        loaded
            .iter()
            .any(|endpoint| endpoint.canonical == handshake_recorded.canonical)
    );

    repository
        .apply_unreachable_node_updates(vec![UnreachableNodeUpdate {
            endpoint: recorded.clone(),
            crawl_run_id: run_id,
            observed_at: base_time + Duration::seconds(2),
            failure_classification: None,
            kind: UnreachableNodeUpdateKind::Recover,
        }])
        .await?;

    let loaded = repository
        .load_unreachable_nodes(base_time + Duration::seconds(1))
        .await?;
    assert!(
        !loaded
            .iter()
            .any(|endpoint| endpoint.canonical == recorded.canonical)
    );

    Ok(())
}

#[tokio::test]
async fn crawler_records_unreachable_node_after_retry_budget() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = Arc::new(PostgresCrawlerRepository::new(&db.config)?);
    let endpoint = closed_loopback_endpoint()?;
    let crawler = Crawler::with_adapters(
        CrawlerConfig {
            max_concurrency: 1,
            max_in_flight_connects: 1,
            max_tracked_nodes: 16,
            max_runtime: StdDuration::from_secs(5),
            idle_timeout: StdDuration::from_millis(20),
            lifecycle_tick: StdDuration::from_millis(5),
            checkpoint_interval: StdDuration::from_millis(50),
            connect_timeout: StdDuration::from_millis(100),
            connect_max_attempts: 3,
            unreachable_nodes_lookback: StdDuration::from_secs(7 * 24 * 60 * 60),
            follow_discovered_nodes: true,
            connect_retry_backoff: StdDuration::ZERO,
            io_timeout: StdDuration::from_millis(100),
            tor_socks5_addr: None,
            shutdown_grace_period: StdDuration::from_secs(1),
            verbose: false,
        },
        repository,
        Arc::new(UnavailableEnrichmentProvider),
    );

    let summary = crawler
        .run_with_seed_nodes(vec![endpoint.clone()])
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;

    assert_eq!(summary.failed_tasks, 3);

    let client = db.connect().await?;
    let row = query::<Postgres>(
        "
SELECT
    endpoint,
    network_type,
    last_failure_classification,
    failure_count,
    recovered_at
FROM unreachable_nodes
WHERE endpoint = $1
",
    )
    .bind(endpoint.canonical.as_str())
    .fetch_one(&client)
    .await?;

    assert_eq!(row.get::<String, _>("endpoint"), endpoint.canonical);
    assert_eq!(row.get::<String, _>("network_type"), "ipv4");
    assert_eq!(
        row.get::<String, _>("last_failure_classification"),
        "connect"
    );
    assert_eq!(row.get::<i64, _>("failure_count"), 1);
    assert!(
        row.get::<Option<chrono::DateTime<Utc>>, _>("recovered_at")
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn crawler_records_unreachable_node_after_handshake_timeouts() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = Arc::new(PostgresCrawlerRepository::new(&db.config)?);
    let (endpoint, server) = start_fake_peer(FakePeerMode::Silent).await?;
    let crawler = Crawler::with_adapters(
        crawler_retry_test_config(),
        repository,
        Arc::new(UnavailableEnrichmentProvider),
    );

    let summary = crawler
        .run_with_seed_nodes(vec![endpoint.clone()])
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    server.abort();

    assert_eq!(summary.failed_tasks, 3);
    assert_unreachable_node(&db, &endpoint, "handshake").await?;

    Ok(())
}

#[tokio::test]
async fn crawler_records_unreachable_node_after_peer_discovery_timeouts() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = Arc::new(PostgresCrawlerRepository::new(&db.config)?);
    let (endpoint, server) = start_fake_peer(FakePeerMode::NoAddrResponse).await?;
    let crawler = Crawler::with_adapters(
        crawler_retry_test_config(),
        repository,
        Arc::new(UnavailableEnrichmentProvider),
    );

    let summary = crawler
        .run_with_seed_nodes(vec![endpoint.clone()])
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    server.abort();

    assert_eq!(summary.failed_tasks, 3);
    assert_unreachable_node(&db, &endpoint, "peer_discovery").await?;

    Ok(())
}

fn closed_loopback_endpoint() -> TestResult<CrawlEndpoint> {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);

    Ok(CrawlEndpoint::new(
        Ipv4Addr::LOCALHOST.to_string(),
        port,
        CrawlNetwork::Ipv4,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ))
}

fn crawler_retry_test_config() -> CrawlerConfig {
    CrawlerConfig {
        max_concurrency: 1,
        max_in_flight_connects: 1,
        max_tracked_nodes: 16,
        max_runtime: StdDuration::from_secs(5),
        idle_timeout: StdDuration::from_millis(20),
        lifecycle_tick: StdDuration::from_millis(5),
        checkpoint_interval: StdDuration::from_millis(50),
        connect_timeout: StdDuration::from_millis(100),
        connect_max_attempts: 3,
        unreachable_nodes_lookback: StdDuration::from_secs(7 * 24 * 60 * 60),
        follow_discovered_nodes: true,
        connect_retry_backoff: StdDuration::ZERO,
        io_timeout: StdDuration::from_millis(100),
        tor_socks5_addr: None,
        shutdown_grace_period: StdDuration::from_secs(1),
        verbose: false,
    }
}

async fn assert_unreachable_node(
    db: &TestDatabase,
    endpoint: &CrawlEndpoint,
    expected_failure_classification: &str,
) -> TestResult {
    let client = db.connect().await?;
    let row = query::<Postgres>(
        "
SELECT
    endpoint,
    network_type,
    last_failure_classification,
    failure_count,
    recovered_at
FROM unreachable_nodes
WHERE endpoint = $1
",
    )
    .bind(endpoint.canonical.as_str())
    .fetch_one(&client)
    .await?;

    assert_eq!(row.get::<String, _>("endpoint"), endpoint.canonical);
    assert_eq!(row.get::<String, _>("network_type"), "ipv4");
    assert_eq!(
        row.get::<String, _>("last_failure_classification"),
        expected_failure_classification
    );
    assert_eq!(row.get::<i64, _>("failure_count"), 1);
    assert!(
        row.get::<Option<chrono::DateTime<Utc>>, _>("recovered_at")
            .is_none()
    );

    Ok(())
}

#[derive(Clone, Copy)]
enum FakePeerMode {
    Silent,
    NoAddrResponse,
}

async fn start_fake_peer(mode: FakePeerMode) -> TestResult<(CrawlEndpoint, JoinHandle<()>)> {
    let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let endpoint = CrawlEndpoint::new(
        Ipv4Addr::LOCALHOST.to_string(),
        port,
        CrawlNetwork::Ipv4,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_fake_peer_connection(stream, mode));
        }
    });

    Ok((endpoint, server))
}

async fn handle_fake_peer_connection(mut stream: TcpStream, mode: FakePeerMode) {
    match mode {
        FakePeerMode::Silent => {
            tokio::time::sleep(StdDuration::from_secs(1)).await;
        }
        FakePeerMode::NoAddrResponse => {
            if complete_fake_handshake(&mut stream).await.is_ok() {
                tokio::time::sleep(StdDuration::from_secs(1)).await;
            }
        }
    }
}

async fn complete_fake_handshake(stream: &mut TcpStream) -> std::io::Result<()> {
    let first = wire::read_message_async(stream).await?;
    if first.command != Command::Version {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected version message",
        ));
    }

    let payload = wire::build_version_payload(wire::constants::PROTOCOL_VERSION, 0)?;
    wire::send_message_async(stream, Command::Version, &payload).await?;
    wire::send_message_async(stream, Command::Verack, &[]).await?;

    loop {
        let raw = wire::read_message_async(stream).await?;
        match raw.command {
            Command::Verack => return Ok(()),
            Command::Ping => wire::send_message_async(stream, Command::Pong, &raw.payload).await?,
            _ => {}
        }
    }
}

#[tokio::test]
async fn repository_batches_large_observation_streams() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;

    let run_id = run_id(11);
    let base_time = Utc::now();
    let observations = (0..1001)
        .map(|index| {
            let host = format!("10.1.{}.{}", index / 256, index % 256);
            sample_verified_observation(
                &run_id,
                &host,
                base_time + Duration::milliseconds(index as i64),
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            )
        })
        .collect::<Vec<_>>();

    repository.insert_observations_stream(observations).await?;

    let client = db.connect().await?;
    let row = query::<Postgres>(
        "
SELECT COUNT(*) AS observations
FROM node_observations
WHERE crawl_run_id = $1
",
    )
    .bind(run_id.as_uuid())
    .fetch_one(&client)
    .await?;

    assert_eq!(row.get::<i64, _>("observations"), 1001);

    Ok(())
}

#[tokio::test]
async fn repository_uses_checkpoint_sequence_to_break_timestamp_ties() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;

    let run_id = run_id(2);
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
            CrawlPhase::Finished,
            tied_time,
            2,
            Some("checkpoint tie".to_string()),
        ))
        .await?;

    let latest = repository
        .get_run_checkpoint(&run_id)
        .await?
        .expect("checkpoint");
    assert_eq!(latest.phase, CrawlPhase::Finished);
    assert_eq!(latest.checkpoint_sequence, 2);
    assert_eq!(latest.stop_reason.as_deref(), Some("checkpoint tie"));

    let runs = repository.list_runs().await?;
    let run = runs
        .into_iter()
        .find(|checkpoint| checkpoint.run_id == run_id)
        .expect("run summary");
    assert_eq!(run.phase, CrawlPhase::Finished);
    assert_eq!(run.checkpoint_sequence, 2);
    assert_eq!(run.stop_reason.as_deref(), Some("checkpoint tie"));
    assert_eq!(run.metrics.unique_nodes, 6);
    assert_eq!(run.metrics.persisted_observation_rows, 8);

    Ok(())
}

#[tokio::test]
async fn repository_persists_real_mmdb_enrichment_and_non_routable_not_applicable() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;
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

    let run_id = run_id(5);
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
                observed_at,
                provider.enrich(&public_endpoint),
            ),
            sample_verified_observation_for_endpoint(
                &run_id,
                &private_endpoint,
                observed_at + Duration::seconds(1),
                provider.enrich(&private_endpoint),
            ),
        ])
        .await?;

    let client = db.connect().await?;
    let rows = query::<Postgres>(
        "
SELECT endpoint, enrichment_status, asn, country, prefix
FROM node_observations
ORDER BY observed_at ASC
",
    )
    .fetch_all(&client)
    .await?;

    assert_eq!(rows.len(), 2);

    assert_eq!(
        rows[0].get::<String, _>("endpoint"),
        public_endpoint.canonical
    );
    assert_eq!(rows[0].get::<String, _>("enrichment_status"), "matched");
    assert_eq!(rows[0].get::<Option<i32>, _>("asn"), Some(13335));
    assert_eq!(
        rows[0].get::<Option<String>, _>("country").as_deref(),
        Some("AU")
    );
    assert_eq!(
        rows[0].get::<Option<String>, _>("prefix").as_deref(),
        Some("1.1.1.0/24")
    );

    assert_eq!(
        rows[1].get::<String, _>("endpoint"),
        private_endpoint.canonical
    );
    assert_eq!(
        rows[1].get::<String, _>("enrichment_status"),
        "not_applicable"
    );
    assert_eq!(rows[1].get::<Option<i32>, _>("asn"), None);
    assert_eq!(rows[1].get::<Option<String>, _>("country"), None);
    assert_eq!(rows[1].get::<Option<String>, _>("prefix"), None);

    Ok(())
}

#[tokio::test]
async fn analytics_reader_lists_runs_with_derived_percentages() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;
    let base_time = Utc::now();

    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id(6),
            CrawlPhase::Finished,
            base_time,
            1,
            Some("idle timeout".to_string()),
        ))
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id(7),
            CrawlPhase::Finished,
            base_time + Duration::seconds(5),
            1,
            Some("connection failure".to_string()),
        ))
        .await?;

    let runs = CrawlerAnalyticsReader::list_crawl_runs(&repository, 1).await?;

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id(7).to_string());
    assert_eq!(runs[0].phase, "finished");
    assert_eq!(runs[0].success_pct, 133.33);
    assert_eq!(runs[0].scheduled_pct, 50.0);
    assert_eq!(runs[0].unscheduled_gap, 3);

    Ok(())
}

#[tokio::test]
async fn analytics_reader_returns_run_detail_with_failure_and_network_breakdowns() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;
    let run_id = run_id(8);
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_verified_observation(
                &run_id,
                "1.1.1.7",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_failed_observation(&run_id, "1.1.1.9", base_time + Duration::seconds(1)),
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
            CrawlPhase::Finished,
            base_time + Duration::seconds(3),
            2,
            Some("checkpoint failure".to_string()),
        ))
        .await?;

    let detail = CrawlerAnalyticsReader::get_crawl_run(&repository, &run_id, 10)
        .await?
        .expect("run detail");

    assert_eq!(detail.run.run_id, run_id.to_string());
    assert_eq!(detail.run.phase, "finished");
    assert_eq!(detail.checkpoints.len(), 2);
    assert_eq!(detail.checkpoints[0].phase, "finished");
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
    let repository = PostgresCrawlerRepository::new(&db.config)?;
    let run_id = run_id(9);
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_verified_observation(
                &run_id,
                "1.1.1.7",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_verified_observation(
                &run_id,
                "8.8.8.8",
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

#[tokio::test]
async fn analytics_reader_last_run_aggregations_use_latest_finished_run() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;
    let finished_run_id = run_id(10);
    let newer_unfinished_run_id = run_id(11);
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![
            sample_verified_observation(
                &finished_run_id,
                "1.1.1.7",
                base_time,
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_verified_observation(
                &finished_run_id,
                "1.1.1.8",
                base_time + Duration::seconds(1),
                Some(64512),
                Some("Example ASN"),
                Some("US"),
            ),
            sample_verified_observation(
                &newer_unfinished_run_id,
                "8.8.8.8",
                base_time + Duration::seconds(2),
                Some(15169),
                Some("Google LLC"),
                Some("US"),
            ),
        ])
        .await?;

    repository
        .insert_run_checkpoint(sample_checkpoint(
            &finished_run_id,
            CrawlPhase::Finished,
            base_time + Duration::seconds(3),
            1,
            Some("idle timeout".to_string()),
        ))
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &newer_unfinished_run_id,
            CrawlPhase::Crawling,
            base_time + Duration::seconds(4),
            1,
            None,
        ))
        .await?;

    let asn_rows = CrawlerAnalyticsReader::list_last_run_asns(&repository, 10).await?;
    let network_rows = CrawlerAnalyticsReader::list_last_run_network_types(&repository, 10).await?;

    assert_eq!(asn_rows.len(), 1);
    assert_eq!(asn_rows[0].asn, 64512);
    assert_eq!(asn_rows[0].asn_organization.as_deref(), Some("Example ASN"));
    assert_eq!(asn_rows[0].node_count, 2);
    assert_eq!(network_rows.len(), 1);
    assert_eq!(network_rows[0].network_type, "ipv4");
    assert_eq!(network_rows[0].node_count, 2);

    Ok(())
}

#[tokio::test]
async fn analytics_reader_lists_last_run_node_rows_for_dashboard_table() -> TestResult {
    let db = TestDatabase::start().await?;
    db.apply_migrations().await?;
    let repository = PostgresCrawlerRepository::new(&db.config)?;
    let run_id = run_id(12);
    let base_time = Utc::now();

    repository
        .insert_observations_stream(vec![sample_verified_observation(
            &run_id,
            "1.1.1.7",
            base_time,
            Some(64512),
            Some("Example ASN"),
            Some("US"),
        )])
        .await?;
    repository
        .insert_run_checkpoint(sample_checkpoint(
            &run_id,
            CrawlPhase::Finished,
            base_time + Duration::seconds(1),
            1,
            Some("idle timeout".to_string()),
        ))
        .await?;

    let rows = CrawlerAnalyticsReader::list_last_run_nodes(&repository, 10).await?;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].endpoint, "1.1.1.7:8333");
    assert_eq!(rows[0].network_type, "ipv4");
    assert_eq!(rows[0].protocol_version, 70016);
    assert_eq!(rows[0].user_agent, "/Satoshi:27.0.0/");
    assert_eq!(rows[0].services, "1");
    assert_eq!(rows[0].start_height, 900_000);
    assert_eq!(rows[0].country.as_deref(), Some("US"));
    assert_eq!(rows[0].asn, Some(64512));
    assert_eq!(rows[0].asn_organization.as_deref(), Some("Example ASN"));

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
        protocol_version: Some(70016),
        services: Some(1),
        user_agent: Some("/Satoshi:27.0.0/".to_string()),
        start_height: Some(900_000),
        relay: Some(true),
        discovered_peer_addresses_count: 8,
        latency: Some(std::time::Duration::from_millis(125)),
        failure_classification: None,
    }
    .into_persisted(IpEnrichment::matched(
        asn,
        asn_organization.map(ToString::to_string),
        country.map(ToString::to_string),
        asn.map(|_| format!("{host}/24")),
    ))
}

fn sample_verified_observation_for_endpoint(
    run_id: &CrawlRunId,
    endpoint: &CrawlEndpoint,
    observed_at: chrono::DateTime<Utc>,
    enrichment: IpEnrichment,
) -> PersistedNodeObservation {
    RawNodeObservation {
        observed_at,
        crawl_run_id: run_id.clone(),
        endpoint: endpoint.clone(),
        protocol_version: Some(70016),
        services: Some(1),
        user_agent: Some("/Satoshi:27.0.0/".to_string()),
        start_height: Some(900_000),
        relay: Some(true),
        discovered_peer_addresses_count: 8,
        latency: Some(std::time::Duration::from_millis(125)),
        failure_classification: None,
    }
    .into_persisted(enrichment)
}

fn sample_failed_observation(
    run_id: &CrawlRunId,
    host: &str,
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
        protocol_version: None,
        services: None,
        user_agent: None,
        start_height: None,
        relay: None,
        discovered_peer_addresses_count: 0,
        latency: Some(std::time::Duration::from_millis(300)),
        failure_classification: Some(btc_network::crawler::FailureClassification::Handshake),
    }
    .into_persisted(IpEnrichment::matched(
        Some(64513),
        Some("Transit ASN".to_string()),
        Some("DE".to_string()),
        Some(format!("{host}/24")),
    ))
}

fn sample_connect_failed_observation(
    run_id: &CrawlRunId,
    host: &str,
    observed_at: chrono::DateTime<Utc>,
) -> PersistedNodeObservation {
    RawNodeObservation {
        observed_at,
        crawl_run_id: *run_id,
        endpoint: CrawlEndpoint::new(
            host,
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(host.parse::<Ipv4Addr>().expect("valid ipv4"))),
        ),
        protocol_version: None,
        services: None,
        user_agent: None,
        start_height: None,
        relay: None,
        discovered_peer_addresses_count: 0,
        latency: Some(std::time::Duration::from_millis(300)),
        failure_classification: Some(btc_network::crawler::FailureClassification::Connect),
    }
    .into_persisted(IpEnrichment::matched(
        Some(64513),
        Some("Transit ASN".to_string()),
        Some("DE".to_string()),
        Some(format!("{host}/24")),
    ))
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
            unique_nodes: 6,
            persisted_observation_rows: 8,
            writer_backlog: 0,
        },
    }
}
