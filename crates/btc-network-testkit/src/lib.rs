use std::env;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use btc_network_postgres::{PostgresConnectionConfig, PostgresMigrationRunner};
use chrono::{DateTime, Utc};
use csv::Trim;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx_core::query::query;
use sqlx_postgres::PgPool;
use testcontainers_modules::{
    postgres,
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};
use tokio::sync::{Mutex, OnceCell};
use url::Url;
use uuid::Uuid;

pub type TestkitResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const CHECKPOINT_FIXTURE_FILE: &str = "crawler_run_checkpoints.csv";
const OBSERVATION_FIXTURE_FILE: &str = "node_observations.csv";
const EXPECTED_RESULT_FILE: &str = "expected.json";
const TEST_POSTGRES_ADMIN_URL_ENV: &str = "BTC_NETWORK_TEST_POSTGRES_ADMIN_URL";
const TEST_POSTGRES_KEEP_DATABASES_ENV: &str = "BTC_NETWORK_TEST_KEEP_DATABASES";
const TEST_POSTGRES_PASSWORD: &str = "btc-network-test";
const TEST_POSTGRES_USER: &str = "postgres";
const TEST_POSTGRES_DB: &str = "postgres";

static SHARED_POSTGRES: OnceCell<SharedPostgres> = OnceCell::const_new();

struct SharedPostgres {
    _container: Option<Mutex<ContainerAsync<postgres::Postgres>>>,
    admin_url: String,
    next_database_id: AtomicU64,
}

impl SharedPostgres {
    fn external(admin_url: String) -> Self {
        Self {
            _container: None,
            admin_url,
            next_database_id: AtomicU64::new(0),
        }
    }

    fn testcontainer(admin_url: String, container: ContainerAsync<postgres::Postgres>) -> Self {
        Self {
            _container: Some(Mutex::new(container)),
            admin_url,
            next_database_id: AtomicU64::new(0),
        }
    }

    fn database_url(&self, database_name: &str) -> TestkitResult<String> {
        let mut url = Url::parse(&self.admin_url)?;
        url.set_path(&format!("/{database_name}"));
        Ok(url.into())
    }

    async fn create_database(&self, scenario_name: &str) -> TestkitResult<String> {
        let database_name = unique_database_name(scenario_name, &self.next_database_id);
        let admin_pool = PgPool::connect(&self.admin_url).await?;
        let create_sql = format!(r#"CREATE DATABASE "{database_name}""#);

        query(&create_sql).execute(&admin_pool).await?;
        admin_pool.close().await;

        Ok(database_name)
    }
}

pub struct ScenarioDatabase {
    config: PostgresConnectionConfig,
    admin_url: String,
    database_name: String,
    drop_database_on_drop: bool,
}

impl ScenarioDatabase {
    pub async fn create(scenario_name: &str) -> TestkitResult<Self> {
        let postgres = shared_postgres().await?;
        let database_name = postgres.create_database(scenario_name).await?;
        let config = PostgresConnectionConfig::new(postgres.database_url(&database_name)?)
            .with_max_connections(10);

        PostgresMigrationRunner::new(&config)?.apply_all().await?;

        Ok(Self {
            config,
            admin_url: postgres.admin_url.clone(),
            database_name,
            drop_database_on_drop: !env_var_is_truthy(TEST_POSTGRES_KEEP_DATABASES_ENV),
        })
    }

    pub fn config(&self) -> &PostgresConnectionConfig {
        &self.config
    }

    pub async fn connect(&self) -> TestkitResult<PgPool> {
        Ok(PgPool::connect(self.config.url()).await?)
    }

    pub async fn seed_fixture_dir(&self, fixture_dir: impl AsRef<Path>) -> TestkitResult {
        let fixture_dir = fixture_dir.as_ref();
        let pool = self.connect().await?;

        let checkpoint_path = fixture_dir.join(CHECKPOINT_FIXTURE_FILE);
        if checkpoint_path.exists() {
            insert_run_checkpoints_csv(&pool, &checkpoint_path).await?;
        }

        let observation_path = fixture_dir.join(OBSERVATION_FIXTURE_FILE);
        if observation_path.exists() {
            insert_node_observations_csv(&pool, &observation_path).await?;
        }

        pool.close().await;
        Ok(())
    }
}

impl Drop for ScenarioDatabase {
    fn drop(&mut self) {
        if !self.drop_database_on_drop {
            return;
        }

        let admin_url = self.admin_url.clone();
        let database_name = self.database_name.clone();
        let cleanup_database_name = database_name.clone();

        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;

            runtime.block_on(drop_database(&admin_url, &cleanup_database_name))
        })
        .join();

        match cleanup {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!(
                    "btc-network-testkit: failed to drop test database {database_name}: {error}"
                );
            }
            Err(_) => {
                eprintln!(
                    "btc-network-testkit: failed to join cleanup thread for test database {database_name}"
                );
            }
        }
    }
}

pub struct FixtureRouterApp {
    pub router: Router,
    _database: ScenarioDatabase,
    fixture: Option<FixtureScenario>,
}

impl FixtureRouterApp {
    pub async fn empty<F>(scenario_name: &str, build_router: F) -> TestkitResult<Self>
    where
        F: FnOnce(&ScenarioDatabase) -> TestkitResult<Router>,
    {
        let database = ScenarioDatabase::create(scenario_name).await?;
        let router = build_router(&database)?;

        Ok(Self {
            router,
            _database: database,
            fixture: None,
        })
    }

    pub async fn from_fixture_root<F>(
        fixture_root: impl AsRef<Path>,
        scenario_name: &str,
        build_router: F,
    ) -> TestkitResult<Self>
    where
        F: FnOnce(&ScenarioDatabase) -> TestkitResult<Router>,
    {
        let fixture = FixtureScenario::new(fixture_root.as_ref(), scenario_name);
        let database = ScenarioDatabase::create(scenario_name).await?;
        database.seed_fixture_dir(fixture.path()).await?;
        let router = build_router(&database)?;

        Ok(Self {
            router,
            _database: database,
            fixture: Some(fixture),
        })
    }

    pub fn expected_json(&self, file_name: &str) -> TestkitResult<Value> {
        let fixture = self
            .fixture
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture not configured"))?;
        fixture.read_json(file_name)
    }

    pub fn expected_result(&self) -> TestkitResult<Value> {
        self.expected_json(EXPECTED_RESULT_FILE)
    }
}

pub fn request(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

pub async fn json_body(response: axum::response::Response) -> TestkitResult<Value> {
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&body)?)
}

struct FixtureScenario {
    path: PathBuf,
}

impl FixtureScenario {
    fn new(fixture_root: &Path, scenario_name: &str) -> Self {
        Self {
            path: fixture_root.join(scenario_name),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn read_json(&self, file_name: &str) -> TestkitResult<Value> {
        Ok(read_json_file(&self.path.join(file_name))?)
    }
}

#[derive(Debug, Deserialize)]
struct CrawlRunCheckpointFixtureRow {
    run_id: Uuid,
    phase: String,
    checkpointed_at: DateTime<Utc>,
    checkpoint_sequence: i64,
    started_at: DateTime<Utc>,
    stop_reason: Option<String>,
    failure_reason: Option<String>,
    frontier_size: i64,
    in_flight_work: i64,
    scheduled_tasks: i64,
    successful_handshakes: i64,
    failed_tasks: i64,
    unique_nodes: i64,
    persisted_observation_rows: i64,
    writer_backlog: i64,
}

#[derive(Debug, Deserialize)]
struct NodeObservationFixtureRow {
    observed_at: DateTime<Utc>,
    crawl_run_id: Uuid,
    endpoint: String,
    network_type: String,
    protocol_version: Option<i32>,
    services: Option<String>,
    user_agent: Option<String>,
    start_height: Option<i32>,
    relay: Option<bool>,
    discovered_peer_addresses_count: i64,
    latency_ms: Option<i64>,
    failure_classification: Option<String>,
    enrichment_status: String,
    asn: Option<i32>,
    asn_organization: Option<String>,
    country: Option<String>,
    prefix: Option<String>,
}

async fn insert_run_checkpoints_csv(pool: &PgPool, path: &Path) -> TestkitResult {
    for row in read_csv_rows::<CrawlRunCheckpointFixtureRow>(path)? {
        query(
            "
INSERT INTO crawler_run_checkpoints (
    run_id,
    phase,
    checkpointed_at,
    checkpoint_sequence,
    started_at,
    stop_reason,
    failure_reason,
    frontier_size,
    in_flight_work,
    scheduled_tasks,
    successful_handshakes,
    failed_tasks,
    unique_nodes,
    persisted_observation_rows,
    writer_backlog
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
)
",
        )
        .bind(row.run_id)
        .bind(row.phase)
        .bind(row.checkpointed_at)
        .bind(row.checkpoint_sequence)
        .bind(row.started_at)
        .bind(row.stop_reason)
        .bind(row.failure_reason)
        .bind(row.frontier_size)
        .bind(row.in_flight_work)
        .bind(row.scheduled_tasks)
        .bind(row.successful_handshakes)
        .bind(row.failed_tasks)
        .bind(row.unique_nodes)
        .bind(row.persisted_observation_rows)
        .bind(row.writer_backlog)
        .execute(pool)
        .await?;
    }

    Ok(())
}

async fn insert_node_observations_csv(pool: &PgPool, path: &Path) -> TestkitResult {
    for row in read_csv_rows::<NodeObservationFixtureRow>(path)? {
        query(
            "
INSERT INTO node_observations (
    observed_at,
    crawl_run_id,
    endpoint,
    network_type,
    protocol_version,
    services,
    user_agent,
    start_height,
    relay,
    discovered_peer_addresses_count,
    latency_ms,
    failure_classification,
    enrichment_status,
    asn,
    asn_organization,
    country,
    prefix
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
)
",
        )
        .bind(row.observed_at)
        .bind(row.crawl_run_id)
        .bind(row.endpoint)
        .bind(row.network_type)
        .bind(row.protocol_version)
        .bind(row.services)
        .bind(row.user_agent)
        .bind(row.start_height)
        .bind(row.relay)
        .bind(row.discovered_peer_addresses_count)
        .bind(row.latency_ms)
        .bind(row.failure_classification)
        .bind(row.enrichment_status)
        .bind(row.asn)
        .bind(row.asn_organization)
        .bind(row.country)
        .bind(row.prefix)
        .execute(pool)
        .await?;
    }

    Ok(())
}

fn read_csv_rows<T>(path: &Path) -> TestkitResult<Vec<T>>
where
    T: DeserializeOwned,
{
    let mut reader = csv::ReaderBuilder::new().trim(Trim::All).from_path(path)?;
    let mut rows = Vec::new();

    for row in reader.deserialize() {
        rows.push(row?);
    }

    Ok(rows)
}

fn read_json_file(path: &Path) -> TestkitResult<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

async fn drop_database(admin_url: &str, database_name: &str) -> TestkitResult {
    let admin_pool = PgPool::connect(admin_url).await?;

    query(
        "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = $1 AND pid <> pg_backend_pid()
",
    )
    .bind(database_name)
    .execute(&admin_pool)
    .await?;

    let drop_sql = format!(r#"DROP DATABASE IF EXISTS "{database_name}""#);
    query(&drop_sql).execute(&admin_pool).await?;
    admin_pool.close().await;

    Ok(())
}

fn env_var_is_truthy(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| env_value_is_truthy(&value))
        .unwrap_or(false)
}

fn env_value_is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::sync::atomic::AtomicU64;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct CsvRow {
        name: String,
        count: u32,
    }

    #[test]
    fn unique_database_name_sanitizes_truncates_and_increments() {
        let next_id = AtomicU64::new(7);
        let name = unique_database_name_with_process_id(
            "Historical Runs / Basic Scenario With Very Long Name!!!",
            4242,
            &next_id,
        );

        assert_eq!(name, "btc_network_api_historical_runs___ba_4242_7");
    }

    #[test]
    fn read_csv_rows_trims_fields() {
        let path = write_temp_file("rows.csv", "name,count\n Example ASN , 2 \nGoogle LLC,1\n");

        let rows = read_csv_rows::<CsvRow>(&path).expect("csv rows");

        assert_eq!(
            rows,
            vec![
                CsvRow {
                    name: "Example ASN".to_string(),
                    count: 2,
                },
                CsvRow {
                    name: "Google LLC".to_string(),
                    count: 1,
                },
            ]
        );
    }

    #[test]
    fn read_json_file_loads_expected_payload() {
        let path = write_temp_file("expected.json", &json!({ "rows": [1, 2, 3] }).to_string());

        let value = read_json_file(&path).expect("json file");

        assert_eq!(value, json!({ "rows": [1, 2, 3] }));
    }

    #[test]
    fn env_value_is_truthy_accepts_common_true_values() {
        for value in ["1", "true", "TRUE", " yes ", "On"] {
            assert!(super::env_value_is_truthy(value), "{value}");
        }
    }

    #[test]
    fn env_value_is_truthy_rejects_common_false_values() {
        for value in ["0", "false", "no", "off", ""] {
            assert!(!super::env_value_is_truthy(value), "{value}");
        }
    }

    #[test]
    fn database_url_replaces_only_database_name() {
        let shared = SharedPostgres::external(
            "postgresql://postgres:secret@127.0.0.1:55432/postgres?sslmode=disable".to_string(),
        );

        let database_url = shared
            .database_url("scenario_db")
            .expect("scenario database url");

        assert_eq!(
            database_url,
            "postgresql://postgres:secret@127.0.0.1:55432/scenario_db?sslmode=disable"
        );
    }

    fn write_temp_file(file_name: &str, contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = env::temp_dir().join(format!("btc-network-testkit-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(file_name);
        fs::write(&path, contents).expect("write temp file");
        path
    }
}

async fn shared_postgres() -> TestkitResult<&'static SharedPostgres> {
    SHARED_POSTGRES
        .get_or_try_init(|| async {
            if let Ok(admin_url) = env::var(TEST_POSTGRES_ADMIN_URL_ENV) {
                return Ok(SharedPostgres::external(admin_url));
            }

            let container = postgres::Postgres::default()
                .with_tag("18")
                .with_env_var("POSTGRES_DB", TEST_POSTGRES_DB)
                .with_env_var("POSTGRES_PASSWORD", TEST_POSTGRES_PASSWORD)
                .with_env_var("POSTGRES_USER", TEST_POSTGRES_USER)
                .start()
                .await?;
            let host = container.get_host().await?.to_string();
            let port = container.get_host_port_ipv4(5432).await?;
            let admin_url = format!(
                "postgresql://{TEST_POSTGRES_USER}:{TEST_POSTGRES_PASSWORD}@{host}:{port}/{TEST_POSTGRES_DB}"
            );

            Ok(SharedPostgres::testcontainer(admin_url, container))
        })
        .await
}

fn unique_database_name(scenario_name: &str, next_database_id: &AtomicU64) -> String {
    unique_database_name_with_process_id(scenario_name, std::process::id(), next_database_id)
}

fn unique_database_name_with_process_id(
    scenario_name: &str,
    process_id: u32,
    next_database_id: &AtomicU64,
) -> String {
    let mut sanitized = scenario_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    // Shared local PostgreSQL can persist across separate cargo test invocations,
    // so include the process id and keep the name under PostgreSQL's 63-byte limit.
    sanitized.truncate(20);
    sanitized = sanitized.trim_matches('_').to_string();
    if sanitized.is_empty() {
        sanitized = "scenario".to_string();
    }

    format!(
        "btc_network_api_{}_{}_{}",
        sanitized,
        process_id,
        next_database_id.fetch_add(1, Ordering::Relaxed)
    )
}
