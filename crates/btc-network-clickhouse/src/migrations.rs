use chrono::{DateTime, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::config::ClickHouseConnectionConfig;

const SCHEMA_MIGRATIONS_TABLE: &str = "schema_migrations";
const CREATE_DATABASE_SQL: &str = "CREATE DATABASE IF NOT EXISTS ?";
const CREATE_SCHEMA_MIGRATIONS_SQL: &str = r"
CREATE TABLE IF NOT EXISTS ? (
    version String,
    name String,
    checksum FixedString(64),
    applied_at DateTime64(3, 'UTC')
) ENGINE = MergeTree
ORDER BY version
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    version: &'static str,
    name: &'static str,
    sql: &'static str,
    checksum: String,
}

impl Migration {
    fn new(version: &'static str, name: &'static str, sql: &'static str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(sql.as_bytes());
        let checksum = hex::encode(hasher.finalize());

        Self {
            version,
            name,
            sql,
            checksum,
        }
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub fn name(&self) -> &str {
        self.name
    }

    pub fn sql(&self) -> &str {
        self.sql
    }

    pub fn checksum(&self) -> &str {
        &self.checksum
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub struct AppliedMigration {
    pub version: String,
    pub name: String,
    pub checksum: String,
    pub applied_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub applied_versions: Vec<String>,
    pub skipped_versions: Vec<String>,
}

#[derive(Debug)]
pub enum ClickHouseMigrationError {
    Query {
        context: String,
        source: clickhouse::error::Error,
    },
    ChecksumMismatch {
        version: String,
        expected: String,
        actual: String,
    },
}

impl ClickHouseMigrationError {
    fn query(context: impl Into<String>, source: clickhouse::error::Error) -> Self {
        Self::Query {
            context: context.into(),
            source,
        }
    }
}

impl Display for ClickHouseMigrationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query { context, source } => {
                write!(f, "{context}: {source}")
            }
            Self::ChecksumMismatch {
                version,
                expected,
                actual,
            } => write!(
                f,
                "migration checksum mismatch for version {version}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl Error for ClickHouseMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Query { source, .. } => Some(source),
            Self::ChecksumMismatch { .. } => None,
        }
    }
}

pub struct ClickHouseMigrationRunner {
    client: Client,
    database: String,
}

impl ClickHouseMigrationRunner {
    pub fn new(config: &ClickHouseConnectionConfig) -> Self {
        Self {
            client: config.admin_client(),
            database: config.database().to_string(),
        }
    }

    pub fn with_client(client: Client, database: impl Into<String>) -> Self {
        Self {
            client,
            database: database.into(),
        }
    }

    pub async fn apply_all(&self) -> Result<MigrationReport, ClickHouseMigrationError> {
        self.ensure_database().await?;
        self.ensure_schema_migrations_table().await?;

        let applied = self.applied_migrations().await?;
        let applied_versions = applied
            .iter()
            .map(|migration| migration.version.clone())
            .collect::<HashSet<_>>();

        for migration in &applied {
            if let Some(expected) = bundled_migrations()
                .iter()
                .find(|candidate| candidate.version() == migration.version)
            {
                if expected.checksum() != migration.checksum {
                    return Err(ClickHouseMigrationError::ChecksumMismatch {
                        version: migration.version.clone(),
                        expected: expected.checksum().to_string(),
                        actual: migration.checksum.clone(),
                    });
                }
            }
        }

        let mut report = MigrationReport {
            applied_versions: Vec::new(),
            skipped_versions: Vec::new(),
        };

        for migration in bundled_migrations() {
            if applied_versions.contains(migration.version()) {
                report
                    .skipped_versions
                    .push(migration.version().to_string());
                continue;
            }

            self.execute_migration(&migration).await?;
            self.record_migration(&migration).await?;
            report
                .applied_versions
                .push(migration.version().to_string());
        }

        Ok(report)
    }

    pub async fn applied_migrations(
        &self,
    ) -> Result<Vec<AppliedMigration>, ClickHouseMigrationError> {
        self.database_client()
            .query("SELECT ?fields FROM ? ORDER BY version ASC")
            .bind(Identifier(SCHEMA_MIGRATIONS_TABLE))
            .fetch_all::<AppliedMigration>()
            .await
            .map_err(|err| ClickHouseMigrationError::query("fetch applied migrations", err))
    }

    async fn ensure_database(&self) -> Result<(), ClickHouseMigrationError> {
        self.client
            .query(CREATE_DATABASE_SQL)
            .with_option("wait_end_of_query", "1")
            .bind(Identifier(&self.database))
            .execute()
            .await
            .map_err(|err| ClickHouseMigrationError::query("create database", err))
    }

    async fn ensure_schema_migrations_table(&self) -> Result<(), ClickHouseMigrationError> {
        self.database_client()
            .query(CREATE_SCHEMA_MIGRATIONS_SQL)
            .with_option("wait_end_of_query", "1")
            .bind(Identifier(SCHEMA_MIGRATIONS_TABLE))
            .execute()
            .await
            .map_err(|err| ClickHouseMigrationError::query("create schema_migrations table", err))
    }

    async fn execute_migration(
        &self,
        migration: &Migration,
    ) -> Result<(), ClickHouseMigrationError> {
        let rendered = migration.sql().replace(
            "__BTC_NETWORK_DATABASE__",
            &quoted_identifier(&self.database),
        );

        self.client
            .query(&rendered)
            .with_option("wait_end_of_query", "1")
            .execute()
            .await
            .map_err(|err| {
                ClickHouseMigrationError::query(
                    format!(
                        "execute migration {} {}",
                        migration.version(),
                        migration.name()
                    ),
                    err,
                )
            })
    }

    async fn record_migration(
        &self,
        migration: &Migration,
    ) -> Result<(), ClickHouseMigrationError> {
        let mut insert = self
            .database_client()
            .insert::<AppliedMigration>(SCHEMA_MIGRATIONS_TABLE)
            .await
            .map_err(|err| {
                ClickHouseMigrationError::query("start schema_migrations insert", err)
            })?;

        insert
            .write(&AppliedMigration {
                version: migration.version().to_string(),
                name: migration.name().to_string(),
                checksum: migration.checksum().to_string(),
                applied_at: Utc::now(),
            })
            .await
            .map_err(|err| ClickHouseMigrationError::query("write schema_migrations row", err))?;

        insert
            .end()
            .await
            .map_err(|err| ClickHouseMigrationError::query("finish schema_migrations insert", err))
    }

    fn database_client(&self) -> Client {
        self.client.clone().with_database(self.database.clone())
    }
}

fn quoted_identifier(value: &str) -> String {
    format!("`{}`", value.replace('`', "\\`"))
}

pub fn bundled_migrations() -> Vec<Migration> {
    vec![
        Migration::new(
            "0001",
            "create_node_observations",
            include_str!("../migrations/0001_create_node_observations.sql"),
        ),
        Migration::new(
            "0002",
            "create_crawler_run_checkpoints",
            include_str!("../migrations/0002_create_crawler_run_checkpoints.sql"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use clickhouse::test::{self, handlers};

    #[test]
    fn bundled_migrations_have_unique_versions_and_checksums() {
        let migrations = bundled_migrations();
        let versions = migrations
            .iter()
            .map(|migration| migration.version().to_string())
            .collect::<HashSet<_>>();

        assert_eq!(versions.len(), migrations.len());
        assert!(
            migrations
                .iter()
                .all(|migration| migration.checksum().len() == 64)
        );
    }

    #[tokio::test]
    async fn migration_runner_applies_pending_migrations_and_records_them() {
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let runner = ClickHouseMigrationRunner::with_client(client, "btc_network");

        let create_db = mock.add(handlers::record_ddl());
        let create_ledger = mock.add(handlers::record_ddl());
        mock.add(handlers::provide(Vec::<AppliedMigration>::new()));
        let create_observations = mock.add(handlers::record_ddl());
        let record_migration_1 = mock.add(handlers::record());
        let create_checkpoints = mock.add(handlers::record_ddl());
        let record_migration_2 = mock.add(handlers::record());

        let report = runner.apply_all().await.expect("apply migrations");

        assert_eq!(report.applied_versions, vec!["0001", "0002"]);
        assert!(
            create_db
                .query()
                .await
                .contains("CREATE DATABASE IF NOT EXISTS")
        );
        assert!(create_ledger.query().await.contains("schema_migrations"));
        assert!(
            create_observations
                .query()
                .await
                .contains("node_observations")
        );
        assert!(
            create_checkpoints
                .query()
                .await
                .contains("crawler_run_checkpoints")
        );

        let rows_1: Vec<AppliedMigration> = record_migration_1.collect().await;
        let rows_2: Vec<AppliedMigration> = record_migration_2.collect().await;
        assert_eq!(rows_1[0].version, "0001");
        assert_eq!(rows_2[0].version, "0002");
    }

    #[tokio::test]
    async fn migration_runner_rejects_checksum_drift_for_recorded_version() {
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let runner = ClickHouseMigrationRunner::with_client(client, "btc_network");

        let create_db = mock.add(handlers::record_ddl());
        let create_ledger = mock.add(handlers::record_ddl());
        mock.add(handlers::provide(vec![AppliedMigration {
            version: "0001".to_string(),
            name: "create_node_observations".to_string(),
            checksum: "deadbeef".repeat(8),
            applied_at: Utc::now(),
        }]));

        let err = runner.apply_all().await.expect_err("checksum mismatch");

        assert!(matches!(
            err,
            ClickHouseMigrationError::ChecksumMismatch { .. }
        ));
        assert!(create_db.query().await.contains("CREATE DATABASE"));
        assert!(create_ledger.query().await.contains("schema_migrations"));
    }
}
