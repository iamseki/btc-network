use clickhouse::{Client, sql::Identifier};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::config::ClickHouseConnectionConfig;

use super::bundled::bundled_migrations;
use super::model::{AppliedMigration, Migration, MigrationReport};

const SCHEMA_MIGRATIONS_TABLE: &str = "schema_migrations";
const CREATE_DATABASE_SQL: &str = "CREATE DATABASE IF NOT EXISTS ?";
const CREATE_SCHEMA_MIGRATIONS_SQL: &str = r"
CREATE TABLE IF NOT EXISTS ? (
    version String,
    name String,
    checksum String,
    applied_at DateTime
) ENGINE = MergeTree
ORDER BY version
";

/// Error returned while bootstrapping or applying ClickHouse schema migrations.
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
    pub(crate) fn query(context: impl Into<String>, source: clickhouse::error::Error) -> Self {
        Self::Query {
            context: context.into(),
            source,
        }
    }
}

impl Display for ClickHouseMigrationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query { context, source } => write!(f, "{context}: {source}"),
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

/// Applies the bundled schema migrations to a ClickHouse deployment.
pub struct ClickHouseMigrationRunner {
    client: Client,
    database: String,
}

impl ClickHouseMigrationRunner {
    /// Builds a migration runner from the shared ClickHouse connection config.
    pub fn new(config: &ClickHouseConnectionConfig) -> Self {
        Self {
            client: config.admin_client(),
            database: config.database().to_string(),
        }
    }

    /// Builds a migration runner from an already configured ClickHouse client.
    pub fn with_client(client: Client, database: impl Into<String>) -> Self {
        Self {
            client,
            database: database.into(),
        }
    }

    /// Ensures the database and migration table exist, validates previously
    /// applied checksums, and applies any remaining bundled migrations.
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
                && expected.checksum() != migration.checksum
            {
                return Err(ClickHouseMigrationError::ChecksumMismatch {
                    version: migration.version.clone(),
                    expected: expected.checksum().to_string(),
                    actual: migration.checksum.clone(),
                });
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

    /// Returns the currently recorded applied migrations ordered by version.
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
                applied_at: chrono::Utc::now(),
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
