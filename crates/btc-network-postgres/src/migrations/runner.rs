use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use chrono::Utc;
use sqlx::{PgPool, Row};

use crate::config::{PostgresConfigError, PostgresConnectionConfig};

use super::bundled::bundled_migrations;
use super::model::{AppliedMigration, Migration, MigrationReport};

const CREATE_SCHEMA_MIGRATIONS_SQL: &str = r"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL
)
";

/// Error returned while bootstrapping or applying PostgreSQL schema migrations.
#[derive(Debug)]
pub enum PostgresMigrationError {
    Config(PostgresConfigError),
    Query {
        context: String,
        source: sqlx::Error,
    },
    ChecksumMismatch {
        version: String,
        expected: String,
        actual: String,
    },
}

impl PostgresMigrationError {
    fn query(context: impl Into<String>, source: sqlx::Error) -> Self {
        Self::Query {
            context: context.into(),
            source,
        }
    }
}

impl Display for PostgresMigrationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(source) => write!(f, "{source}"),
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

impl Error for PostgresMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::Query { source, .. } => Some(source),
            Self::ChecksumMismatch { .. } => None,
        }
    }
}

impl From<PostgresConfigError> for PostgresMigrationError {
    fn from(value: PostgresConfigError) -> Self {
        Self::Config(value)
    }
}

/// Applies the bundled schema migrations to a PostgreSQL deployment.
pub struct PostgresMigrationRunner {
    pool: PgPool,
}

impl PostgresMigrationRunner {
    pub fn new(config: &PostgresConnectionConfig) -> Result<Self, PostgresMigrationError> {
        Ok(Self {
            pool: config.pool()?,
        })
    }

    pub async fn apply_all(&self) -> Result<MigrationReport, PostgresMigrationError> {
        sqlx::raw_sql(CREATE_SCHEMA_MIGRATIONS_SQL)
            .execute(&self.pool)
            .await
            .map_err(|err| PostgresMigrationError::query("create schema_migrations table", err))?;

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
                return Err(PostgresMigrationError::ChecksumMismatch {
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

    pub async fn applied_migrations(
        &self,
    ) -> Result<Vec<AppliedMigration>, PostgresMigrationError> {
        let rows = sqlx::query(
            "
SELECT version, name, checksum, applied_at
FROM schema_migrations
ORDER BY version ASC
",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|err| PostgresMigrationError::query("fetch applied migrations", err))?;

        Ok(rows
            .into_iter()
            .map(|row| AppliedMigration {
                version: row.get("version"),
                name: row.get("name"),
                checksum: row.get("checksum"),
                applied_at: row.get("applied_at"),
            })
            .collect())
    }

    async fn execute_migration(&self, migration: &Migration) -> Result<(), PostgresMigrationError> {
        sqlx::raw_sql(migration.sql())
            .execute(&self.pool)
            .await
            .map_err(|err| {
                PostgresMigrationError::query(
                    format!(
                        "execute migration {} {}",
                        migration.version(),
                        migration.name()
                    ),
                    err,
                )
            })?;

        Ok(())
    }

    async fn record_migration(&self, migration: &Migration) -> Result<(), PostgresMigrationError> {
        sqlx::query(
            "
INSERT INTO schema_migrations (version, name, checksum, applied_at)
VALUES ($1, $2, $3, $4)
",
        )
        .bind(migration.version())
        .bind(migration.name())
        .bind(migration.checksum())
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .map_err(|err| PostgresMigrationError::query("record schema_migrations row", err))?;

        Ok(())
    }
}
