use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    version: &'static str,
    name: &'static str,
    sql: &'static str,
    checksum: String,
}

impl Migration {
    pub(crate) fn new(version: &'static str, name: &'static str, sql: &'static str) -> Self {
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

    pub(crate) fn from_filename(filename: &'static str, sql: &'static str) -> Self {
        let (version, remainder) = filename
            .split_once('_')
            .expect("migration filename must start with a timestamp prefix");
        let name = remainder
            .strip_suffix(".sql")
            .expect("migration filename must end with .sql");

        assert!(
            version.len() == 14 && version.chars().all(|ch| ch.is_ascii_digit()),
            "migration filename must use YYYYMMDDHHMMSS_slug.sql"
        );
        assert!(
            !name.is_empty(),
            "migration filename must include a descriptive slug"
        );

        Self::new(version, name, sql)
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
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub applied_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub applied_versions: Vec<String>,
    pub skipped_versions: Vec<String>,
}
