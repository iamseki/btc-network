use std::error::Error;
use std::fmt::{Display, Formatter};

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Connection settings for the PostgreSQL crawler storage adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct PostgresConnectionConfig {
    url: String,
    max_connections: usize,
}

impl PostgresConnectionConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 16,
        }
    }

    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub fn pool(&self) -> Result<PgPool, PostgresConfigError> {
        PgPoolOptions::new()
            .max_connections(self.max_connections as u32)
            .connect_lazy(&self.url)
            .map_err(PostgresConfigError::PoolConnect)
    }
}

impl Default for PostgresConnectionConfig {
    fn default() -> Self {
        Self::new("postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network")
    }
}

/// Error returned while building a PostgreSQL adapter config or pool.
#[derive(Debug)]
pub enum PostgresConfigError {
    PoolConnect(sqlx::Error),
}

impl Display for PostgresConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PoolConnect(source) => {
                write!(f, "failed to create postgres connection pool: {source}")
            }
        }
    }
}

impl Error for PostgresConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PoolConnect(source) => Some(source),
        }
    }
}
