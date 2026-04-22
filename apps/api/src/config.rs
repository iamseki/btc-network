use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use axum::http::HeaderValue;
use btc_network_postgres::PostgresConnectionConfig;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;
const DEFAULT_CONCURRENCY_LIMIT: usize = 64;
const DEFAULT_ALLOWED_ORIGINS: [&str; 7] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://btcnetwork.info",
    "https://www.btcnetwork.info",
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
];

#[derive(Clone)]
pub struct ApiRuntimeConfig {
    pub(crate) allowed_origins: Vec<HeaderValue>,
    pub(crate) request_timeout: Duration,
    pub(crate) concurrency_limit: usize,
}

impl ApiRuntimeConfig {
    pub fn with_allowed_origins(mut self, allowed_origins: Vec<HeaderValue>) -> Self {
        self.allowed_origins = allowed_origins;
        self
    }

    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    pub fn with_concurrency_limit(mut self, concurrency_limit: usize) -> Self {
        self.concurrency_limit = concurrency_limit;
        self
    }
}

impl Default for ApiRuntimeConfig {
    fn default() -> Self {
        Self {
            allowed_origins: DEFAULT_ALLOWED_ORIGINS
                .into_iter()
                .map(HeaderValue::from_static)
                .collect(),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
        }
    }
}

pub fn parse_bind_addr() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let value =
        env::var("BTC_NETWORK_API_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    Ok(value.parse()?)
}

pub fn parse_postgres_config() -> Result<PostgresConnectionConfig, Box<dyn std::error::Error>> {
    let url = env::var("BTC_NETWORK_POSTGRES_URL").unwrap_or_else(|_| {
        "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network".to_string()
    });
    let max_connections = parse_positive_usize_env("BTC_NETWORK_POSTGRES_MAX_CONNECTIONS", 16)?;

    Ok(PostgresConnectionConfig::new(url).with_max_connections(max_connections))
}

pub fn parse_runtime_config() -> Result<ApiRuntimeConfig, Box<dyn std::error::Error>> {
    Ok(ApiRuntimeConfig {
        allowed_origins: parse_allowed_origins()?,
        request_timeout: Duration::from_secs(parse_positive_u64_env(
            "BTC_NETWORK_API_REQUEST_TIMEOUT_SECS",
            DEFAULT_REQUEST_TIMEOUT_SECS,
        )?),
        concurrency_limit: parse_positive_usize_env(
            "BTC_NETWORK_API_CONCURRENCY_LIMIT",
            DEFAULT_CONCURRENCY_LIMIT,
        )?,
    })
}

fn parse_allowed_origins() -> Result<Vec<HeaderValue>, Box<dyn std::error::Error>> {
    let Some(value) = env::var("BTC_NETWORK_API_ALLOWED_ORIGINS").ok() else {
        return Ok(ApiRuntimeConfig::default().allowed_origins);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(ApiRuntimeConfig::default().allowed_origins);
    }

    let mut origins = Vec::new();
    for origin in trimmed
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
    {
        origins.push(HeaderValue::from_str(origin)?);
    }

    if origins.is_empty() {
        return Ok(ApiRuntimeConfig::default().allowed_origins);
    }

    Ok(origins)
}

fn parse_positive_usize_env(
    name: &str,
    default_value: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let Some(raw_value) = env::var(name).ok() else {
        return Ok(default_value);
    };

    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return Ok(default_value);
    }

    let value: usize = trimmed.parse()?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }

    Ok(value)
}

fn parse_positive_u64_env(
    name: &str,
    default_value: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(raw_value) = env::var(name).ok() else {
        return Ok(default_value);
    };

    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return Ok(default_value);
    }

    let value: u64 = trimmed.parse()?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::parse_postgres_config;

    #[test]
    fn parse_postgres_config_uses_defaults_and_max_connections_override() {
        unsafe {
            env::remove_var("BTC_NETWORK_POSTGRES_URL");
            env::set_var("BTC_NETWORK_POSTGRES_MAX_CONNECTIONS", "24");
        }

        let config = parse_postgres_config().expect("postgres config");

        assert_eq!(
            config.url(),
            "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network"
        );
        assert_eq!(config.max_connections(), 24);

        unsafe {
            env::remove_var("BTC_NETWORK_POSTGRES_MAX_CONNECTIONS");
        }
    }
}
