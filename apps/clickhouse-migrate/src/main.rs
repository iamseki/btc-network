use std::error::Error;

use btc_network_clickhouse::{ClickHouseConnectionConfig, ClickHouseMigrationRunner};
use btc_network_observability::init_tracing;
use clap::{Args, Parser};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "clickhouse-migrate")]
struct Cli {
    #[command(flatten)]
    clickhouse: ClickHouseArgs,
}

#[derive(Args, Debug, Clone)]
struct ClickHouseArgs {
    #[arg(
        long,
        env = "BTC_NETWORK_CLICKHOUSE_URL",
        default_value = "http://localhost:8123"
    )]
    clickhouse_url: String,

    #[arg(
        long,
        env = "BTC_NETWORK_CLICKHOUSE_DATABASE",
        default_value = "btc_network"
    )]
    clickhouse_database: String,

    #[arg(long, env = "BTC_NETWORK_CLICKHOUSE_USER")]
    clickhouse_user: Option<String>,

    #[arg(long, env = "BTC_NETWORK_CLICKHOUSE_PASSWORD", hide_env_values = true)]
    clickhouse_password: Option<String>,
}

fn build_clickhouse_config(args: &ClickHouseArgs) -> ClickHouseConnectionConfig {
    let mut config = ClickHouseConnectionConfig::new(
        args.clickhouse_url.clone(),
        args.clickhouse_database.clone(),
    );

    if let Some(user) = &args.clickhouse_user {
        config = config.with_user(user.clone());
    }

    if let Some(password) = &args.clickhouse_password {
        config = config.with_password(password.clone());
    }

    config
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();
    let cli = Cli::parse();
    run_clickhouse_migrations(cli.clickhouse).await
}

async fn run_clickhouse_migrations(args: ClickHouseArgs) -> Result<(), Box<dyn Error>> {
    let config = build_clickhouse_config(&args);
    let report = ClickHouseMigrationRunner::new(&config).apply_all().await?;

    info!(
        "ClickHouse migrations finished: {} applied, {} skipped.",
        report.applied_versions.len(),
        report.skipped_versions.len()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn clickhouse_config_applies_optional_auth() {
        let args = ClickHouseArgs {
            clickhouse_url: "http://clickhouse.internal:8123".to_string(),
            clickhouse_database: "btc_network".to_string(),
            clickhouse_user: Some("crawler_writer".to_string()),
            clickhouse_password: Some("secret".to_string()),
        };

        let config = build_clickhouse_config(&args);

        assert_eq!(config.url(), "http://clickhouse.internal:8123");
        assert_eq!(config.database(), "btc_network");
    }

    #[test]
    fn migration_cli_parses_clickhouse_args() {
        let cli = Cli::try_parse_from([
            "clickhouse-migrate",
            "--clickhouse-url",
            "http://clickhouse.internal:8123",
            "--clickhouse-password",
            "secret",
        ])
        .expect("cli");

        assert_eq!(
            cli.clickhouse.clickhouse_url,
            "http://clickhouse.internal:8123"
        );
        assert_eq!(
            cli.clickhouse.clickhouse_password.as_deref(),
            Some("secret")
        );
    }
}
