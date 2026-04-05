use std::error::Error;

use btc_network_observability::init_tracing;
use btc_network_postgres::{PostgresConnectionConfig, PostgresMigrationRunner};
use clap::{Args, Parser};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "postgres-migrate")]
struct Cli {
    #[command(flatten)]
    postgres: PostgresArgs,
}

#[derive(Args, Debug, Clone)]
struct PostgresArgs {
    #[arg(
        long,
        env = "BTC_NETWORK_POSTGRES_URL",
        default_value = "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network"
    )]
    postgres_url: String,
}

fn build_postgres_config(args: &PostgresArgs) -> PostgresConnectionConfig {
    PostgresConnectionConfig::new(args.postgres_url.clone())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();
    let cli = Cli::parse();
    run_postgres_migrations(cli.postgres).await
}

async fn run_postgres_migrations(args: PostgresArgs) -> Result<(), Box<dyn Error>> {
    let config = build_postgres_config(&args);
    let report = PostgresMigrationRunner::new(&config)?.apply_all().await?;

    info!(
        "PostgreSQL migrations finished: {} applied, {} skipped.",
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
    fn migration_cli_parses_postgres_args() {
        let cli = Cli::try_parse_from([
            "postgres-migrate",
            "--postgres-url",
            "postgresql://writer:secret@postgres.internal:5432/btc_network",
        ])
        .expect("cli");

        assert_eq!(
            cli.postgres.postgres_url,
            "postgresql://writer:secret@postgres.internal:5432/btc_network"
        );
    }
}
