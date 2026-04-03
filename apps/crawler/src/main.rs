use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use btc_network::crawler::{Crawler, CrawlerConfig, IpEnrichmentProvider};
use btc_network_clickhouse::{ClickHouseConnectionConfig, ClickHouseCrawlerRepository};
use btc_network_mmdb::{MmdbEnrichmentConfig, MmdbIpEnrichmentProvider};
use btc_network_observability::init_tracing;
use clap::{Args, Parser};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "crawler")]
struct Cli {
    #[command(flatten)]
    crawl: CrawlArgs,
}

/// Runtime knobs for a crawler run.
///
/// These options control concurrency, in-memory frontier limits, stop conditions,
/// and per-node network behavior. ClickHouse and MMDB settings are flattened in
/// below so the runnable app stays a thin adapter over the shared crawler config.
#[derive(Args, Debug)]
struct CrawlArgs {
    /// Maximum number of worker tasks processing nodes concurrently.
    #[arg(long, default_value_t = 1000, value_parser = parse_positive_usize)]
    max_concurrency: usize,

    /// Hard cap on unique endpoints tracked in-memory during a run.
    ///
    /// Once this limit is reached, newly discovered endpoints are ignored.
    #[arg(long, default_value_t = 100_000, value_parser = parse_positive_usize)]
    max_tracked_nodes: usize,

    /// Wall-clock limit for the full crawl before shutdown begins.
    #[arg(long, default_value_t = 60, value_parser = parse_positive_u64)]
    max_runtime_minutes: u64,

    /// Stop after this many minutes without queueing any newly discovered nodes.
    #[arg(long, default_value_t = 5, value_parser = parse_positive_u64)]
    idle_timeout_minutes: u64,

    /// Timeout for a single TCP connect attempt to a peer.
    #[arg(long, default_value_t = 30, value_parser = parse_positive_u64)]
    connect_timeout_secs: u64,

    /// Maximum number of TCP connect attempts per node, including the first try.
    ///
    /// Retries are only applied to connect failures, not later handshake or
    /// peer-discovery failures.
    #[arg(long, default_value_t = 3, value_parser = parse_positive_usize)]
    connect_max_attempts: usize,

    /// Base exponential backoff in milliseconds between failed connect attempts.
    ///
    /// With the default settings, retries wait 250ms, 500ms, 1000ms, and so on.
    #[arg(long, default_value_t = 250)]
    connect_retry_backoff_ms: u64,

    /// Timeout for read and write operations after a TCP connection is established.
    #[arg(long, default_value_t = 10, value_parser = parse_positive_u64)]
    io_timeout_secs: u64,

    /// Maximum number of seconds to wait for worker tasks to drain during shutdown.
    ///
    /// If the grace period expires, remaining worker tasks are aborted so the
    /// process can exit instead of hanging in the terminal.
    #[arg(long, default_value_t = 15, value_parser = parse_positive_u64)]
    shutdown_grace_period_secs: u64,

    /// Emit per-node timing and retry logs.
    #[arg(long, default_value_t = false)]
    verbose: bool,

    #[command(flatten)]
    clickhouse: ClickHouseArgs,

    #[command(flatten)]
    mmdb: MmdbArgs,
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

/// Optional local MMDB inputs for crawler IP enrichment.
///
/// Provide both paths together to persist ASN/country data, or omit both to run
/// without enrichment. This keeps ASN/country derivation in the enrichment
/// adapter rather than in protocol or app code. See BNDD-0001 for the local
/// MMDB dataset choice and BNDD-0005 for the enrichment-boundary decision.
#[derive(Args, Debug, Clone)]
struct MmdbArgs {
    /// Path to the local ASN MMDB, such as `GeoLite2-ASN.mmdb`.
    ///
    /// Must be set together with `--mmdb-country-path`.
    #[arg(long, env = "BTC_NETWORK_MMDB_ASN_PATH")]
    mmdb_asn_path: Option<PathBuf>,

    /// Path to the local country MMDB, such as `GeoLite2-Country.mmdb`.
    ///
    /// Must be set together with `--mmdb-asn-path`.
    #[arg(long, env = "BTC_NETWORK_MMDB_COUNTRY_PATH")]
    mmdb_country_path: Option<PathBuf>,
}

fn parse_positive_usize(raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("invalid positive integer: {raw}"))?;

    if value == 0 {
        return Err("value must be greater than zero".to_string());
    }

    Ok(value)
}

fn parse_positive_u64(raw: &str) -> Result<u64, String> {
    let value = raw
        .parse::<u64>()
        .map_err(|_| format!("invalid positive integer: {raw}"))?;

    if value == 0 {
        return Err("value must be greater than zero".to_string());
    }

    Ok(value)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();
    let cli = Cli::parse();
    run_crawler(cli.crawl).await
}

async fn run_crawler(args: CrawlArgs) -> Result<(), Box<dyn Error>> {
    let config = build_crawler_config(&args);
    let clickhouse_config = build_clickhouse_config(&args.clickhouse);
    let repository = Arc::new(ClickHouseCrawlerRepository::new(&clickhouse_config));
    let enrichment_provider = build_enrichment_provider(&args.mmdb)?;
    let crawler = Crawler::with_adapters(config, repository, enrichment_provider);
    let summary = crawler.run().await?;

    info!("Crawler finished.");
    info!("scheduled tasks: {}", summary.scheduled_tasks);
    info!("successful handshakes: {}", summary.successful_handshakes);
    info!("failed tasks: {}", summary.failed_tasks);
    info!("total queued nodes: {}", summary.queued_nodes_total);
    info!("unique nodes discovered: {}", summary.unique_nodes);
    info!("node states captured: {}", summary.discovered_node_states);
    info!("elapsed: {:.2?}", summary.elapsed);

    Ok(())
}

fn build_crawler_config(args: &CrawlArgs) -> CrawlerConfig {
    CrawlerConfig {
        max_concurrency: args.max_concurrency,
        max_tracked_nodes: args.max_tracked_nodes,
        max_runtime: Duration::from_secs(args.max_runtime_minutes * 60),
        idle_timeout: Duration::from_secs(args.idle_timeout_minutes * 60),
        connect_timeout: Duration::from_secs(args.connect_timeout_secs),
        connect_max_attempts: args.connect_max_attempts,
        connect_retry_backoff: Duration::from_millis(args.connect_retry_backoff_ms),
        io_timeout: Duration::from_secs(args.io_timeout_secs),
        shutdown_grace_period: Duration::from_secs(args.shutdown_grace_period_secs),
        verbose: args.verbose,
        ..CrawlerConfig::default()
    }
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

fn build_enrichment_provider(
    args: &MmdbArgs,
) -> Result<Arc<dyn IpEnrichmentProvider>, Box<dyn Error>> {
    match (&args.mmdb_asn_path, &args.mmdb_country_path) {
        (Some(asn_path), Some(country_path)) => Ok(Arc::new(MmdbIpEnrichmentProvider::new(
            MmdbEnrichmentConfig::new(asn_path.clone(), country_path.clone()),
        )?)),
        (None, None) => {
            warn!(
                "MMDB enrichment is disabled; crawler observations will persist without ASN/country data."
            );
            Ok(Arc::new(MmdbIpEnrichmentProvider::unavailable()))
        }
        _ => Err("both --mmdb-asn-path and --mmdb-country-path must be set together".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn build_crawler_config_applies_max_tracked_nodes_override() {
        let args = CrawlArgs {
            max_concurrency: 1000,
            max_tracked_nodes: 250_000,
            max_runtime_minutes: 60,
            idle_timeout_minutes: 5,
            connect_timeout_secs: 30,
            connect_max_attempts: 4,
            connect_retry_backoff_ms: 500,
            io_timeout_secs: 10,
            shutdown_grace_period_secs: 20,
            verbose: false,
            clickhouse: ClickHouseArgs {
                clickhouse_url: "http://localhost:8123".to_string(),
                clickhouse_database: "btc_network".to_string(),
                clickhouse_user: None,
                clickhouse_password: None,
            },
            mmdb: MmdbArgs {
                mmdb_asn_path: None,
                mmdb_country_path: None,
            },
        };

        let config = build_crawler_config(&args);

        assert_eq!(config.max_tracked_nodes, 250_000);
        assert_eq!(config.connect_max_attempts, 4);
        assert_eq!(config.connect_retry_backoff, Duration::from_millis(500));
        assert_eq!(config.shutdown_grace_period, Duration::from_secs(20));
    }

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
    fn enrichment_provider_requires_both_mmdb_paths() {
        let args = MmdbArgs {
            mmdb_asn_path: Some(PathBuf::from("/var/lib/btc-network/GeoLite2-ASN.mmdb")),
            mmdb_country_path: None,
        };

        let error = match build_enrichment_provider(&args) {
            Ok(_) => panic!("partial config should fail"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "both --mmdb-asn-path and --mmdb-country-path must be set together"
        );
    }

    #[test]
    fn enrichment_provider_defaults_to_unavailable_when_paths_are_absent() {
        let args = MmdbArgs {
            mmdb_asn_path: None,
            mmdb_country_path: None,
        };

        let provider = build_enrichment_provider(&args).expect("provider");
        let endpoint = btc_network::crawler::CrawlEndpoint::new(
            "1.1.1.1",
            8333,
            btc_network::crawler::CrawlNetwork::Ipv4,
            Some("1.1.1.1".parse().expect("ip")),
        );

        assert_eq!(
            provider.enrich(&endpoint).status,
            btc_network::crawler::IpEnrichmentStatus::Unavailable
        );
    }

    #[test]
    fn crawl_args_reject_zero_max_concurrency() {
        let error = Cli::try_parse_from(["crawler", "--max-concurrency", "0"])
            .expect_err("zero worker count should fail");

        assert!(error.to_string().contains("--max-concurrency"));
    }

    #[test]
    fn crawl_args_reject_zero_connect_max_attempts() {
        let error = Cli::try_parse_from(["crawler", "--connect-max-attempts", "0"])
            .expect_err("zero connect attempts should fail");

        assert!(error.to_string().contains("--connect-max-attempts"));
    }
}
