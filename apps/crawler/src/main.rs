use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use btc_network::crawler::{Crawler, CrawlerConfig, IpEnrichmentProvider};
use btc_network_mmdb::{MmdbEnrichmentConfig, MmdbIpEnrichmentProvider};
use btc_network_observability::init_tracing;
use btc_network_postgres::{PostgresConnectionConfig, PostgresCrawlerRepository};
use clap::{Args, Parser, Subcommand};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "crawler")]
struct Cli {
    #[command(subcommand)]
    command: Option<CrawlerCommand>,

    #[command(flatten)]
    crawl: CrawlArgs,
}

#[derive(Subcommand, Debug)]
enum CrawlerCommand {
    /// Run a normal DNS-seeded crawl.
    Crawl(CrawlArgs),
    /// Retry active unreachable-node rows and mark recovered peers.
    RecoverUnreachable(CrawlArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Crawl,
    RecoverUnreachable,
}

/// Runtime knobs for a crawler run.
///
/// These options control concurrency, in-memory frontier limits, stop conditions,
/// and per-node network behavior. PostgreSQL and MMDB settings are flattened in
/// below so the runnable app stays a thin adapter over the shared crawler config.
#[derive(Args, Debug)]
struct CrawlArgs {
    /// Maximum number of worker tasks processing nodes concurrently.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_MAX_CONCURRENCY",
        default_value_t = 1000,
        value_parser = parse_positive_usize
    )]
    max_concurrency: usize,

    /// Maximum number of endpoints allowed to be in the TCP connect phase at once.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_MAX_IN_FLIGHT_CONNECTS",
        default_value_t = 256,
        value_parser = parse_positive_usize
    )]
    max_in_flight_connects: usize,

    /// Hard cap on unique endpoints tracked in-memory during a run.
    ///
    /// Once this limit is reached, newly discovered endpoints are ignored.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_MAX_TRACKED_NODES",
        default_value_t = 100_000,
        value_parser = parse_positive_usize
    )]
    max_tracked_nodes: usize,

    /// Wall-clock limit for the full crawl before shutdown begins.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_MAX_RUNTIME_MINUTES",
        default_value_t = 60,
        value_parser = parse_positive_u64
    )]
    max_runtime_minutes: u64,

    /// Stop after this many minutes without queueing any newly discovered nodes.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_IDLE_TIMEOUT_MINUTES",
        default_value_t = 5,
        value_parser = parse_positive_u64
    )]
    idle_timeout_minutes: u64,

    /// Seconds between periodic durable progress checkpoints.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_CHECKPOINT_INTERVAL_SECS",
        default_value_t = 30,
        value_parser = parse_positive_u64
    )]
    checkpoint_interval_secs: u64,

    /// Timeout for a single TCP connect attempt to a peer.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_CONNECT_TIMEOUT_SECS",
        default_value_t = 30,
        value_parser = parse_positive_u64
    )]
    connect_timeout_secs: u64,

    /// Maximum number of TCP connect attempts per node, including the first try.
    ///
    /// Retries apply to any failed reachable endpoint. This is the total
    /// per-endpoint attempt budget.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_CONNECT_MAX_ATTEMPTS",
        default_value_t = 5,
        value_parser = parse_positive_usize
    )]
    connect_max_attempts: usize,

    /// Days of active unreachable-node state to load at startup.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_UNREACHABLE_LOOKBACK_DAYS",
        default_value_t = 7,
        value_parser = parse_positive_u64
    )]
    unreachable_lookback_days: u64,

    /// Base exponential backoff in milliseconds between failed connect attempts.
    ///
    /// With the default settings, retries wait 250ms, 500ms, 1000ms, and so on.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_CONNECT_RETRY_BACKOFF_MS",
        default_value_t = 250
    )]
    connect_retry_backoff_ms: u64,

    /// Timeout for read and write operations after a TCP connection is established.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_IO_TIMEOUT_SECS",
        default_value_t = 10,
        value_parser = parse_positive_u64
    )]
    io_timeout_secs: u64,

    /// Optional SOCKS5 proxy target used for onion reachability, such as `127.0.0.1:9050` or `tor:9050`.
    #[arg(long, env = "BTC_NETWORK_CRAWLER_TOR_SOCKS5_ADDR")]
    tor_socks5_addr: Option<String>,

    /// Maximum number of seconds to wait for worker tasks to drain during shutdown.
    ///
    /// If the grace period expires, remaining worker tasks are aborted so the
    /// process can exit instead of hanging in the terminal.
    #[arg(
        long,
        env = "BTC_NETWORK_CRAWLER_SHUTDOWN_GRACE_PERIOD_SECS",
        default_value_t = 15,
        value_parser = parse_positive_u64
    )]
    shutdown_grace_period_secs: u64,

    /// Emit per-node timing and retry logs.
    #[arg(long, env = "BTC_NETWORK_CRAWLER_VERBOSE", default_value_t = false)]
    verbose: bool,

    #[command(flatten)]
    postgres: PostgresArgs,

    #[command(flatten)]
    mmdb: MmdbArgs,
}

#[derive(Args, Debug, Clone)]
struct PostgresArgs {
    #[arg(
        long,
        env = "BTC_NETWORK_POSTGRES_URL",
        default_value = "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network"
    )]
    postgres_url: String,

    #[arg(
        long,
        env = "BTC_NETWORK_POSTGRES_MAX_CONNECTIONS",
        default_value_t = 16,
        value_parser = parse_positive_usize
    )]
    postgres_max_connections: usize,
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
    let (mode, args) = cli.into_run_request();
    run_crawler(args, mode).await
}

impl Cli {
    fn into_run_request(self) -> (RunMode, CrawlArgs) {
        match self.command {
            Some(CrawlerCommand::Crawl(args)) => (RunMode::Crawl, args),
            Some(CrawlerCommand::RecoverUnreachable(args)) => (RunMode::RecoverUnreachable, args),
            None => (RunMode::Crawl, self.crawl),
        }
    }
}

async fn run_crawler(args: CrawlArgs, mode: RunMode) -> Result<(), Box<dyn Error>> {
    let config = build_crawler_config(&args, mode);
    let postgres_config = build_postgres_config(&args.postgres);
    let repository = Arc::new(PostgresCrawlerRepository::new(&postgres_config)?);
    let enrichment_provider = build_enrichment_provider(&args.mmdb)?;
    let crawler = Crawler::with_adapters(config, repository, enrichment_provider);
    let summary = match mode {
        RunMode::Crawl => crawler.run().await?,
        RunMode::RecoverUnreachable => crawler.run_unreachable_recovery().await?,
    };

    match mode {
        RunMode::Crawl => info!("Crawler finished."),
        RunMode::RecoverUnreachable => info!("Unreachable recovery finished."),
    }
    info!("scheduled tasks: {}", summary.scheduled_tasks);
    info!("successful handshakes: {}", summary.successful_handshakes);
    info!("failed tasks: {}", summary.failed_tasks);
    info!("unique nodes discovered: {}", summary.unique_nodes);
    info!("elapsed: {:.2?}", summary.elapsed);

    Ok(())
}

fn build_crawler_config(args: &CrawlArgs, mode: RunMode) -> CrawlerConfig {
    CrawlerConfig {
        max_concurrency: args.max_concurrency,
        max_in_flight_connects: args.max_in_flight_connects,
        max_tracked_nodes: args.max_tracked_nodes,
        max_runtime: Duration::from_secs(args.max_runtime_minutes * 60),
        idle_timeout: Duration::from_secs(args.idle_timeout_minutes * 60),
        checkpoint_interval: Duration::from_secs(args.checkpoint_interval_secs),
        connect_timeout: Duration::from_secs(args.connect_timeout_secs),
        connect_max_attempts: args.connect_max_attempts,
        unreachable_nodes_lookback: Duration::from_secs(
            args.unreachable_lookback_days * 24 * 60 * 60,
        ),
        follow_discovered_nodes: mode == RunMode::Crawl,
        connect_retry_backoff: Duration::from_millis(args.connect_retry_backoff_ms),
        io_timeout: Duration::from_secs(args.io_timeout_secs),
        tor_socks5_addr: args.tor_socks5_addr.clone(),
        shutdown_grace_period: Duration::from_secs(args.shutdown_grace_period_secs),
        verbose: args.verbose,
        ..CrawlerConfig::default()
    }
}

fn build_postgres_config(args: &PostgresArgs) -> PostgresConnectionConfig {
    PostgresConnectionConfig::new(args.postgres_url.clone())
        .with_max_connections(args.postgres_max_connections)
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
            max_in_flight_connects: 256,
            max_tracked_nodes: 250_000,
            max_runtime_minutes: 60,
            idle_timeout_minutes: 5,
            checkpoint_interval_secs: 30,
            connect_timeout_secs: 30,
            connect_max_attempts: 4,
            unreachable_lookback_days: 14,
            connect_retry_backoff_ms: 500,
            io_timeout_secs: 10,
            tor_socks5_addr: Some("tor:9050".to_string()),
            shutdown_grace_period_secs: 20,
            verbose: false,
            postgres: PostgresArgs {
                postgres_url:
                    "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network"
                        .to_string(),
                postgres_max_connections: 16,
            },
            mmdb: MmdbArgs {
                mmdb_asn_path: None,
                mmdb_country_path: None,
            },
        };

        let config = build_crawler_config(&args, RunMode::Crawl);

        assert_eq!(config.max_in_flight_connects, 256);
        assert_eq!(config.max_tracked_nodes, 250_000);
        assert_eq!(config.connect_max_attempts, 4);
        assert_eq!(
            config.unreachable_nodes_lookback,
            Duration::from_secs(14 * 24 * 60 * 60)
        );
        assert!(config.follow_discovered_nodes);
        assert_eq!(config.connect_retry_backoff, Duration::from_millis(500));
        assert_eq!(config.tor_socks5_addr.as_deref(), Some("tor:9050"));
        assert_eq!(config.shutdown_grace_period, Duration::from_secs(20));
    }

    #[test]
    fn build_crawler_config_disables_discovered_fanout_for_recovery() {
        let args = test_crawl_args();

        let config = build_crawler_config(&args, RunMode::RecoverUnreachable);

        assert!(!config.follow_discovered_nodes);
    }

    #[test]
    fn cli_defaults_to_normal_crawl_without_subcommand() {
        let cli = Cli::parse_from(["crawler", "--connect-max-attempts", "4"]);

        let (mode, args) = cli.into_run_request();

        assert_eq!(mode, RunMode::Crawl);
        assert_eq!(args.connect_max_attempts, 4);
    }

    #[test]
    fn cli_accepts_explicit_recovery_subcommand() {
        let cli = Cli::parse_from([
            "crawler",
            "recover-unreachable",
            "--connect-max-attempts",
            "2",
        ]);

        let (mode, args) = cli.into_run_request();

        assert_eq!(mode, RunMode::RecoverUnreachable);
        assert_eq!(args.connect_max_attempts, 2);
    }

    fn test_crawl_args() -> CrawlArgs {
        CrawlArgs {
            max_concurrency: 1000,
            max_in_flight_connects: 256,
            max_tracked_nodes: 250_000,
            max_runtime_minutes: 60,
            idle_timeout_minutes: 5,
            checkpoint_interval_secs: 30,
            connect_timeout_secs: 30,
            connect_max_attempts: 4,
            unreachable_lookback_days: 14,
            connect_retry_backoff_ms: 500,
            io_timeout_secs: 10,
            tor_socks5_addr: Some("tor:9050".to_string()),
            shutdown_grace_period_secs: 20,
            verbose: false,
            postgres: PostgresArgs {
                postgres_url:
                    "postgresql://btc_network_dev:btc_network_dev@localhost:5432/btc_network"
                        .to_string(),
                postgres_max_connections: 16,
            },
            mmdb: MmdbArgs {
                mmdb_asn_path: None,
                mmdb_country_path: None,
            },
        }
    }

    #[test]
    fn postgres_config_applies_connection_pool_override() {
        let args = PostgresArgs {
            postgres_url: "postgresql://crawler_writer:secret@postgres.internal:5432/btc_network"
                .to_string(),
            postgres_max_connections: 32,
        };

        let config = build_postgres_config(&args);

        assert_eq!(
            config.url(),
            "postgresql://crawler_writer:secret@postgres.internal:5432/btc_network"
        );
        assert_eq!(config.max_connections(), 32);
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
    fn crawl_args_reject_zero_max_in_flight_connects() {
        let error = Cli::try_parse_from(["crawler", "--max-in-flight-connects", "0"])
            .expect_err("zero connect budget should fail");

        assert!(error.to_string().contains("--max-in-flight-connects"));
    }

    #[test]
    fn crawl_args_reject_zero_connect_max_attempts() {
        let error = Cli::try_parse_from(["crawler", "--connect-max-attempts", "0"])
            .expect_err("zero connect attempts should fail");

        assert!(error.to_string().contains("--connect-max-attempts"));
    }
}
