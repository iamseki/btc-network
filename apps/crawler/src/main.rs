use btc_network::crawler::{Crawler, CrawlerConfig};
use btc_network_observability::init_tracing;
use clap::Parser;
use std::error::Error;
use std::time::Duration;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "crawler")]
struct Cli {
    #[arg(long, default_value_t = 1000)]
    max_concurrency: usize,

    #[arg(long, default_value_t = 60)]
    max_runtime_minutes: u64,

    #[arg(long, default_value_t = 5)]
    idle_timeout_minutes: u64,

    #[arg(long, default_value_t = 30)]
    connect_timeout_secs: u64,

    #[arg(long, default_value_t = 10)]
    io_timeout_secs: u64,

    #[arg(long, default_value_t = false)]
    verbose: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();
    let cli = Cli::parse();
    let config = CrawlerConfig {
        max_concurrency: cli.max_concurrency,
        max_runtime: Duration::from_secs(cli.max_runtime_minutes * 60),
        idle_timeout: Duration::from_secs(cli.idle_timeout_minutes * 60),
        connect_timeout: Duration::from_secs(cli.connect_timeout_secs),
        io_timeout: Duration::from_secs(cli.io_timeout_secs),
        verbose: cli.verbose,
        ..CrawlerConfig::default()
    };

    let crawler = Crawler::new(config);
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
