use std::sync::Arc;

use btc_network::crawler::CrawlerAnalyticsReader;
use btc_network_api::{
    DocsConfig, build_router_with_config, parse_bind_addr, parse_postgres_config,
    parse_runtime_config,
};
use btc_network_observability::init_tracing;
use btc_network_postgres::PostgresCrawlerRepository;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let bind_addr = parse_bind_addr()?;
    let postgres_config = parse_postgres_config()?;
    let runtime_config = parse_runtime_config()?;
    let docs_config = DocsConfig::from_env()?;
    let analytics_reader: Arc<dyn CrawlerAnalyticsReader> =
        Arc::new(PostgresCrawlerRepository::new(&postgres_config)?);
    let app = build_router_with_config(analytics_reader, runtime_config, docs_config);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!(%bind_addr, "[api] listening for network analytics requests");
    axum::serve(listener, app).await?;
    Ok(())
}
