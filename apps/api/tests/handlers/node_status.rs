use std::sync::Arc;

use axum::http::StatusCode;
use btc_network::crawler::{CrawlerAnalyticsReader, CrawlerRepository};
use btc_network::status::{NodeStatus, NodeStatusRecord, NodeStatusTarget};
use btc_network_api::build_router;
use btc_network_postgres::PostgresCrawlerRepository;
use btc_network_testkit::{ScenarioDatabase, json_body, request};
use chrono::{Duration, Utc};
use tower::util::ServiceExt;

use crate::TestResult;

#[tokio::test]
async fn node_status_returns_empty_array_without_rows() -> TestResult {
    let database = ScenarioDatabase::create("node_status_empty").await?;
    let router = build_router(Arc::new(PostgresCrawlerRepository::new(database.config())?));
    let response = router.oneshot(request("/api/nodes/status")).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, serde_json::json!([]));

    Ok(())
}

#[tokio::test]
async fn node_status_returns_latest_rows_with_history() -> TestResult {
    let database = ScenarioDatabase::create("node_status_populated").await?;
    let repository = Arc::new(PostgresCrawlerRepository::new(database.config())?);
    let target = NodeStatusTarget::new(
        "seed.bitcoin.sipa.be:8333",
        "Sipa DNS Seed",
        "Long-running Bitcoin Core mainnet DNS seed.",
    )?;
    let older = NodeStatusRecord::from_target(
        &target,
        NodeStatus::Failed,
        Utc::now() - Duration::seconds(30),
        "Status check failed after 5 attempts: connect failed",
    );
    let latest = NodeStatusRecord::from_target(
        &target,
        NodeStatus::Healthy,
        Utc::now(),
        "Handshake succeeded.",
    );

    repository.insert_node_status(older).await?;
    repository.insert_node_status(latest).await?;

    let reader: Arc<dyn CrawlerAnalyticsReader> = repository.clone();
    let router = build_router(reader);
    let response = router.oneshot(request("/api/nodes/status")).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await?;
    assert_eq!(json[0]["endpoint"], "seed.bitcoin.sipa.be:8333");
    assert_eq!(json[0]["status"], "healthy");
    assert_eq!(json[0]["history"][0]["status"], "healthy");
    assert_eq!(json[0]["history"][1]["status"], "failed");

    Ok(())
}
