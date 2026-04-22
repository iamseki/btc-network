use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn last_run_nodes_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_nodes/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/nodes?limit=25"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn last_run_nodes_rejects_limit_above_node_max() -> TestResult {
    let app = fixture_app("last_run_nodes/limit_too_high").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/nodes?limit=1001"))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}
