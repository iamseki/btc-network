use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn list_runs_returns_fixture_payload() -> TestResult {
    let app = fixture_app("historical_runs/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/historical/runs"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn list_runs_rejects_zero_limit() -> TestResult {
    let app = fixture_app("historical_runs/limit_zero").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/historical/runs?limit=0"))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn list_runs_rejects_limit_above_max() -> TestResult {
    let app = fixture_app("historical_runs/limit_too_high").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/historical/runs?limit=101"))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}
