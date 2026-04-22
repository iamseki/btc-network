use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn get_run_returns_fixture_payload() -> TestResult {
    let app = fixture_app("historical_run_detail/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/historical/runs/00000000-0000-0000-0000-000000000101",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn get_run_returns_not_found_when_missing() -> TestResult {
    let app = fixture_app("historical_run_detail/not_found").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/historical/runs/00000000-0000-0000-0000-000000000199",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn get_run_rejects_invalid_uuid() -> TestResult {
    let app = fixture_app("historical_run_detail/invalid_uuid").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/historical/runs/not-a-uuid"))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}
