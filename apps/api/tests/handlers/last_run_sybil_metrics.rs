use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use serde_json::json;
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn last_run_sybil_metrics_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_sybil_metrics/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/sybil-metrics"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn last_run_sybil_metrics_phase_any_uses_newest_matching_run() -> TestResult {
    let app = fixture_app("last_run_sybil_metrics/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/sybil-metrics?phase=any"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("phase_any.expected.json")?
    );

    Ok(())
}

#[tokio::test]
async fn last_run_sybil_metrics_rejects_unknown_phase_filter() -> TestResult {
    let app = fixture_app("last_run_sybil_metrics/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/last-run/sybil-metrics?phase=unknown",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[tokio::test]
async fn last_run_sybil_metrics_rejects_limit_parameter() -> TestResult {
    let app = fixture_app("last_run_sybil_metrics/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/sybil-metrics?limit=1"))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({
            "error": {
                "code": "bad_request",
                "message": "limit is not supported for sybil metrics"
            }
        })
    );

    Ok(())
}
