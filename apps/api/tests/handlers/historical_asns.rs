use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn historical_asns_returns_fixture_payload() -> TestResult {
    let app = fixture_app("historical_asns/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/historical/asns?start=2026-04-01T00:00:00Z&end=2026-04-04T00:00:00Z",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn historical_asns_requires_start() -> TestResult {
    let app = fixture_app("historical_asns/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/historical/asns?end=2026-04-04T00:00:00Z",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        serde_json::json!({
            "error": {
                "code": "bad_request",
                "message": "start is required"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn historical_asns_rejects_invalid_window_order() -> TestResult {
    let app = fixture_app("historical_asns/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/historical/asns?start=2026-04-04T00:00:00Z&end=2026-04-01T00:00:00Z",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        serde_json::json!({
            "error": {
                "code": "bad_request",
                "message": "start must be before end"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn historical_asns_rejects_too_large_window() -> TestResult {
    let app = fixture_app("historical_asns/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/historical/asns?start=2026-04-01T00:00:00Z&end=2026-05-03T00:00:00Z",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        serde_json::json!({
            "error": {
                "code": "bad_request",
                "message": "time window must be less than or equal to 31 days"
            }
        })
    );

    Ok(())
}
