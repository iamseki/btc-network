use axum::http::StatusCode;
use tower::util::ServiceExt;

use crate::common::{StubAnalyticsReader, app, request, sample_run};

#[tokio::test]
async fn list_runs_returns_json_payload() {
    let app = app(StubAnalyticsReader {
        runs: vec![sample_run()],
        ..StubAnalyticsReader::default()
    });

    let response = app
        .oneshot(request("/api/v1/network/historical/runs"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_runs_rejects_zero_limit() {
    let app = app(StubAnalyticsReader::default());

    let response = app
        .oneshot(request("/api/v1/network/historical/runs?limit=0"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_runs_rejects_limit_above_max() {
    let app = app(StubAnalyticsReader::default());

    let response = app
        .oneshot(request("/api/v1/network/historical/runs?limit=101"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
