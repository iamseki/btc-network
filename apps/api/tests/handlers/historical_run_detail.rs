use axum::http::StatusCode;
use tower::util::ServiceExt;

use crate::common::{StubAnalyticsReader, app, request, sample_detail};

#[tokio::test]
async fn get_run_returns_not_found_when_missing() {
    let app = app(StubAnalyticsReader::default());

    let response = app
        .oneshot(request(
            "/api/v1/network/historical/runs/00000000-0000-0000-0000-000000000099",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_run_returns_detail_payload() {
    let app = app(StubAnalyticsReader {
        detail: Some(sample_detail()),
        ..StubAnalyticsReader::default()
    });

    let response = app
        .oneshot(request(
            "/api/v1/network/historical/runs/00000000-0000-0000-0000-000000000001",
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_run_rejects_invalid_uuid() {
    let app = app(StubAnalyticsReader::default());

    let response = app
        .oneshot(request("/api/v1/network/historical/runs/not-a-uuid"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
