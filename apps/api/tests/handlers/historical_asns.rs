use axum::http::StatusCode;
use btc_network::crawler::CrawlerRepositoryError;
use tower::util::ServiceExt;

use crate::common::{StubAnalyticsReader, app, json_body, request};

#[tokio::test]
async fn historical_asns_returns_internal_error_without_leaking_adapter_message() {
    let app = app(StubAnalyticsReader {
        fail_with: Some(CrawlerRepositoryError::new("raw postgres detail")),
        ..StubAnalyticsReader::default()
    });

    let response = app
        .oneshot(request("/api/v1/network/historical/asns"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let json = json_body(response).await;
    assert_eq!(json["error"]["code"], "internal_error");
    assert_eq!(json["error"]["message"], "network analytics backend failed");
}
