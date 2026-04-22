use axum::http::StatusCode;
use tower::util::ServiceExt;

use crate::common::{StubAnalyticsReader, app, json_body, request, sample_last_run_node};

#[tokio::test]
async fn last_run_nodes_returns_table_rows_payload() {
    let app = app(StubAnalyticsReader {
        last_run_nodes: vec![sample_last_run_node()],
        ..StubAnalyticsReader::default()
    });

    let response = app
        .oneshot(request("/api/v1/network/last-run/nodes?limit=25"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let json = json_body(response).await;
    assert_eq!(json["rows"][0]["endpoint"], "1.1.1.7:8333");
    assert_eq!(json["rows"][0]["protocolVersion"], 70016);
    assert_eq!(json["rows"][0]["userAgent"], "/Satoshi:27.0.0/");
}

#[tokio::test]
async fn last_run_nodes_rejects_limit_above_node_max() {
    let app = app(StubAnalyticsReader::default());

    let response = app
        .oneshot(request("/api/v1/network/last-run/nodes?limit=1001"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
