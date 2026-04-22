use axum::http::StatusCode;
use tower::util::ServiceExt;

use crate::common::{StubAnalyticsReader, app, json_body, request, sample_last_run_asn};

#[tokio::test]
async fn last_run_asns_returns_rows_payload() {
    let app = app(StubAnalyticsReader {
        last_run_asns: vec![sample_last_run_asn()],
        ..StubAnalyticsReader::default()
    });

    let response = app
        .oneshot(request("/api/v1/network/last-run/asns?limit=10"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let json = json_body(response).await;
    assert_eq!(json["rows"][0]["asn"], 64512);
    assert_eq!(json["rows"][0]["asnOrganization"], "Example ASN");
    assert_eq!(json["rows"][0]["nodeCount"], 4);
}
