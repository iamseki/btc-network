use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn last_run_asns_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_asns/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/asns?limit=10"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}
