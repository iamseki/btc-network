use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use serde_json::{Value, json};
use tower::util::ServiceExt;

use crate::{TestResult, empty_app};

const DEFAULT_MAX_ENDPOINTS: &[&str] = &[
    "/api/v1/network/historical/runs",
    "/api/v1/network/historical/asns",
    "/api/v1/network/last-run/services",
    "/api/v1/network/last-run/protocol-versions",
    "/api/v1/network/last-run/user-agents",
    "/api/v1/network/last-run/network-types",
    "/api/v1/network/last-run/countries",
    "/api/v1/network/last-run/asns",
    "/api/v1/network/last-run/start-heights",
    "/api/v1/network/last-run/asn-organizations",
];

fn bad_request(message: &str) -> Value {
    json!({
        "error": {
            "code": "bad_request",
            "message": message
        }
    })
}

#[tokio::test]
async fn bounded_list_endpoints_reject_zero_limit() -> TestResult {
    let app = empty_app("limit_guardrails/zero").await?;

    for path in DEFAULT_MAX_ENDPOINTS
        .iter()
        .chain(["/api/v1/network/last-run/nodes"].iter())
    {
        let response = app
            .router
            .clone()
            .oneshot(request(&format!("{path}?limit=0")))
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            json_body(response).await?,
            bad_request("limit must be greater than zero"),
            "{path}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn standard_bounded_list_endpoints_reject_limit_above_100() -> TestResult {
    let app = empty_app("limit_guardrails/above_standard_max").await?;

    for path in DEFAULT_MAX_ENDPOINTS {
        let response = app
            .router
            .clone()
            .oneshot(request(&format!("{path}?limit=101")))
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            json_body(response).await?,
            bad_request("limit must be less than or equal to 100"),
            "{path}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn last_run_nodes_keeps_separate_1000_row_cap() -> TestResult {
    let app = empty_app("limit_guardrails/last_run_nodes_max").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/nodes?limit=1001"))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        bad_request("limit must be less than or equal to 1000")
    );

    Ok(())
}
