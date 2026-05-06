use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use serde_json::json;
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn last_run_nodes_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_nodes/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/nodes?limit=25"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}

#[tokio::test]
async fn last_run_nodes_returns_next_page_token() -> TestResult {
    let app = fixture_app("last_run_nodes/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/nodes?limit=2"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["items"].as_array().map(Vec::len), Some(2));
    assert!(body["nextPageToken"].as_str().is_some());

    Ok(())
}

#[tokio::test]
async fn last_run_nodes_uses_next_page_token() -> TestResult {
    let app = fixture_app("last_run_nodes/basic").await?;
    let first_response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/nodes?limit=2"))
        .await?;
    let first_body = json_body(first_response).await?;
    let token = first_body["nextPageToken"]
        .as_str()
        .expect("next page token");

    let second_response = app
        .router
        .clone()
        .oneshot(request(&format!(
            "/api/v1/network/last-run/nodes?limit=2&pageToken={token}"
        )))
        .await?;

    assert_eq!(second_response.status(), StatusCode::OK);
    assert_eq!(
        json_body(second_response).await?,
        json!({
            "items": [
                {
                    "endpoint": "2.2.2.1:8333",
                    "networkType": "ipv4",
                    "protocolVersion": 70016,
                    "userAgent": "/Satoshi:27.0.0/",
                    "services": "01",
                    "startHeight": 900000,
                    "country": "US",
                    "asn": 64512,
                    "asnOrganization": "Example ASN"
                }
            ],
            "nextPageToken": null
        })
    );

    Ok(())
}

#[tokio::test]
async fn last_run_nodes_rejects_invalid_page_token() -> TestResult {
    let app = fixture_app("last_run_nodes/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/last-run/nodes?pageToken=not-a-token",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({
            "error": {
                "code": "bad_request",
                "message": "pageToken is invalid"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn last_run_nodes_rejects_wrong_endpoint_page_token() -> TestResult {
    let app = fixture_app("last_run_nodes/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/last-run/nodes?pageToken=historical-asns-v1:0:00:1",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await?,
        json!({
            "error": {
                "code": "bad_request",
                "message": "pageToken is invalid"
            }
        })
    );

    Ok(())
}

#[tokio::test]
async fn last_run_nodes_rejects_limit_above_node_max() -> TestResult {
    let app = fixture_app("last_run_nodes/limit_too_high").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/nodes?limit=1001"))
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await?, app.expected_result()?);

    Ok(())
}
