use axum::http::{HeaderValue, StatusCode, header};
use btc_network_testkit::{json_body, request};
use tower::util::ServiceExt;

use crate::{TestResult, empty_app};

#[tokio::test]
async fn openapi_route_returns_generated_spec() -> TestResult {
    let app = empty_app("docs_openapi_integration").await?;
    let response = app.router.clone().oneshot(request("/api/openapi.json")).await?;

    assert_eq!(response.status(), StatusCode::OK);

    let json = json_body(response).await?;
    assert_eq!(json["openapi"], "3.1.0");
    assert_eq!(
        json["paths"]["/api/v1/network/historical/runs"]["get"]["tags"][0],
        "Network Analytics"
    );
    assert_eq!(json["info"]["version"], env!("CARGO_PKG_VERSION"));

    Ok(())
}

#[tokio::test]
async fn docs_config_route_returns_scalar_ui_config() -> TestResult {
    let app = empty_app("docs_config_integration").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/docs/config.json"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let json = json_body(response).await?;
    assert_eq!(json["title"], "btc-network API");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        json["description"],
        "Read-only Bitcoin network analytics API for historical run inspection, historical ASN concentration, last-run snapshot slices, protocol distributions, and verified node summaries. The OpenAPI specification is generated from the live Rust handlers so hosted Scalar docs, web-embedded API reference views, and downstream tooling stay aligned with the real contract."
    );
    assert_eq!(
        json["introduction"],
        "Start with historical runs to inspect previous network snapshots and outcomes, compare historical ASN concentration when needed, then drill into last-run analytics for transport mix, services, user agents, countries, and verified nodes."
    );
    assert_eq!(json["openapiUrl"], "/api/openapi.json");
    assert_eq!(json["scalarPath"], "/docs");

    Ok(())
}

#[tokio::test]
async fn scalar_docs_route_returns_html() -> TestResult {
    let app = empty_app("docs_scalar_integration").await?;
    let response = app.router.clone().oneshot(request("/docs")).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/html; charset=utf-8"))
    );

    Ok(())
}
