use axum::http::StatusCode;
use btc_network_testkit::{json_body, request};
use tower::util::ServiceExt;

use crate::{TestResult, fixture_app};

#[tokio::test]
async fn last_run_services_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_distributions/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/services?limit=10"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("services.expected.json")?
    );

    Ok(())
}

#[tokio::test]
async fn last_run_protocol_versions_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_distributions/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/last-run/protocol-versions?limit=10",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("protocol_versions.expected.json")?
    );

    Ok(())
}

#[tokio::test]
async fn last_run_user_agents_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_distributions/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/user-agents?limit=10"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("user_agents.expected.json")?
    );

    Ok(())
}

#[tokio::test]
async fn last_run_network_types_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_distributions/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/network-types?limit=10"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("network_types.expected.json")?
    );

    Ok(())
}

#[tokio::test]
async fn last_run_countries_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_distributions/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/countries?limit=10"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("countries.expected.json")?
    );

    Ok(())
}

#[tokio::test]
async fn last_run_start_heights_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_distributions/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request("/api/v1/network/last-run/start-heights?limit=10"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("start_heights.expected.json")?
    );

    Ok(())
}

#[tokio::test]
async fn last_run_asn_organizations_returns_fixture_payload() -> TestResult {
    let app = fixture_app("last_run_distributions/basic").await?;
    let response = app
        .router
        .clone()
        .oneshot(request(
            "/api/v1/network/last-run/asn-organizations?limit=10",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await?,
        app.expected_json("asn_organizations.expected.json")?
    );

    Ok(())
}
