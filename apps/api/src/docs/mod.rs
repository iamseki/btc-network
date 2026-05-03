mod config;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use btc_network::crawler::{
    AsnNodeCountItem, CrawlRunDetail, LastRunAsnCountItem, LastRunAsnOrganizationCountItem,
    LastRunCountryCountItem, LastRunNetworkTypeCountItem, LastRunNodeSummaryItem,
    LastRunProtocolVersionCountItem, LastRunServicesCountItem, LastRunStartHeightCountItem,
    LastRunUserAgentCountItem,
};
use btc_network::status::{NodeStatusHistoryItem, NodeStatusItem};
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::{Modify, OpenApi};
use utoipa_scalar::{Scalar, Servable};

use crate::handlers::{CrawlRunsResponse, ErrorResponse, RowsResponse};
use crate::routes::AppState;

pub use config::DocsConfig;
pub(crate) use config::{DOCS_CONFIG_PATH, DocsUiConfigResponse, OPENAPI_PATH, SCALAR_PATH};

pub(super) fn router(docs_config: DocsConfig) -> Router<AppState> {
    let openapi = openapi_document(&docs_config);

    Router::new()
        .route(OPENAPI_PATH, get(openapi_spec))
        .route(DOCS_CONFIG_PATH, get(docs_ui_config))
        .merge(Scalar::with_url(SCALAR_PATH, openapi))
}

async fn openapi_spec(State(state): State<AppState>) -> Json<OpenApiDocument> {
    Json(openapi_document(&state.docs_config))
}

async fn docs_ui_config(State(state): State<AppState>) -> Json<DocsUiConfigResponse> {
    Json(state.docs_config.scalar_ui_config())
}

pub fn openapi_document(docs_config: &DocsConfig) -> OpenApiDocument {
    let mut openapi = ApiDoc::openapi();
    docs_config.modify(&mut openapi);
    openapi
}

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::historical::runs::list::list_crawl_runs_docs,
        crate::handlers::historical::runs::detail::get_crawl_run_docs,
        crate::handlers::historical::asns::count_nodes_by_asn_docs,
        crate::handlers::last_run::services::list_last_run_services_docs,
        crate::handlers::last_run::protocol_versions::list_last_run_protocol_versions_docs,
        crate::handlers::last_run::user_agents::list_last_run_user_agents_docs,
        crate::handlers::last_run::network_types::list_last_run_network_types_docs,
        crate::handlers::last_run::countries::list_last_run_countries_docs,
        crate::handlers::last_run::asns::list_last_run_asns_docs,
        crate::handlers::last_run::start_heights::list_last_run_start_heights_docs,
        crate::handlers::last_run::asn_organizations::list_last_run_asn_organizations_docs,
        crate::handlers::last_run::nodes::list_last_run_nodes_docs,
        crate::handlers::node_status::list_node_status_docs
    ),
    components(
        schemas(
            CrawlRunsResponse,
            CrawlRunDetail,
            RowsResponse<AsnNodeCountItem>,
            RowsResponse<LastRunServicesCountItem>,
            RowsResponse<LastRunProtocolVersionCountItem>,
            RowsResponse<LastRunUserAgentCountItem>,
            RowsResponse<LastRunNetworkTypeCountItem>,
            RowsResponse<LastRunCountryCountItem>,
            RowsResponse<LastRunAsnCountItem>,
            RowsResponse<LastRunStartHeightCountItem>,
            RowsResponse<LastRunAsnOrganizationCountItem>,
            RowsResponse<LastRunNodeSummaryItem>,
            NodeStatusItem,
            NodeStatusHistoryItem,
            ErrorResponse
        )
    ),
    tags(
        (name = "Network Analytics", description = "Read-only network analytics endpoints.")
    )
)]
struct ApiDoc;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{HeaderValue, StatusCode, header};
    use btc_network_postgres::PostgresCrawlerRepository;
    use btc_network_testkit::{FixtureRouterApp, TestkitResult, json_body, request};
    use tower::util::ServiceExt;

    use super::*;
    use crate::build_router;

    fn build_api_router(database: &btc_network_testkit::ScenarioDatabase) -> TestkitResult<Router> {
        Ok(build_router(Arc::new(PostgresCrawlerRepository::new(
            database.config(),
        )?)))
    }

    #[tokio::test]
    async fn openapi_route_returns_generated_spec() -> TestkitResult {
        let app = FixtureRouterApp::empty("docs_openapi", build_api_router).await?;
        let response = app.router.clone().oneshot(request(OPENAPI_PATH)).await?;

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
    async fn docs_config_route_returns_scalar_ui_config() -> TestkitResult {
        let app = FixtureRouterApp::empty("docs_config", build_api_router).await?;
        let response = app
            .router
            .clone()
            .oneshot(request(DOCS_CONFIG_PATH))
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
        assert_eq!(json["openapiUrl"], OPENAPI_PATH);
        assert_eq!(json["scalarPath"], SCALAR_PATH);

        Ok(())
    }

    #[tokio::test]
    async fn scalar_docs_route_returns_html() -> TestkitResult {
        let app = FixtureRouterApp::empty("docs_scalar", build_api_router).await?;
        let response = app.router.clone().oneshot(request(SCALAR_PATH)).await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/html; charset=utf-8"))
        );

        Ok(())
    }
}
