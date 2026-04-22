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
        crate::handlers::last_run::nodes::list_last_run_nodes_docs
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

    use axum::body::Body;
    use axum::http::{HeaderValue, Request, StatusCode, header};
    use btc_network::crawler::{
        AsnNodeCountItem, CrawlRunDetail, CrawlRunId, CrawlRunListItem, CrawlerAnalyticsReader,
        CrawlerRepositoryError, LastRunAsnCountItem, LastRunAsnOrganizationCountItem,
        LastRunCountryCountItem, LastRunNetworkTypeCountItem, LastRunNodeSummaryItem,
        LastRunProtocolVersionCountItem, LastRunServicesCountItem, LastRunStartHeightCountItem,
        LastRunUserAgentCountItem, RepositoryFuture,
    };
    use tower::util::ServiceExt;

    use super::{DOCS_CONFIG_PATH, OPENAPI_PATH, SCALAR_PATH};
    use crate::build_router;

    #[derive(Default)]
    struct EmptyReader;

    impl CrawlerAnalyticsReader for EmptyReader {
        fn list_crawl_runs<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunListItem>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn get_crawl_run<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
            _checkpoint_limit: usize,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunDetail>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(None) })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_services<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_protocol_versions<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<
            'a,
            Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_user_agents<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_network_types<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_countries<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_asns<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_start_heights<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_asn_organizations<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<
            'a,
            Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError>,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_last_run_nodes<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunNodeSummaryItem>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn request(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn openapi_route_returns_generated_spec() {
        let app = build_router(Arc::new(EmptyReader));

        let response = app.oneshot(request(OPENAPI_PATH)).await.expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["openapi"], "3.1.0");
        assert_eq!(
            json["paths"]["/api/v1/network/historical/runs"]["get"]["tags"][0],
            "Network Analytics"
        );
        assert_eq!(json["info"]["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn scalar_docs_route_returns_html() {
        let app = build_router(Arc::new(EmptyReader));

        let response = app.oneshot(request(SCALAR_PATH)).await.expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/html; charset=utf-8"))
        );
    }

    #[tokio::test]
    async fn docs_config_route_returns_scalar_ui_config() {
        let app = build_router(Arc::new(EmptyReader));

        let response = app
            .oneshot(request(DOCS_CONFIG_PATH))
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
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
    }
}
