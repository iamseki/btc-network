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

use super::{AppState, CrawlRunsResponse, ErrorResponse, RowsResponse};

pub(crate) use config::{
    DOCS_CONFIG_PATH, DocsConfig, DocsUiConfigResponse, OPENAPI_PATH, SCALAR_PATH,
};

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
        super::list_crawl_runs,
        super::get_crawl_run,
        super::count_nodes_by_asn,
        super::list_last_run_services,
        super::list_last_run_protocol_versions,
        super::list_last_run_user_agents,
        super::list_last_run_network_types,
        super::list_last_run_countries,
        super::list_last_run_asns,
        super::list_last_run_start_heights,
        super::list_last_run_asn_organizations,
        super::list_last_run_nodes
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
        (name = "Crawler Analytics", description = "Read-only crawler analytics endpoints.")
    )
)]
struct ApiDoc;
