use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::LastRunProtocolVersionCountItem;

use crate::handlers::{
    ApiError, DEFAULT_LAST_RUN_BUCKET_LIMIT, ErrorResponse, PaginationQuery, RowsResponse,
    parse_limit,
};
use crate::routes::AppState;

pub(crate) const LIST_LAST_RUN_PROTOCOL_VERSIONS_PATH: &str =
    "/api/v1/network/last-run/protocol-versions";

#[utoipa::path(
    get,
    path = "/api/v1/network/last-run/protocol-versions",
    summary = "List last-run protocol versions",
    description = "Return verified-node protocol-version distribution from latest finished run.",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of protocol-version buckets to return. Default 100. Maximum 100.")
    ),
    responses(
        (status = 200, description = "Last-run protocol-version distribution.", body = RowsResponse<LastRunProtocolVersionCountItem>),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_last_run_protocol_versions_docs() {}

pub(crate) async fn list_last_run_protocol_versions(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<RowsResponse<LastRunProtocolVersionCountItem>>, ApiError> {
    let rows = state
        .analytics_reader
        .list_last_run_protocol_versions(parse_limit(query.limit, DEFAULT_LAST_RUN_BUCKET_LIMIT)?)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RowsResponse { rows }))
}
