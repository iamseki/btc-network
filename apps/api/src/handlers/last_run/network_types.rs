use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::LastRunNetworkTypeCountItem;

use crate::handlers::{
    ApiError, DEFAULT_LAST_RUN_BUCKET_LIMIT, ErrorResponse, PaginationQuery, RowsResponse,
    parse_limit,
};
use crate::routes::AppState;

pub(crate) const LIST_LAST_RUN_NETWORK_TYPES_PATH: &str = "/api/v1/network/last-run/network-types";

#[utoipa::path(
    get,
    path = "/api/v1/network/last-run/network-types",
    summary = "List last-run network types",
    description = "Return verified-node network-type distribution from latest finished run.",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of network-type buckets to return. Default 100. Maximum 100.")
    ),
    responses(
        (status = 200, description = "Last-run network-type distribution.", body = RowsResponse<LastRunNetworkTypeCountItem>),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_last_run_network_types_docs() {}

pub(crate) async fn list_last_run_network_types(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<RowsResponse<LastRunNetworkTypeCountItem>>, ApiError> {
    let rows = state
        .analytics_reader
        .list_last_run_network_types(parse_limit(query.limit, DEFAULT_LAST_RUN_BUCKET_LIMIT)?)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RowsResponse { rows }))
}
