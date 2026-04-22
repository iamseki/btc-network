use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::LastRunNodeSummaryItem;

use crate::handlers::{
    ApiError, DEFAULT_LAST_RUN_NODE_LIMIT, ErrorResponse, MAX_LAST_RUN_NODE_LIMIT, PaginationQuery,
    RowsResponse, parse_limit_with_max,
};
use crate::routes::AppState;

pub(crate) const LIST_LAST_RUN_NODES_PATH: &str = "/api/v1/network/last-run/nodes";

#[utoipa::path(
    get,
    path = "/api/v1/network/last-run/nodes",
    summary = "List last-run verified nodes",
    description = "Return verified-node table from latest finished run with endpoint, network, protocol, geography, and ASN context.",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of verified node rows to return. Default 500. Maximum 1000.")
    ),
    responses(
        (status = 200, description = "Last-run verified nodes.", body = RowsResponse<LastRunNodeSummaryItem>),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_last_run_nodes_docs() {}

pub(crate) async fn list_last_run_nodes(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<RowsResponse<LastRunNodeSummaryItem>>, ApiError> {
    let rows = state
        .analytics_reader
        .list_last_run_nodes(parse_limit_with_max(
            query.limit,
            DEFAULT_LAST_RUN_NODE_LIMIT,
            MAX_LAST_RUN_NODE_LIMIT,
        )?)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RowsResponse { rows }))
}
