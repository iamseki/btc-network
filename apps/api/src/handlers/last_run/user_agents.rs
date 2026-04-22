use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::LastRunUserAgentCountItem;

use crate::handlers::{
    ApiError, DEFAULT_LAST_RUN_BUCKET_LIMIT, ErrorResponse, PaginationQuery, RowsResponse,
    parse_limit,
};
use crate::routes::AppState;

pub(crate) const LIST_LAST_RUN_USER_AGENTS_PATH: &str = "/api/v1/network/last-run/user-agents";

#[utoipa::path(
    get,
    path = "/api/v1/network/last-run/user-agents",
    summary = "List last-run user agents",
    description = "Return verified-node user-agent distribution from latest finished run.",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of user-agent buckets to return. Default 100. Maximum 100.")
    ),
    responses(
        (status = 200, description = "Last-run user-agent distribution.", body = RowsResponse<LastRunUserAgentCountItem>),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_last_run_user_agents_docs() {}

pub(crate) async fn list_last_run_user_agents(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<RowsResponse<LastRunUserAgentCountItem>>, ApiError> {
    let rows = state
        .analytics_reader
        .list_last_run_user_agents(parse_limit(query.limit, DEFAULT_LAST_RUN_BUCKET_LIMIT)?)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RowsResponse { rows }))
}
