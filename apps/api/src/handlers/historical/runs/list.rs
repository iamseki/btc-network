use axum::Json;
use axum::extract::{Query, State};

use crate::handlers::{
    ApiError, CrawlRunsResponse, DEFAULT_RUN_LIMIT, ErrorResponse, PaginationQuery, parse_limit,
};
use crate::routes::AppState;

pub(crate) const HISTORICAL_RUNS_PATH: &str = "/api/v1/network/historical/runs";

#[utoipa::path(
    get,
    path = "/api/v1/network/historical/runs",
    summary = "List historical runs",
    description = "Return historical crawl-run snapshots so clients can inspect previous network analytics windows and select a run for deeper inspection.",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of historical runs to return. Default 10. Maximum 100.")
    ),
    responses(
        (status = 200, description = "Historical crawl runs.", body = CrawlRunsResponse),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_crawl_runs_docs() {}

pub(crate) async fn list_crawl_runs(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<CrawlRunsResponse>, ApiError> {
    let limit = parse_limit(query.limit, DEFAULT_RUN_LIMIT)?;
    let runs = state
        .analytics_reader
        .list_crawl_runs(limit)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(CrawlRunsResponse { runs }))
}
