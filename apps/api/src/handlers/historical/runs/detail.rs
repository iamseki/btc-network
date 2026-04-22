use axum::Json;
use axum::extract::{Path, State};
use btc_network::crawler::{CrawlRunDetail, CrawlRunId};

use crate::handlers::{ApiError, DEFAULT_CHECKPOINT_LIMIT, ErrorResponse};
use crate::routes::AppState;

pub(crate) const HISTORICAL_RUN_DETAIL_PATH: &str = "/api/v1/network/historical/runs/{run_id}";

#[utoipa::path(
    get,
    path = "/api/v1/network/historical/runs/{run_id}",
    summary = "Get historical run detail",
    description = "Return detailed network analytics for one historical crawl run, including checkpoints, failure counts, and network outcomes.",
    params(
        ("run_id" = String, Path, description = "Historical crawl run identifier.")
    ),
    responses(
        (status = 200, description = "Detailed historical crawl run analytics.", body = CrawlRunDetail),
        (status = 400, description = "Invalid crawl run identifier.", body = ErrorResponse),
        (status = 404, description = "Crawl run not found.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn get_crawl_run_docs() {}

pub(crate) async fn get_crawl_run(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
) -> Result<Json<CrawlRunDetail>, ApiError> {
    let run_id = CrawlRunId::parse_str(&run_id)
        .map_err(|_| ApiError::bad_request("invalid crawl run id"))?;
    let detail = state
        .analytics_reader
        .get_crawl_run(&run_id, DEFAULT_CHECKPOINT_LIMIT)
        .await
        .map_err(ApiError::internal)?;

    match detail {
        Some(detail) => Ok(Json(detail)),
        None => Err(ApiError::not_found("crawl run not found")),
    }
}
