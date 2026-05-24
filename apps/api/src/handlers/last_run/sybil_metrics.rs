use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::SybilMetricsReport;

use crate::handlers::{ApiError, ErrorResponse, last_run::parse_phase_filter};
use crate::routes::AppState;

pub(crate) const GET_LAST_RUN_SYBIL_METRICS_PATH: &str = "/api/v1/network/last-run/sybil-metrics";

#[utoipa::path(
    get,
    path = "/api/v1/network/last-run/sybil-metrics",
    summary = "Get last-run Sybil-oriented metrics",
    description = "Return a compact latest-run report of typed crawler-visible concentration and uniformity signals. Signals are review prompts only; they are not confirmed attack claims or proof of shared operator control.",
    params(
        ("phase" = Option<String>, Query, description = "Run phase filter. Defaults to finished. Use any for the newest run regardless of phase, or comma-separated phases such as finished,crawling.")
    ),
    responses(
        (status = 200, description = "Last-run Sybil-oriented metrics report.", body = SybilMetricsReport),
        (status = 400, description = "Invalid phase filter.", body = ErrorResponse),
        (status = 404, description = "No matching crawl run found.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn get_last_run_sybil_metrics_docs() {}

pub(crate) async fn get_last_run_sybil_metrics(
    State(state): State<AppState>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Result<Json<SybilMetricsReport>, ApiError> {
    if let Some(parameter) = query.keys().find(|key| key.as_str() != "phase") {
        return Err(ApiError::bad_request(format!(
            "{parameter} is not supported for sybil metrics"
        )));
    }

    let report = state
        .analytics_reader
        .get_last_run_sybil_metrics(parse_phase_filter(query.get("phase").cloned())?)
        .await
        .map_err(ApiError::internal)?;

    match report {
        Some(report) => Ok(Json(report)),
        None => Err(ApiError::not_found("last run not found")),
    }
}
