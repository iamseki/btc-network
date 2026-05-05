use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::AsnNodeCountItem;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::handlers::{
    ApiError, DEFAULT_ASN_LIMIT, ErrorResponse, MAX_HISTORICAL_ASN_WINDOW_DAYS, RowsResponse,
    parse_limit,
};
use crate::routes::AppState;

pub(crate) const HISTORICAL_ASNS_PATH: &str = "/api/v1/network/historical/asns";

#[derive(Debug, Deserialize)]
pub(crate) struct HistoricalAsnsQuery {
    limit: Option<usize>,
    start: Option<String>,
    end: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/network/historical/asns",
    summary = "List historical ASN concentration",
    description = "Return verified-node counts grouped by ASN inside a bounded historical observation window.",
    params(
        ("start" = String, Query, description = "Inclusive RFC3339 observation window start. Required."),
        ("end" = String, Query, description = "Exclusive RFC3339 observation window end. Required. Maximum window is 31 days."),
        ("limit" = Option<usize>, Query, description = "Maximum number of ASN buckets to return. Default 10. Maximum 100.")
    ),
    responses(
        (status = 200, description = "Historical verified-node counts grouped by ASN.", body = RowsResponse<AsnNodeCountItem>),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn count_nodes_by_asn_docs() {}

pub(crate) async fn count_nodes_by_asn(
    State(state): State<AppState>,
    Query(query): Query<HistoricalAsnsQuery>,
) -> Result<Json<RowsResponse<AsnNodeCountItem>>, ApiError> {
    let limit = parse_limit(query.limit, DEFAULT_ASN_LIMIT)?;
    let (start, end) = parse_window(query.start.as_deref(), query.end.as_deref())?;
    let rows = state
        .analytics_reader
        .count_nodes_by_asn(start, end, limit)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RowsResponse { rows }))
}

fn parse_window(
    start: Option<&str>,
    end: Option<&str>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let start = parse_rfc3339(start.ok_or_else(|| ApiError::bad_request("start is required"))?)?;
    let end = parse_rfc3339(end.ok_or_else(|| ApiError::bad_request("end is required"))?)?;

    if start >= end {
        return Err(ApiError::bad_request("start must be before end"));
    }

    if end - start > Duration::days(MAX_HISTORICAL_ASN_WINDOW_DAYS) {
        return Err(ApiError::bad_request(format!(
            "time window must be less than or equal to {MAX_HISTORICAL_ASN_WINDOW_DAYS} days"
        )));
    }

    Ok((start, end))
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ApiError::bad_request("timestamp must be RFC3339"))
}
