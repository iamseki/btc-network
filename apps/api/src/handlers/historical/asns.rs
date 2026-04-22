use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::AsnNodeCountItem;

use crate::handlers::{
    ApiError, DEFAULT_ASN_LIMIT, ErrorResponse, PaginationQuery, RowsResponse, parse_limit,
};
use crate::routes::AppState;

pub(crate) const HISTORICAL_ASNS_PATH: &str = "/api/v1/network/historical/asns";

#[utoipa::path(
    get,
    path = "/api/v1/network/historical/asns",
    summary = "List historical ASN concentration",
    description = "Return verified-node counts grouped by ASN across stored historical network analytics data.",
    params(
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
    Query(query): Query<PaginationQuery>,
) -> Result<Json<RowsResponse<AsnNodeCountItem>>, ApiError> {
    let limit = parse_limit(query.limit, DEFAULT_ASN_LIMIT)?;
    let rows = state
        .analytics_reader
        .count_nodes_by_asn(limit)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RowsResponse { rows }))
}
