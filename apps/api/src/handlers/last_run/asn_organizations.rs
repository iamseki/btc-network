use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::LastRunAsnOrganizationCountItem;

use crate::handlers::{
    ApiError, DEFAULT_LAST_RUN_BUCKET_LIMIT, ErrorResponse, RowsResponse,
    last_run::{LastRunDistributionQuery, parse_phase_filter},
    parse_limit,
};
use crate::routes::AppState;

pub(crate) const LIST_LAST_RUN_ASN_ORGANIZATIONS_PATH: &str =
    "/api/v1/network/last-run/asn-organizations";

#[utoipa::path(
    get,
    path = "/api/v1/network/last-run/asn-organizations",
    summary = "List last-run ASN organizations",
    description = "Return verified-node ASN-organization distribution from the newest run that matches the phase filter. Defaults to the latest finished run.",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of ASN-organization buckets to return. Default 100. Maximum 100."),
        ("phase" = Option<String>, Query, description = "Run phase filter. Defaults to finished. Use any for the newest run regardless of phase, or comma-separated phases such as finished,crawling.")
    ),
    responses(
        (status = 200, description = "Last-run ASN-organization distribution.", body = RowsResponse<LastRunAsnOrganizationCountItem>),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_last_run_asn_organizations_docs() {}

pub(crate) async fn list_last_run_asn_organizations(
    State(state): State<AppState>,
    Query(query): Query<LastRunDistributionQuery>,
) -> Result<Json<RowsResponse<LastRunAsnOrganizationCountItem>>, ApiError> {
    let rows = state
        .analytics_reader
        .list_last_run_asn_organizations(
            parse_limit(query.limit, DEFAULT_LAST_RUN_BUCKET_LIMIT)?,
            parse_phase_filter(query.phase)?,
        )
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(RowsResponse { rows }))
}
