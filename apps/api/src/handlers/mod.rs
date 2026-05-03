pub(crate) mod historical;
pub(crate) mod last_run;
pub(crate) mod node_status;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use btc_network::crawler::{CrawlRunListItem, CrawlerRepositoryError};
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;

pub(crate) use historical::{
    HISTORICAL_ASNS_PATH, HISTORICAL_RUN_DETAIL_PATH, HISTORICAL_RUNS_PATH, count_nodes_by_asn,
    get_crawl_run, list_crawl_runs,
};
pub(crate) use last_run::{
    LIST_LAST_RUN_ASN_ORGANIZATIONS_PATH, LIST_LAST_RUN_ASNS_PATH, LIST_LAST_RUN_COUNTRIES_PATH,
    LIST_LAST_RUN_NETWORK_TYPES_PATH, LIST_LAST_RUN_NODES_PATH,
    LIST_LAST_RUN_PROTOCOL_VERSIONS_PATH, LIST_LAST_RUN_SERVICES_PATH,
    LIST_LAST_RUN_START_HEIGHTS_PATH, LIST_LAST_RUN_USER_AGENTS_PATH,
    list_last_run_asn_organizations, list_last_run_asns, list_last_run_countries,
    list_last_run_network_types, list_last_run_nodes, list_last_run_protocol_versions,
    list_last_run_services, list_last_run_start_heights, list_last_run_user_agents,
};
pub(crate) use node_status::{NODE_STATUS_PATH, list_node_status};

const DEFAULT_RUN_LIMIT: usize = 10;
const DEFAULT_ASN_LIMIT: usize = 10;
const DEFAULT_CHECKPOINT_LIMIT: usize = 10;
const MAX_PAGE_LIMIT: usize = 100;
const DEFAULT_LAST_RUN_BUCKET_LIMIT: usize = 100;
const DEFAULT_LAST_RUN_NODE_LIMIT: usize = 500;
const MAX_LAST_RUN_NODE_LIMIT: usize = 1_000;

#[derive(Debug, Deserialize)]
pub(crate) struct PaginationQuery {
    pub(crate) limit: Option<usize>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CrawlRunsResponse {
    pub(crate) runs: Vec<CrawlRunListItem>,
}

#[derive(Debug, Serialize, ToSchema)]
#[schema(bound = "T: utoipa::ToSchema")]
#[serde(rename_all = "camelCase")]
pub(crate) struct RowsResponse<T> {
    pub(crate) rows: Vec<T>,
}

pub(crate) fn parse_limit(value: Option<usize>, default_value: usize) -> Result<usize, ApiError> {
    parse_limit_with_max(value, default_value, MAX_PAGE_LIMIT)
}

pub(crate) fn parse_limit_with_max(
    value: Option<usize>,
    default_value: usize,
    max_value: usize,
) -> Result<usize, ApiError> {
    let limit = value.unwrap_or(default_value);

    if limit == 0 {
        return Err(ApiError::bad_request("limit must be greater than zero"));
    }

    if limit > max_value {
        return Err(ApiError::bad_request(format!(
            "limit must be less than or equal to {max_value}"
        )));
    }

    Ok(limit)
}

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    log_detail: Option<String>,
}

impl ApiError {
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
            log_detail: None,
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
            log_detail: None,
        }
    }

    pub(crate) fn internal(error: CrawlerRepositoryError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "network analytics backend failed".to_string(),
            log_detail: Some(error.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Some(detail) = self.log_detail {
            error!(code = self.code, detail = %detail, "[api] request failed");
        }

        (
            self.status,
            Json(ErrorResponse {
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorBody {
    code: &'static str,
    message: String,
}
