use axum::Json;
use axum::extract::{Query, State};
use btc_network::crawler::{LastRunNodePageCursor, LastRunNodeSummaryItem};
use chrono::{DateTime, Utc};

use crate::handlers::{
    ApiError, DEFAULT_LAST_RUN_NODE_LIMIT, ErrorResponse, MAX_LAST_RUN_NODE_LIMIT, PageResponse,
    PageTokenQuery, parse_limit_with_max,
};
use crate::routes::AppState;

pub(crate) const LIST_LAST_RUN_NODES_PATH: &str = "/api/v1/network/last-run/nodes";
const PAGE_TOKEN_PREFIX: &str = "last-run-nodes-v1";

#[utoipa::path(
    get,
    path = "/api/v1/network/last-run/nodes",
    summary = "List last-run verified nodes",
    description = "Return verified-node table from latest finished run with endpoint, network, protocol, geography, and ASN context.",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum number of verified node rows to return. Default 500. Maximum 1000."),
        ("pageToken" = Option<String>, Query, description = "Opaque continuation token from nextPageToken. Only valid for this endpoint.")
    ),
    responses(
        (status = 200, description = "Last-run verified nodes.", body = PageResponse<LastRunNodeSummaryItem>),
        (status = 400, description = "Invalid pagination limit.", body = ErrorResponse),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_last_run_nodes_docs() {}

pub(crate) async fn list_last_run_nodes(
    State(state): State<AppState>,
    Query(query): Query<PageTokenQuery>,
) -> Result<Json<PageResponse<LastRunNodeSummaryItem>>, ApiError> {
    let limit = parse_limit_with_max(
        query.limit,
        DEFAULT_LAST_RUN_NODE_LIMIT,
        MAX_LAST_RUN_NODE_LIMIT,
    )?;
    let cursor = query
        .page_token
        .as_deref()
        .map(decode_page_token)
        .transpose()?;
    let page = state
        .analytics_reader
        .list_last_run_nodes(limit, cursor)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(PageResponse {
        items: page.items,
        next_page_token: page.next_cursor.as_ref().map(encode_page_token),
    }))
}

fn encode_page_token(cursor: &LastRunNodePageCursor) -> String {
    format!(
        "{PAGE_TOKEN_PREFIX}:{}:{}:{}",
        cursor.observed_at.timestamp_micros(),
        hex_encode(cursor.endpoint.as_bytes()),
        cursor.node_observation_id
    )
}

fn decode_page_token(token: &str) -> Result<LastRunNodePageCursor, ApiError> {
    let mut parts = token.split(':');
    let prefix = parts.next();
    let observed_at = parts.next();
    let endpoint = parts.next();
    let node_observation_id = parts.next();

    if prefix != Some(PAGE_TOKEN_PREFIX) || parts.next().is_some() {
        return Err(invalid_page_token());
    }

    let observed_at = observed_at
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .ok_or_else(invalid_page_token)?;
    let endpoint = endpoint
        .and_then(hex_decode)
        .ok_or_else(invalid_page_token)?;
    let node_observation_id = node_observation_id
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(invalid_page_token)?;

    Ok(LastRunNodePageCursor {
        observed_at,
        endpoint,
        node_observation_id,
    })
}

fn invalid_page_token() -> ApiError {
    ApiError::bad_request("pageToken is invalid")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Option<String> {
    if !value.len().is_multiple_of(2) {
        return None;
    }

    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = hex_value(chunk[0])?;
            let low = hex_value(chunk[1])?;
            Some((high << 4) | low)
        })
        .collect::<Option<Vec<_>>>()?;

    String::from_utf8(bytes).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
