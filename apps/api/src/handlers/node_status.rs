use axum::Json;
use axum::extract::State;
use btc_network::status::NodeStatusItem;

use crate::handlers::{ApiError, ErrorResponse};
use crate::routes::AppState;

pub(crate) const NODE_STATUS_PATH: &str = "/api/nodes/status";

#[utoipa::path(
    get,
    path = "/api/nodes/status",
    summary = "List curated node status",
    description = "Return latest status plus bounded recent history for curated Bitcoin DNS seeders and public node targets.",
    responses(
        (status = 200, description = "Curated node status rows.", body = Vec<NodeStatusItem>),
        (status = 500, description = "Network analytics backend failed.", body = ErrorResponse)
    ),
    tag = "Network Analytics"
)]
#[allow(dead_code)]
pub(crate) fn list_node_status_docs() {}

pub(crate) async fn list_node_status(
    State(state): State<AppState>,
) -> Result<Json<Vec<NodeStatusItem>>, ApiError> {
    let rows = state
        .analytics_reader
        .list_node_status()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(rows))
}
