use chrono::{DateTime, Utc};
use serde::Serialize;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

use super::domain::{CountNodesByAsnRow, CrawlPhase, CrawlRunCheckpoint};

/// Summary row returned by crawl-run listing APIs.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrawlRunListItem {
    pub run_id: String,
    pub phase: String,
    pub started_at: String,
    pub last_checkpointed_at: String,
    pub stop_reason: Option<String>,
    pub failure_reason: Option<String>,
    pub scheduled_tasks: usize,
    pub successful_handshakes: usize,
    pub failed_tasks: usize,
    pub unique_nodes: usize,
    pub persisted_observation_rows: usize,
    pub success_pct: f64,
    pub scheduled_pct: f64,
    pub unscheduled_gap: usize,
}

impl CrawlRunListItem {
    /// Derives a list item from the winning checkpoint row for a run.
    pub fn from_checkpoint(checkpoint: &CrawlRunCheckpoint) -> Self {
        let scheduled_tasks = checkpoint.metrics.scheduled_tasks;
        let successful_handshakes = checkpoint.metrics.successful_handshakes;
        let unique_nodes = checkpoint.metrics.unique_nodes;

        Self {
            run_id: checkpoint.run_id.to_string(),
            phase: crawl_phase_to_str(checkpoint.phase).to_string(),
            started_at: to_rfc3339(checkpoint.started_at),
            last_checkpointed_at: to_rfc3339(checkpoint.checkpointed_at),
            stop_reason: checkpoint.stop_reason.clone(),
            failure_reason: checkpoint.failure_reason.clone(),
            scheduled_tasks,
            successful_handshakes,
            failed_tasks: checkpoint.metrics.failed_tasks,
            unique_nodes,
            persisted_observation_rows: checkpoint.metrics.persisted_observation_rows,
            success_pct: percentage(successful_handshakes, scheduled_tasks),
            scheduled_pct: percentage(scheduled_tasks, unique_nodes),
            unscheduled_gap: unique_nodes.saturating_sub(scheduled_tasks),
        }
    }
}

/// Serializable checkpoint summary exposed to analytics clients.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrawlRunCheckpointItem {
    pub phase: String,
    pub checkpointed_at: String,
    pub checkpoint_sequence: u64,
    pub stop_reason: Option<String>,
    pub failure_reason: Option<String>,
    pub frontier_size: usize,
    pub in_flight_work: usize,
    pub scheduled_tasks: usize,
    pub successful_handshakes: usize,
    pub failed_tasks: usize,
    pub unique_nodes: usize,
    pub persisted_observation_rows: usize,
    pub writer_backlog: usize,
}

impl CrawlRunCheckpointItem {
    /// Derives a checkpoint item from one durable checkpoint row.
    pub fn from_checkpoint(checkpoint: &CrawlRunCheckpoint) -> Self {
        Self {
            phase: crawl_phase_to_str(checkpoint.phase).to_string(),
            checkpointed_at: to_rfc3339(checkpoint.checkpointed_at),
            checkpoint_sequence: checkpoint.checkpoint_sequence,
            stop_reason: checkpoint.stop_reason.clone(),
            failure_reason: checkpoint.failure_reason.clone(),
            frontier_size: checkpoint.metrics.frontier_size,
            in_flight_work: checkpoint.metrics.in_flight_work,
            scheduled_tasks: checkpoint.metrics.scheduled_tasks,
            successful_handshakes: checkpoint.metrics.successful_handshakes,
            failed_tasks: checkpoint.metrics.failed_tasks,
            unique_nodes: checkpoint.metrics.unique_nodes,
            persisted_observation_rows: checkpoint.metrics.persisted_observation_rows,
            writer_backlog: checkpoint.metrics.writer_backlog,
        }
    }
}

/// Count of observations grouped by failure classification.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureClassificationCount {
    pub classification: String,
    pub observations: u64,
}

/// Count of observations grouped by network family with derived verification
/// rate for UI consumers.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkOutcomeCount {
    pub network_type: String,
    pub observations: u64,
    pub verified_nodes: u64,
    pub failed_nodes: u64,
    pub verified_pct: f64,
}

/// Verified-node count grouped by ASN for analytics views.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsnNodeCountItem {
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub verified_nodes: u64,
}

impl From<CountNodesByAsnRow> for AsnNodeCountItem {
    fn from(value: CountNodesByAsnRow) -> Self {
        Self {
            asn: value.asn,
            asn_organization: value.asn_organization,
            verified_nodes: value.verified_nodes,
        }
    }
}

/// Latest finished-run services distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunServicesCountItem {
    pub services: String,
    pub node_count: u64,
}

/// Latest finished-run protocol version distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunProtocolVersionCountItem {
    pub protocol_version: i32,
    pub node_count: u64,
}

/// Latest finished-run user agent distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunUserAgentCountItem {
    pub user_agent: String,
    pub node_count: u64,
}

/// Latest finished-run network type distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunNetworkTypeCountItem {
    pub network_type: String,
    pub node_count: u64,
}

/// Latest finished-run country distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunCountryCountItem {
    pub country: String,
    pub node_count: u64,
}

/// Latest finished-run ASN distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunAsnCountItem {
    pub asn: u32,
    pub asn_organization: Option<String>,
    pub node_count: u64,
}

/// Latest finished-run start-height distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunStartHeightCountItem {
    pub start_height: i32,
    pub node_count: u64,
}

/// Latest finished-run ASN organization distribution bucket.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunAsnOrganizationCountItem {
    pub asn_organization: String,
    pub node_count: u64,
}

/// Latest finished-run verified node row for table-oriented UI views.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRunNodeSummaryItem {
    pub endpoint: String,
    pub network_type: String,
    pub protocol_version: i32,
    pub user_agent: String,
    pub services: String,
    pub start_height: i32,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
}

/// Full crawl-run payload returned by analytics detail APIs.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrawlRunDetail {
    pub run: CrawlRunListItem,
    pub checkpoints: Vec<CrawlRunCheckpointItem>,
    pub failure_counts: Vec<FailureClassificationCount>,
    pub network_outcomes: Vec<NetworkOutcomeCount>,
}

/// Formats a UTC timestamp for browser-safe analytics payloads.
pub fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

/// Converts an internal crawl phase to the stable analytics string form.
pub fn crawl_phase_to_str(value: CrawlPhase) -> &'static str {
    match value {
        CrawlPhase::Bootstrap => "bootstrap",
        CrawlPhase::Crawling => "crawling",
        CrawlPhase::Draining => "draining",
        CrawlPhase::Finished => "finished",
    }
}

/// Returns a two-decimal percentage, using `0.0` when the denominator is zero.
pub fn percentage(numerator: usize, denominator: usize) -> f64 {
    percentage_u64(numerator as u64, denominator as u64)
}

/// Returns a two-decimal percentage for `u64` inputs, using `0.0` when the
/// denominator is zero.
pub fn percentage_u64(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }

    round_two_decimals((numerator as f64 / denominator as f64) * 100.0)
}

fn round_two_decimals(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::{CrawlRunCheckpoint, CrawlRunId, CrawlRunMetrics};
    use chrono::TimeZone;

    #[test]
    fn crawl_run_list_item_derives_percentages_from_checkpoint() {
        let checkpoint = CrawlRunCheckpoint {
            run_id: CrawlRunId::from_u128(1),
            phase: CrawlPhase::Finished,
            checkpointed_at: Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap(),
            checkpoint_sequence: 3,
            started_at: Utc.with_ymd_and_hms(2026, 3, 30, 11, 30, 0).unwrap(),
            stop_reason: Some("idle timeout".to_string()),
            failure_reason: None,
            metrics: CrawlRunMetrics {
                frontier_size: 0,
                in_flight_work: 0,
                scheduled_tasks: 80,
                successful_handshakes: 20,
                failed_tasks: 60,
                unique_nodes: 100,
                persisted_observation_rows: 80,
                writer_backlog: 0,
            },
        };

        let item = CrawlRunListItem::from_checkpoint(&checkpoint);

        assert_eq!(item.run_id, CrawlRunId::from_u128(1).to_string());
        assert_eq!(item.phase, "finished");
        assert_eq!(item.success_pct, 25.0);
        assert_eq!(item.scheduled_pct, 80.0);
        assert_eq!(item.unscheduled_gap, 20);
    }

    #[test]
    fn percentage_returns_zero_for_zero_denominator() {
        assert_eq!(percentage(5, 0), 0.0);
        assert_eq!(percentage_u64(5, 0), 0.0);
    }
}
