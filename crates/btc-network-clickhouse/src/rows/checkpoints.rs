use btc_network::crawler::{CrawlPhase, CrawlRunCheckpoint, CrawlRunId, CrawlRunMetrics};
use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Row, Serialize, Deserialize)]
pub(crate) struct RunCheckpointRow {
    pub run_id: String,
    pub phase: String,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub checkpointed_at: DateTime<Utc>,
    pub checkpoint_sequence: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime")]
    pub started_at: DateTime<Utc>,
    pub stop_reason: Option<String>,
    pub failure_reason: Option<String>,
    pub frontier_size: u64,
    pub in_flight_work: u64,
    pub scheduled_tasks: u64,
    pub successful_handshakes: u64,
    pub failed_tasks: u64,
    pub queued_nodes_total: u64,
    pub unique_nodes: u64,
    pub discovered_node_states: u64,
    pub persisted_observation_rows: u64,
    pub writer_backlog: u64,
    pub resume_state: Option<String>,
    pub caller: Option<String>,
}

pub(crate) fn from_checkpoint(checkpoint: CrawlRunCheckpoint) -> RunCheckpointRow {
    RunCheckpointRow {
        run_id: checkpoint.run_id.as_str().to_string(),
        phase: phase_to_str(checkpoint.phase).to_string(),
        checkpointed_at: checkpoint.checkpointed_at,
        checkpoint_sequence: checkpoint.checkpoint_sequence,
        started_at: checkpoint.started_at,
        stop_reason: checkpoint.stop_reason,
        failure_reason: checkpoint.failure_reason,
        frontier_size: checkpoint.metrics.frontier_size as u64,
        in_flight_work: checkpoint.metrics.in_flight_work as u64,
        scheduled_tasks: checkpoint.metrics.scheduled_tasks as u64,
        successful_handshakes: checkpoint.metrics.successful_handshakes as u64,
        failed_tasks: checkpoint.metrics.failed_tasks as u64,
        queued_nodes_total: checkpoint.metrics.queued_nodes_total as u64,
        unique_nodes: checkpoint.metrics.unique_nodes as u64,
        discovered_node_states: checkpoint.metrics.discovered_node_states as u64,
        persisted_observation_rows: checkpoint.metrics.persisted_observation_rows as u64,
        writer_backlog: checkpoint.metrics.writer_backlog as u64,
        resume_state: checkpoint.resume_state,
        caller: checkpoint.caller,
    }
}

pub(crate) fn to_checkpoint(row: RunCheckpointRow) -> CrawlRunCheckpoint {
    CrawlRunCheckpoint {
        run_id: CrawlRunId::new(row.run_id),
        phase: phase_from_str(&row.phase),
        checkpointed_at: row.checkpointed_at,
        checkpoint_sequence: row.checkpoint_sequence,
        started_at: row.started_at,
        stop_reason: row.stop_reason,
        failure_reason: row.failure_reason,
        metrics: CrawlRunMetrics {
            frontier_size: row.frontier_size as usize,
            in_flight_work: row.in_flight_work as usize,
            scheduled_tasks: row.scheduled_tasks as usize,
            successful_handshakes: row.successful_handshakes as usize,
            failed_tasks: row.failed_tasks as usize,
            queued_nodes_total: row.queued_nodes_total as usize,
            unique_nodes: row.unique_nodes as usize,
            discovered_node_states: row.discovered_node_states as usize,
            persisted_observation_rows: row.persisted_observation_rows as usize,
            writer_backlog: row.writer_backlog as usize,
        },
        resume_state: row.resume_state,
        caller: row.caller,
    }
}

fn phase_to_str(value: CrawlPhase) -> &'static str {
    match value {
        CrawlPhase::Bootstrap => "bootstrap",
        CrawlPhase::Crawling => "crawling",
        CrawlPhase::Draining => "draining",
        CrawlPhase::Completed => "completed",
        CrawlPhase::Failed => "failed",
    }
}

fn phase_from_str(value: &str) -> CrawlPhase {
    match value {
        "bootstrap" => CrawlPhase::Bootstrap,
        "crawling" => CrawlPhase::Crawling,
        "draining" => CrawlPhase::Draining,
        "completed" => CrawlPhase::Completed,
        "failed" => CrawlPhase::Failed,
        _ => CrawlPhase::Failed,
    }
}
