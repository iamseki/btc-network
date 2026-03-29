use btc_network::crawler::{CrawlRunCheckpoint, CrawlRunId, CrawlerRepositoryError};
use clickhouse::{Client, sql::Identifier};

use crate::rows::{RunCheckpointRow, to_checkpoint};

use super::{CRAWLER_RUN_CHECKPOINTS_TABLE, map_clickhouse_err};

pub(super) async fn get_run_checkpoint(
    client: &Client,
    run_id: &CrawlRunId,
) -> Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError> {
    client
        .query(
            "SELECT ?fields FROM ? WHERE run_id = ? ORDER BY checkpointed_at DESC, checkpoint_sequence DESC LIMIT 1",
        )
        .bind(Identifier(CRAWLER_RUN_CHECKPOINTS_TABLE))
        .bind(run_id.as_str())
        .fetch_optional::<RunCheckpointRow>()
        .await
        .map(|row| row.map(to_checkpoint))
        .map_err(map_clickhouse_err("fetch latest run checkpoint"))
}

pub(super) async fn list_runs(
    client: &Client,
) -> Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError> {
    client
        .query(
            "
SELECT
    run_id,
    phase,
    latest_checkpointed_at AS checkpointed_at,
    latest_checkpoint_sequence AS checkpoint_sequence,
    started_at,
    stop_reason,
    failure_reason,
    frontier_size,
    in_flight_work,
    scheduled_tasks,
    successful_handshakes,
    failed_tasks,
    queued_nodes_total,
    unique_nodes,
    discovered_node_states,
    persisted_observation_rows,
    writer_backlog,
    resume_state,
    caller
FROM (
    SELECT
        run_id,
        argMax(phase, tuple(checkpointed_at, checkpoint_sequence)) AS phase,
        max(checkpointed_at) AS latest_checkpointed_at,
        argMax(checkpoint_sequence, tuple(checkpointed_at, checkpoint_sequence)) AS latest_checkpoint_sequence,
        argMax(started_at, tuple(checkpointed_at, checkpoint_sequence)) AS started_at,
        argMax(stop_reason, tuple(checkpointed_at, checkpoint_sequence)) AS stop_reason,
        argMax(failure_reason, tuple(checkpointed_at, checkpoint_sequence)) AS failure_reason,
        argMax(frontier_size, tuple(checkpointed_at, checkpoint_sequence)) AS frontier_size,
        argMax(in_flight_work, tuple(checkpointed_at, checkpoint_sequence)) AS in_flight_work,
        argMax(scheduled_tasks, tuple(checkpointed_at, checkpoint_sequence)) AS scheduled_tasks,
        argMax(successful_handshakes, tuple(checkpointed_at, checkpoint_sequence)) AS successful_handshakes,
        argMax(failed_tasks, tuple(checkpointed_at, checkpoint_sequence)) AS failed_tasks,
        argMax(queued_nodes_total, tuple(checkpointed_at, checkpoint_sequence)) AS queued_nodes_total,
        argMax(unique_nodes, tuple(checkpointed_at, checkpoint_sequence)) AS unique_nodes,
        argMax(discovered_node_states, tuple(checkpointed_at, checkpoint_sequence)) AS discovered_node_states,
        argMax(persisted_observation_rows, tuple(checkpointed_at, checkpoint_sequence)) AS persisted_observation_rows,
        argMax(writer_backlog, tuple(checkpointed_at, checkpoint_sequence)) AS writer_backlog,
        argMax(resume_state, tuple(checkpointed_at, checkpoint_sequence)) AS resume_state,
        argMax(caller, tuple(checkpointed_at, checkpoint_sequence)) AS caller
    FROM ?
    GROUP BY run_id
)
ORDER BY checkpointed_at DESC
",
        )
        .bind(Identifier(CRAWLER_RUN_CHECKPOINTS_TABLE))
        .fetch_all::<RunCheckpointRow>()
        .await
        .map(|rows| rows.into_iter().map(to_checkpoint).collect())
        .map_err(map_clickhouse_err("list crawler runs"))
}
