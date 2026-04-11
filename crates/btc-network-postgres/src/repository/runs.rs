use btc_network::crawler::{
    CrawlEndpoint, CrawlNetwork, CrawlRunCheckpoint, CrawlRunId, CrawlRunMetrics,
    CrawlRunRecoveryPoint, CrawlerRepositoryError, RecoveryPayloadEncoding,
};
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::{PgPool, PgRow, Postgres};
use uuid::Uuid;

use crate::values::crawl_phase_from_str;

use super::map_postgres_err;

pub(super) async fn get_run_checkpoint(
    pool: &PgPool,
    run_id: &CrawlRunId,
) -> Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError> {
    let row = query::<Postgres>(
        "
SELECT
    run_id,
    phase,
    checkpointed_at,
    checkpoint_sequence,
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
    caller
FROM crawler_run_checkpoints
WHERE run_id = $1
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 1
",
    )
    .bind(run_id.as_uuid())
    .fetch_optional(pool)
    .await
    .map_err(|err| map_postgres_err("fetch latest run checkpoint", err))?;

    row.map(row_to_checkpoint).transpose()
}

pub(super) async fn get_latest_active_run_checkpoint(
    pool: &PgPool,
) -> Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError> {
    let row = query::<Postgres>(
        "
SELECT
    run_id,
    phase,
    checkpointed_at,
    checkpoint_sequence,
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
    caller
FROM crawler_run_checkpoints
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 1
",
    )
    .fetch_optional(pool)
    .await
    .map_err(|err| map_postgres_err("fetch latest active run checkpoint", err))?;

    let Some(checkpoint) = row.map(row_to_checkpoint).transpose()? else {
        return Ok(None);
    };

    if matches!(
        checkpoint.phase,
        btc_network::crawler::CrawlPhase::Bootstrap
            | btc_network::crawler::CrawlPhase::Crawling
            | btc_network::crawler::CrawlPhase::Draining
    ) {
        Ok(Some(checkpoint))
    } else {
        Ok(None)
    }
}

pub(super) async fn get_latest_active_run_recovery_point(
    pool: &PgPool,
) -> Result<Option<CrawlRunRecoveryPoint>, CrawlerRepositoryError> {
    let row = query::<Postgres>(
        "
SELECT
    run_id,
    phase,
    checkpointed_at,
    checkpoint_sequence,
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
    payload_encoding,
    frontier_payload,
    recovery_frontier_size,
    caller
FROM crawler_run_recovery_points
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 1
",
    )
    .fetch_optional(pool)
    .await
    .map_err(|err| map_postgres_err("fetch latest active run recovery point", err))?;

    let Some(recovery_point) = row.map(row_to_recovery_point).transpose()? else {
        return Ok(None);
    };

    if matches!(
        recovery_point.phase,
        btc_network::crawler::CrawlPhase::Bootstrap
            | btc_network::crawler::CrawlPhase::Crawling
            | btc_network::crawler::CrawlPhase::Draining
    ) {
        Ok(Some(recovery_point))
    } else {
        Ok(None)
    }
}

pub(super) async fn list_runs(
    pool: &PgPool,
) -> Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError> {
    let rows = query::<Postgres>(
        "
SELECT *
FROM (
    SELECT DISTINCT ON (run_id)
        run_id,
        phase,
        checkpointed_at,
        checkpoint_sequence,
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
        caller
    FROM crawler_run_checkpoints
    ORDER BY run_id, checkpointed_at DESC, checkpoint_sequence DESC
) latest_runs
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
",
    )
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list crawler runs", err))?;

    rows.into_iter().map(row_to_checkpoint).collect()
}

pub(super) async fn list_observed_endpoints_for_run(
    pool: &PgPool,
    run_id: &CrawlRunId,
) -> Result<Vec<CrawlEndpoint>, CrawlerRepositoryError> {
    let rows = query::<Postgres>(
        "
SELECT endpoint, network_type
FROM node_observations
WHERE crawl_run_id = $1
GROUP BY endpoint, network_type
ORDER BY endpoint ASC
",
    )
    .bind(run_id.as_uuid())
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list observed endpoints for run", err))?;

    rows.into_iter()
        .map(|row| {
            let endpoint: String = row
                .try_get("endpoint")
                .map_err(|err| map_postgres_err("decode observed endpoint", err))?;
            let network_type: String = row
                .try_get("network_type")
                .map_err(|err| map_postgres_err("decode observed network_type", err))?;
            let network = CrawlNetwork::from_storage_str(&network_type).ok_or_else(|| {
                CrawlerRepositoryError::new(format!(
                    "decode observed network_type: unsupported network type {network_type}"
                ))
            })?;
            CrawlEndpoint::from_stored(endpoint, network).map_err(CrawlerRepositoryError::new)
        })
        .collect()
}

pub(super) fn row_to_checkpoint(row: PgRow) -> Result<CrawlRunCheckpoint, CrawlerRepositoryError> {
    let checkpoint_sequence: i64 = row
        .try_get("checkpoint_sequence")
        .map_err(|err| map_postgres_err("decode checkpoint_sequence", err))?;
    let metrics = CrawlRunMetrics {
        frontier_size: row
            .try_get::<i64, _>("frontier_size")
            .map_err(|err| map_postgres_err("decode frontier_size", err))?
            .max(0) as usize,
        in_flight_work: row
            .try_get::<i64, _>("in_flight_work")
            .map_err(|err| map_postgres_err("decode in_flight_work", err))?
            .max(0) as usize,
        scheduled_tasks: row
            .try_get::<i64, _>("scheduled_tasks")
            .map_err(|err| map_postgres_err("decode scheduled_tasks", err))?
            .max(0) as usize,
        successful_handshakes: row
            .try_get::<i64, _>("successful_handshakes")
            .map_err(|err| map_postgres_err("decode successful_handshakes", err))?
            .max(0) as usize,
        failed_tasks: row
            .try_get::<i64, _>("failed_tasks")
            .map_err(|err| map_postgres_err("decode failed_tasks", err))?
            .max(0) as usize,
        queued_nodes_total: row
            .try_get::<i64, _>("queued_nodes_total")
            .map_err(|err| map_postgres_err("decode queued_nodes_total", err))?
            .max(0) as usize,
        unique_nodes: row
            .try_get::<i64, _>("unique_nodes")
            .map_err(|err| map_postgres_err("decode unique_nodes", err))?
            .max(0) as usize,
        discovered_node_states: row
            .try_get::<i64, _>("discovered_node_states")
            .map_err(|err| map_postgres_err("decode discovered_node_states", err))?
            .max(0) as usize,
        persisted_observation_rows: row
            .try_get::<i64, _>("persisted_observation_rows")
            .map_err(|err| map_postgres_err("decode persisted_observation_rows", err))?
            .max(0) as usize,
        writer_backlog: row
            .try_get::<i64, _>("writer_backlog")
            .map_err(|err| map_postgres_err("decode writer_backlog", err))?
            .max(0) as usize,
    };

    Ok(CrawlRunCheckpoint {
        run_id: CrawlRunId::new(
            row.try_get::<Uuid, _>("run_id")
                .map_err(|err| map_postgres_err("decode run_id", err))?,
        ),
        phase: crawl_phase_from_str(
            row.try_get::<String, _>("phase")
                .map_err(|err| map_postgres_err("decode phase", err))?
                .as_str(),
        ),
        checkpointed_at: row
            .try_get("checkpointed_at")
            .map_err(|err| map_postgres_err("decode checkpointed_at", err))?,
        checkpoint_sequence: checkpoint_sequence.max(0) as u64,
        started_at: row
            .try_get("started_at")
            .map_err(|err| map_postgres_err("decode started_at", err))?,
        stop_reason: row
            .try_get("stop_reason")
            .map_err(|err| map_postgres_err("decode stop_reason", err))?,
        failure_reason: row
            .try_get("failure_reason")
            .map_err(|err| map_postgres_err("decode failure_reason", err))?,
        metrics,
        caller: row
            .try_get("caller")
            .map_err(|err| map_postgres_err("decode caller", err))?,
    })
}

fn row_to_recovery_point(row: PgRow) -> Result<CrawlRunRecoveryPoint, CrawlerRepositoryError> {
    let checkpoint_sequence: i64 = row
        .try_get("checkpoint_sequence")
        .map_err(|err| map_postgres_err("decode checkpoint_sequence", err))?;
    let payload_encoding = row
        .try_get::<String, _>("payload_encoding")
        .map_err(|err| map_postgres_err("decode payload_encoding", err))?;

    Ok(CrawlRunRecoveryPoint {
        run_id: CrawlRunId::new(
            row.try_get::<Uuid, _>("run_id")
                .map_err(|err| map_postgres_err("decode run_id", err))?,
        ),
        phase: crawl_phase_from_str(
            row.try_get::<String, _>("phase")
                .map_err(|err| map_postgres_err("decode phase", err))?
                .as_str(),
        ),
        checkpointed_at: row
            .try_get("checkpointed_at")
            .map_err(|err| map_postgres_err("decode checkpointed_at", err))?,
        checkpoint_sequence: checkpoint_sequence.max(0) as u64,
        started_at: row
            .try_get("started_at")
            .map_err(|err| map_postgres_err("decode started_at", err))?,
        stop_reason: row
            .try_get("stop_reason")
            .map_err(|err| map_postgres_err("decode stop_reason", err))?,
        failure_reason: row
            .try_get("failure_reason")
            .map_err(|err| map_postgres_err("decode failure_reason", err))?,
        metrics: CrawlRunMetrics {
            frontier_size: row
                .try_get::<i64, _>("frontier_size")
                .map_err(|err| map_postgres_err("decode frontier_size", err))?
                .max(0) as usize,
            in_flight_work: row
                .try_get::<i64, _>("in_flight_work")
                .map_err(|err| map_postgres_err("decode in_flight_work", err))?
                .max(0) as usize,
            scheduled_tasks: row
                .try_get::<i64, _>("scheduled_tasks")
                .map_err(|err| map_postgres_err("decode scheduled_tasks", err))?
                .max(0) as usize,
            successful_handshakes: row
                .try_get::<i64, _>("successful_handshakes")
                .map_err(|err| map_postgres_err("decode successful_handshakes", err))?
                .max(0) as usize,
            failed_tasks: row
                .try_get::<i64, _>("failed_tasks")
                .map_err(|err| map_postgres_err("decode failed_tasks", err))?
                .max(0) as usize,
            queued_nodes_total: row
                .try_get::<i64, _>("queued_nodes_total")
                .map_err(|err| map_postgres_err("decode queued_nodes_total", err))?
                .max(0) as usize,
            unique_nodes: row
                .try_get::<i64, _>("unique_nodes")
                .map_err(|err| map_postgres_err("decode unique_nodes", err))?
                .max(0) as usize,
            discovered_node_states: row
                .try_get::<i64, _>("discovered_node_states")
                .map_err(|err| map_postgres_err("decode discovered_node_states", err))?
                .max(0) as usize,
            persisted_observation_rows: row
                .try_get::<i64, _>("persisted_observation_rows")
                .map_err(|err| map_postgres_err("decode persisted_observation_rows", err))?
                .max(0) as usize,
            writer_backlog: row
                .try_get::<i64, _>("writer_backlog")
                .map_err(|err| map_postgres_err("decode writer_backlog", err))?
                .max(0) as usize,
        },
        payload_encoding: RecoveryPayloadEncoding::from_str(&payload_encoding).ok_or_else(
            || {
                CrawlerRepositoryError::new(format!(
                    "decode payload_encoding: unsupported encoding {payload_encoding}"
                ))
            },
        )?,
        frontier_payload: row
            .try_get("frontier_payload")
            .map_err(|err| map_postgres_err("decode frontier_payload", err))?,
        frontier_size: row
            .try_get::<i64, _>("recovery_frontier_size")
            .map_err(|err| map_postgres_err("decode recovery_frontier_size", err))?
            .max(0) as usize,
        caller: row
            .try_get("caller")
            .map_err(|err| map_postgres_err("decode caller", err))?,
    })
}
