use btc_network::crawler::{
    CrawlRunCheckpoint, CrawlRunRecoveryPoint, CrawlerRepositoryError, PersistedNodeObservation,
};
use sqlx_core::query::query;
use sqlx_postgres::{PgPool, Postgres};

use crate::values::{
    confidence_to_str, crawl_network_to_str, crawl_phase_to_str, duration_to_millis,
    enrichment_status_to_str, failure_classification_to_str, handshake_status_to_str, usize_to_i64,
};

use super::map_postgres_err;

pub(super) async fn insert_observations_stream(
    pool: &PgPool,
    observations: Vec<PersistedNodeObservation>,
) -> Result<(), CrawlerRepositoryError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|err| map_postgres_err("start observation transaction", err))?;
    for observation in observations {
        let latency_ms = observation.raw.latency.map(duration_to_millis);
        let failure_classification = observation
            .raw
            .failure_classification
            .as_ref()
            .map(failure_classification_to_str);
        let network_type = crawl_network_to_str(observation.raw.endpoint.network);
        let endpoint = observation.raw.endpoint.canonical;
        let services = observation.raw.services.map(|value| value.to_string());
        let asn = observation.enrichment.asn.map(|value| value as i32);

        query::<Postgres>(
            "
INSERT INTO node_observations (
    observed_at,
    crawl_run_id,
    observation_id,
    batch_id,
    endpoint,
    network_type,
    handshake_status,
    confidence_level,
    protocol_version,
    services,
    user_agent,
    start_height,
    relay,
    discovered_count,
    latency_ms,
    failure_classification,
    enrichment_status,
    asn,
    asn_organization,
    country,
    prefix
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
)
",
        )
        .bind(observation.raw.observed_at)
        .bind(observation.raw.crawl_run_id.as_str())
        .bind(observation.observation_id.as_str())
        .bind(observation.batch_id.as_str())
        .bind(endpoint)
        .bind(network_type)
        .bind(handshake_status_to_str(observation.raw.handshake_status))
        .bind(confidence_to_str(observation.raw.confidence))
        .bind(observation.raw.protocol_version)
        .bind(services)
        .bind(observation.raw.user_agent)
        .bind(observation.raw.start_height)
        .bind(observation.raw.relay)
        .bind(usize_to_i64(observation.raw.discovered_count))
        .bind(latency_ms)
        .bind(failure_classification)
        .bind(enrichment_status_to_str(observation.enrichment.status))
        .bind(asn)
        .bind(observation.enrichment.asn_organization)
        .bind(observation.enrichment.country)
        .bind(observation.enrichment.prefix)
        .execute(&mut *transaction)
        .await
        .map_err(|err| map_postgres_err("write observation row", err))?;
    }

    transaction
        .commit()
        .await
        .map_err(|err| map_postgres_err("commit observation transaction", err))
}

pub(super) async fn insert_run_checkpoint(
    pool: &PgPool,
    checkpoint: CrawlRunCheckpoint,
) -> Result<(), CrawlerRepositoryError> {
    query::<Postgres>(
        "
INSERT INTO crawler_run_checkpoints (
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
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
)
",
    )
    .bind(checkpoint.run_id.as_str())
    .bind(crawl_phase_to_str(checkpoint.phase))
    .bind(checkpoint.checkpointed_at)
    .bind(checkpoint.checkpoint_sequence as i64)
    .bind(checkpoint.started_at)
    .bind(checkpoint.stop_reason)
    .bind(checkpoint.failure_reason)
    .bind(usize_to_i64(checkpoint.metrics.frontier_size))
    .bind(usize_to_i64(checkpoint.metrics.in_flight_work))
    .bind(usize_to_i64(checkpoint.metrics.scheduled_tasks))
    .bind(usize_to_i64(checkpoint.metrics.successful_handshakes))
    .bind(usize_to_i64(checkpoint.metrics.failed_tasks))
    .bind(usize_to_i64(checkpoint.metrics.queued_nodes_total))
    .bind(usize_to_i64(checkpoint.metrics.unique_nodes))
    .bind(usize_to_i64(checkpoint.metrics.discovered_node_states))
    .bind(usize_to_i64(checkpoint.metrics.persisted_observation_rows))
    .bind(usize_to_i64(checkpoint.metrics.writer_backlog))
    .bind(checkpoint.caller)
    .execute(pool)
    .await
    .map_err(|err| map_postgres_err("write checkpoint row", err))?;

    Ok(())
}

pub(super) async fn insert_run_recovery_point(
    pool: &PgPool,
    recovery_point: CrawlRunRecoveryPoint,
) -> Result<(), CrawlerRepositoryError> {
    query::<Postgres>(
        "
INSERT INTO crawler_run_recovery_points (
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
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
)
",
    )
    .bind(recovery_point.run_id.as_str())
    .bind(crawl_phase_to_str(recovery_point.phase))
    .bind(recovery_point.checkpointed_at)
    .bind(recovery_point.checkpoint_sequence as i64)
    .bind(recovery_point.started_at)
    .bind(recovery_point.stop_reason)
    .bind(recovery_point.failure_reason)
    .bind(usize_to_i64(recovery_point.metrics.frontier_size))
    .bind(usize_to_i64(recovery_point.metrics.in_flight_work))
    .bind(usize_to_i64(recovery_point.metrics.scheduled_tasks))
    .bind(usize_to_i64(recovery_point.metrics.successful_handshakes))
    .bind(usize_to_i64(recovery_point.metrics.failed_tasks))
    .bind(usize_to_i64(recovery_point.metrics.queued_nodes_total))
    .bind(usize_to_i64(recovery_point.metrics.unique_nodes))
    .bind(usize_to_i64(recovery_point.metrics.discovered_node_states))
    .bind(usize_to_i64(
        recovery_point.metrics.persisted_observation_rows,
    ))
    .bind(usize_to_i64(recovery_point.metrics.writer_backlog))
    .bind(recovery_point.payload_encoding.as_str())
    .bind(recovery_point.frontier_payload)
    .bind(usize_to_i64(recovery_point.frontier_size))
    .bind(recovery_point.caller)
    .execute(pool)
    .await
    .map_err(|err| map_postgres_err("write recovery point row", err))?;

    Ok(())
}
