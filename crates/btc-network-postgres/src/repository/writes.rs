use btc_network::crawler::{CrawlRunCheckpoint, CrawlerRepositoryError, PersistedNodeObservation};
use sqlx_core::{query::query, query_builder::QueryBuilder};
use sqlx_postgres::{PgPool, Postgres};

use crate::values::{
    crawl_network_to_str, crawl_phase_to_str, duration_to_millis, enrichment_status_to_str,
    failure_classification_to_str, usize_to_i64,
};

use super::map_postgres_err;

// Observation ingest is write-heavy; batching reduces round trips without
// getting close to PostgreSQL's bind-parameter limit.
const OBSERVATION_INSERT_CHUNK_SIZE: usize = 1000;
const INSERT_OBSERVATIONS_SQL: &str = "
INSERT INTO node_observations (
    observed_at,
    crawl_run_id,
    endpoint,
    network_type,
    protocol_version,
    services,
    user_agent,
    start_height,
    relay,
    discovered_peer_addresses_count,
    latency_ms,
    failure_classification,
    enrichment_status,
    asn,
    asn_organization,
    country,
    prefix
)
";

pub(super) async fn insert_observations_stream(
    pool: &PgPool,
    observations: Vec<PersistedNodeObservation>,
) -> Result<(), CrawlerRepositoryError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|err| map_postgres_err("start observation transaction", err))?;

    for chunk in observations.chunks(OBSERVATION_INSERT_CHUNK_SIZE) {
        observation_insert_builder(chunk)
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(|err| map_postgres_err("write observation batch", err))?;
    }

    transaction
        .commit()
        .await
        .map_err(|err| map_postgres_err("commit observation transaction", err))
}

fn observation_insert_builder<'a>(
    observations: &'a [PersistedNodeObservation],
) -> QueryBuilder<'a, Postgres> {
    let mut builder = QueryBuilder::<Postgres>::new(INSERT_OBSERVATIONS_SQL);

    builder.push_values(observations, |mut row, observation| {
        row.push_bind(observation.raw.observed_at)
            .push_bind(observation.raw.crawl_run_id.as_uuid())
            .push_bind(observation.raw.endpoint.canonical.as_str())
            .push_bind(crawl_network_to_str(observation.raw.endpoint.network))
            .push_bind(observation.raw.protocol_version)
            .push_bind(observation.raw.services.map(|value| value.to_string()))
            .push_bind(observation.raw.user_agent.as_deref())
            .push_bind(observation.raw.start_height)
            .push_bind(observation.raw.relay)
            .push_bind(usize_to_i64(
                observation.raw.discovered_peer_addresses_count,
            ))
            .push_bind(observation.raw.latency.map(duration_to_millis))
            .push_bind(
                observation
                    .raw
                    .failure_classification
                    .as_ref()
                    .map(failure_classification_to_str),
            )
            .push_bind(enrichment_status_to_str(observation.enrichment.status))
            .push_bind(observation.enrichment.asn.map(|value| value as i32))
            .push_bind(observation.enrichment.asn_organization.as_deref())
            .push_bind(observation.enrichment.country.as_deref())
            .push_bind(observation.enrichment.prefix.as_deref());
    });

    builder
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
    unique_nodes,
    persisted_observation_rows,
    writer_backlog
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
)
",
    )
    .bind(checkpoint.run_id.as_uuid())
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
    .bind(usize_to_i64(checkpoint.metrics.unique_nodes))
    .bind(usize_to_i64(checkpoint.metrics.persisted_observation_rows))
    .bind(usize_to_i64(checkpoint.metrics.writer_backlog))
    .execute(pool)
    .await
    .map_err(|err| map_postgres_err("write checkpoint row", err))?;

    Ok(())
}
