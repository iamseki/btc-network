use btc_network::crawler::{
    AsnNodeCountItem, CountNodesByAsnRow, CrawlRunCheckpointItem, CrawlRunDetail, CrawlRunId,
    CrawlRunListItem, CrawlerRepositoryError, FailureClassificationCount, NetworkOutcomeCount,
};
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::{PgPool, Postgres};

use super::map_postgres_err;

pub(super) async fn count_nodes_by_asn(
    pool: &PgPool,
) -> Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError> {
    query_count_nodes_by_asn(pool, None).await.map(|rows| {
        rows.into_iter()
            .map(|row| CountNodesByAsnRow {
                asn: row.asn.map(|value| value as u32),
                asn_organization: row.asn_organization,
                verified_nodes: row.verified_nodes.max(0) as u64,
            })
            .collect()
    })
}

pub(super) async fn count_nodes_by_asn_limited(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError> {
    query_count_nodes_by_asn(pool, Some(limit))
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| AsnNodeCountItem {
                    asn: row.asn.map(|value| value as u32),
                    asn_organization: row.asn_organization,
                    verified_nodes: row.verified_nodes.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_crawl_runs(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<CrawlRunListItem>, CrawlerRepositoryError> {
    let rows = super::runs::list_runs(pool).await?;
    Ok(rows
        .into_iter()
        .take(limit)
        .map(|checkpoint| CrawlRunListItem::from_checkpoint(&checkpoint))
        .collect())
}

pub(super) async fn get_crawl_run(
    pool: &PgPool,
    run_id: &CrawlRunId,
    checkpoint_limit: usize,
) -> Result<Option<CrawlRunDetail>, CrawlerRepositoryError> {
    let latest_checkpoint = super::runs::get_run_checkpoint(pool, run_id).await?;
    let Some(latest_checkpoint) = latest_checkpoint else {
        return Ok(None);
    };

    let checkpoints = list_run_checkpoints(pool, run_id, checkpoint_limit).await?;
    let failure_counts = list_failure_classification_counts(pool, run_id).await?;
    let network_outcomes = list_network_outcomes(pool, run_id).await?;

    Ok(Some(CrawlRunDetail {
        run: CrawlRunListItem::from_checkpoint(&latest_checkpoint),
        checkpoints,
        failure_counts,
        network_outcomes,
    }))
}

struct CountNodesByAsnDbRow {
    asn: Option<i32>,
    asn_organization: Option<String>,
    verified_nodes: i64,
}

async fn query_count_nodes_by_asn(
    pool: &PgPool,
    limit: Option<usize>,
) -> Result<Vec<CountNodesByAsnDbRow>, CrawlerRepositoryError> {
    let limit = limit.unwrap_or(i64::MAX as usize).min(i64::MAX as usize) as i64;
    let rows = query::<Postgres>(
        "
SELECT
    asn,
    asn_organization,
    COUNT(*) AS verified_nodes
FROM (
    SELECT DISTINCT ON (endpoint)
        endpoint,
        handshake_status,
        asn,
        asn_organization
    FROM node_observations
    ORDER BY endpoint, observed_at DESC, observation_id DESC
) latest_by_endpoint
WHERE handshake_status = 'succeeded'
GROUP BY asn, asn_organization
ORDER BY verified_nodes DESC, asn ASC NULLS FIRST
LIMIT $1
",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("count nodes by ASN", err))?;

    Ok(rows
        .into_iter()
        .map(
            |row| -> Result<CountNodesByAsnDbRow, CrawlerRepositoryError> {
                Ok(CountNodesByAsnDbRow {
                    asn: row
                        .try_get("asn")
                        .map_err(|err| map_postgres_err("decode asn", err))?,
                    asn_organization: row
                        .try_get("asn_organization")
                        .map_err(|err| map_postgres_err("decode asn_organization", err))?,
                    verified_nodes: row
                        .try_get("verified_nodes")
                        .map_err(|err| map_postgres_err("decode verified_nodes", err))?,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?)
}

async fn list_run_checkpoints(
    pool: &PgPool,
    run_id: &CrawlRunId,
    checkpoint_limit: usize,
) -> Result<Vec<CrawlRunCheckpointItem>, CrawlerRepositoryError> {
    let limit = checkpoint_limit.min(i64::MAX as usize) as i64;
    let rows = query::<Postgres>(
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
LIMIT $2
",
    )
    .bind(run_id.as_uuid())
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list crawl run checkpoints", err))?;

    rows.into_iter()
        .map(super::runs::row_to_checkpoint)
        .map(|result| result.map(|checkpoint| CrawlRunCheckpointItem::from_checkpoint(&checkpoint)))
        .collect()
}

async fn list_failure_classification_counts(
    pool: &PgPool,
    run_id: &CrawlRunId,
) -> Result<Vec<FailureClassificationCount>, CrawlerRepositoryError> {
    let rows = query::<Postgres>(
        "
SELECT failure_classification AS classification, COUNT(*) AS observations
FROM node_observations
WHERE crawl_run_id = $1
  AND failure_classification IS NOT NULL
GROUP BY failure_classification
ORDER BY observations DESC, classification ASC
",
    )
    .bind(run_id.as_uuid())
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list failure classification counts", err))?;

    Ok(rows
        .into_iter()
        .map(
            |row| -> Result<FailureClassificationCount, CrawlerRepositoryError> {
                Ok(FailureClassificationCount {
                    classification: row
                        .try_get("classification")
                        .map_err(|err| map_postgres_err("decode classification", err))?,
                    observations: row
                        .try_get::<i64, _>("observations")
                        .map_err(|err| map_postgres_err("decode observations", err))?
                        .max(0) as u64,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?)
}

async fn list_network_outcomes(
    pool: &PgPool,
    run_id: &CrawlRunId,
) -> Result<Vec<NetworkOutcomeCount>, CrawlerRepositoryError> {
    let rows = query::<Postgres>(
        "
SELECT
    network_type,
    COUNT(*) AS observations,
    COUNT(*) FILTER (WHERE handshake_status = 'succeeded') AS verified_nodes,
    COUNT(*) FILTER (WHERE handshake_status = 'failed') AS failed_nodes,
    COALESCE(
        ROUND(
            (
                100.0 * COUNT(*) FILTER (WHERE handshake_status = 'succeeded')
                / NULLIF(COUNT(*), 0)
            )::numeric,
            2
        )::double precision,
        0.0
    ) AS verified_pct
FROM node_observations
WHERE crawl_run_id = $1
GROUP BY network_type
ORDER BY observations DESC, network_type ASC
",
    )
    .bind(run_id.as_uuid())
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list network outcomes", err))?;

    Ok(rows
        .into_iter()
        .map(
            |row| -> Result<NetworkOutcomeCount, CrawlerRepositoryError> {
                Ok(NetworkOutcomeCount {
                    network_type: row
                        .try_get("network_type")
                        .map_err(|err| map_postgres_err("decode network_type", err))?,
                    observations: row
                        .try_get::<i64, _>("observations")
                        .map_err(|err| map_postgres_err("decode observations", err))?
                        .max(0) as u64,
                    verified_nodes: row
                        .try_get::<i64, _>("verified_nodes")
                        .map_err(|err| map_postgres_err("decode verified_nodes", err))?
                        .max(0) as u64,
                    failed_nodes: row
                        .try_get::<i64, _>("failed_nodes")
                        .map_err(|err| map_postgres_err("decode failed_nodes", err))?
                        .max(0) as u64,
                    verified_pct: row
                        .try_get("verified_pct")
                        .map_err(|err| map_postgres_err("decode verified_pct", err))?,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?)
}
