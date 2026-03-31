use btc_network::crawler::{
    AsnNodeCountItem, CrawlRunCheckpointItem, CrawlRunDetail, CrawlRunId, CrawlRunListItem,
    CrawlerRepositoryError,
};
use clickhouse::{Client, sql::Identifier};

use crate::rows::{
    CountNodesByAsnDbRow, FailureClassificationCountDbRow, NetworkOutcomeCountDbRow,
    RunCheckpointRow, to_asn_node_count_item, to_checkpoint, to_count_nodes_by_asn,
    to_failure_classification_count, to_network_outcome_count,
};

use super::{CRAWLER_RUN_CHECKPOINTS_TABLE, NODE_OBSERVATIONS_TABLE, map_clickhouse_err};

pub(super) async fn count_nodes_by_asn(
    client: &Client,
) -> Result<Vec<btc_network::crawler::CountNodesByAsnRow>, CrawlerRepositoryError> {
    query_count_nodes_by_asn(client, None)
        .await
        .map(|rows| rows.into_iter().map(to_count_nodes_by_asn).collect())
}

pub(super) async fn count_nodes_by_asn_limited(
    client: &Client,
    limit: usize,
) -> Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError> {
    query_count_nodes_by_asn(client, Some(limit))
        .await
        .map(|rows| rows.into_iter().map(to_asn_node_count_item).collect())
}

pub(super) async fn list_crawl_runs(
    client: &Client,
    limit: usize,
) -> Result<Vec<CrawlRunListItem>, CrawlerRepositoryError> {
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
LIMIT ?
",
        )
        .bind(Identifier(CRAWLER_RUN_CHECKPOINTS_TABLE))
        .bind(limit as u64)
        .fetch_all::<RunCheckpointRow>()
        .await
        .map(|rows| {
            rows.into_iter()
                .map(to_checkpoint)
                .map(|checkpoint| CrawlRunListItem::from_checkpoint(&checkpoint))
                .collect()
        })
        .map_err(map_clickhouse_err("list crawl runs"))
}

pub(super) async fn get_crawl_run(
    client: &Client,
    run_id: &CrawlRunId,
    checkpoint_limit: usize,
) -> Result<Option<CrawlRunDetail>, CrawlerRepositoryError> {
    let latest_checkpoint = super::runs::get_run_checkpoint(client, run_id).await?;
    let Some(latest_checkpoint) = latest_checkpoint else {
        return Ok(None);
    };

    let checkpoints = list_run_checkpoints(client, run_id, checkpoint_limit).await?;
    let failure_counts = list_failure_classification_counts(client, run_id).await?;
    let network_outcomes = list_network_outcomes(client, run_id).await?;

    Ok(Some(CrawlRunDetail {
        run: CrawlRunListItem::from_checkpoint(&latest_checkpoint),
        checkpoints,
        failure_counts,
        network_outcomes,
    }))
}

async fn query_count_nodes_by_asn(
    client: &Client,
    limit: Option<usize>,
) -> Result<Vec<CountNodesByAsnDbRow>, CrawlerRepositoryError> {
    let limit = limit.unwrap_or(usize::MAX) as u64;

    client
        .query(
            "
SELECT
    asn,
    asn_organization,
    count() AS verified_nodes
FROM (
    SELECT
        endpoint,
        argMax(confidence_level, tuple(observed_at, observation_id)) AS confidence_level,
        argMax(asn, tuple(observed_at, observation_id)) AS asn,
        argMax(asn_organization, tuple(observed_at, observation_id)) AS asn_organization
    FROM ?
    GROUP BY endpoint
)
WHERE confidence_level = 'verified'
GROUP BY asn, asn_organization
ORDER BY verified_nodes DESC, asn ASC
LIMIT ?
",
        )
        .bind(Identifier(NODE_OBSERVATIONS_TABLE))
        .bind(limit)
        .fetch_all::<CountNodesByAsnDbRow>()
        .await
        .map_err(map_clickhouse_err("count nodes by ASN"))
}

async fn list_run_checkpoints(
    client: &Client,
    run_id: &CrawlRunId,
    checkpoint_limit: usize,
) -> Result<Vec<CrawlRunCheckpointItem>, CrawlerRepositoryError> {
    client
        .query(
            "
SELECT ?fields
FROM ?
WHERE run_id = ?
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT ?
",
        )
        .bind(Identifier(CRAWLER_RUN_CHECKPOINTS_TABLE))
        .bind(run_id.as_str())
        .bind(checkpoint_limit as u64)
        .fetch_all::<RunCheckpointRow>()
        .await
        .map(|rows| {
            rows.into_iter()
                .map(to_checkpoint)
                .map(|checkpoint| CrawlRunCheckpointItem::from_checkpoint(&checkpoint))
                .collect()
        })
        .map_err(map_clickhouse_err("list crawl run checkpoints"))
}

async fn list_failure_classification_counts(
    client: &Client,
    run_id: &CrawlRunId,
) -> Result<Vec<btc_network::crawler::FailureClassificationCount>, CrawlerRepositoryError> {
    client
        .query(
            "
SELECT
    assumeNotNull(failure_classification) AS classification,
    count() AS observations
FROM ?
WHERE crawl_run_id = ?
  AND failure_classification IS NOT NULL
GROUP BY failure_classification
ORDER BY observations DESC, classification ASC
",
        )
        .bind(Identifier(NODE_OBSERVATIONS_TABLE))
        .bind(run_id.as_str())
        .fetch_all::<FailureClassificationCountDbRow>()
        .await
        .map(|rows| {
            rows.into_iter()
                .map(to_failure_classification_count)
                .collect()
        })
        .map_err(map_clickhouse_err("list failure classification counts"))
}

async fn list_network_outcomes(
    client: &Client,
    run_id: &CrawlRunId,
) -> Result<Vec<btc_network::crawler::NetworkOutcomeCount>, CrawlerRepositoryError> {
    client
        .query(
            "
SELECT
    network_type,
    count() AS observations,
    countIf(confidence_level = 'verified') AS verified_nodes,
    countIf(confidence_level = 'failed') AS failed_nodes,
    ifNull(round(100.0 * countIf(confidence_level = 'verified') / nullIf(count(), 0), 2), 0.0) AS verified_pct
FROM ?
WHERE crawl_run_id = ?
GROUP BY network_type
ORDER BY observations DESC, network_type ASC
",
        )
        .bind(Identifier(NODE_OBSERVATIONS_TABLE))
        .bind(run_id.as_str())
        .fetch_all::<NetworkOutcomeCountDbRow>()
        .await
        .map(|rows| rows.into_iter().map(to_network_outcome_count).collect())
        .map_err(map_clickhouse_err("list network outcomes"))
}
