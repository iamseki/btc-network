use btc_network::crawler::{
    CrawlEndpoint, CrawlerRepositoryError, UnreachableNodeUpdate, UnreachableNodeUpdateKind,
};
use chrono::{DateTime, Utc};
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::{PgPool, Postgres};

use crate::values::{crawl_network_from_str, crawl_network_to_str, failure_classification_to_str};

use super::map_postgres_err;

pub(super) async fn load_unreachable_nodes(
    pool: &PgPool,
    since: DateTime<Utc>,
) -> Result<Vec<CrawlEndpoint>, CrawlerRepositoryError> {
    let rows = query::<Postgres>(
        "
SELECT endpoint, network_type
FROM unreachable_nodes
WHERE recovered_at IS NULL
  AND last_unreachable_at >= $1
ORDER BY endpoint
",
    )
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("load unreachable nodes", err))?;

    rows.into_iter()
        .map(|row| {
            let endpoint = row.get::<String, _>("endpoint");
            let network_type = row.get::<String, _>("network_type");
            let network = crawl_network_from_str(&network_type).ok_or_else(|| {
                CrawlerRepositoryError::new(format!(
                    "load unreachable nodes: unknown network type {network_type}"
                ))
            })?;
            CrawlEndpoint::from_stored(endpoint, network).map_err(|err| {
                CrawlerRepositoryError::new(format!("load unreachable nodes: {err}"))
            })
        })
        .collect()
}

pub(super) async fn apply_unreachable_node_updates(
    pool: &PgPool,
    updates: Vec<UnreachableNodeUpdate>,
) -> Result<(), CrawlerRepositoryError> {
    if updates.is_empty() {
        return Ok(());
    }

    let mut transaction = pool
        .begin()
        .await
        .map_err(|err| map_postgres_err("start unreachable-node transaction", err))?;

    for update in updates {
        match update.kind {
            UnreachableNodeUpdateKind::Record => {
                record_unreachable_node(&mut transaction, update).await?;
            }
            UnreachableNodeUpdateKind::Recover => {
                recover_unreachable_node(&mut transaction, update).await?;
            }
        }
    }

    transaction
        .commit()
        .await
        .map_err(|err| map_postgres_err("commit unreachable-node transaction", err))
}

async fn record_unreachable_node(
    transaction: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    update: UnreachableNodeUpdate,
) -> Result<(), CrawlerRepositoryError> {
    let Some(classification) = update.failure_classification.as_ref() else {
        return Ok(());
    };

    query::<Postgres>(
        "
INSERT INTO unreachable_nodes (
    endpoint,
    network_type,
    first_unreachable_at,
    last_unreachable_at,
    last_crawl_run_id,
    last_failure_classification,
    failure_count,
    recovered_at,
    recovered_crawl_run_id
)
VALUES ($1, $2, $3, $3, $4, $5, 1, NULL, NULL)
ON CONFLICT (endpoint) DO UPDATE SET
    network_type = EXCLUDED.network_type,
    last_unreachable_at = EXCLUDED.last_unreachable_at,
    last_crawl_run_id = EXCLUDED.last_crawl_run_id,
    last_failure_classification = EXCLUDED.last_failure_classification,
    failure_count = unreachable_nodes.failure_count + 1,
    recovered_at = NULL,
    recovered_crawl_run_id = NULL
",
    )
    .bind(update.endpoint.canonical.as_str())
    .bind(crawl_network_to_str(update.endpoint.network))
    .bind(update.observed_at)
    .bind(update.crawl_run_id.as_uuid())
    .bind(failure_classification_to_str(classification))
    .execute(&mut **transaction)
    .await
    .map_err(|err| map_postgres_err("record unreachable node", err))?;

    Ok(())
}

async fn recover_unreachable_node(
    transaction: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    update: UnreachableNodeUpdate,
) -> Result<(), CrawlerRepositoryError> {
    query::<Postgres>(
        "
UPDATE unreachable_nodes
SET
    recovered_at = $2,
    recovered_crawl_run_id = $3
WHERE endpoint = $1
",
    )
    .bind(update.endpoint.canonical.as_str())
    .bind(update.observed_at)
    .bind(update.crawl_run_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|err| map_postgres_err("recover unreachable node", err))?;

    Ok(())
}
