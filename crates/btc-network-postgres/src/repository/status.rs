use std::collections::HashMap;

use btc_network::crawler::CrawlerRepositoryError;
use btc_network::status::{NodeStatus, NodeStatusItem, NodeStatusRecord};
use chrono::{DateTime, Duration, Utc};
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::{PgPool, Postgres};

use super::map_postgres_err;

const DEFAULT_HISTORY_DAYS: i64 = 365;

pub(super) async fn insert_node_status(
    pool: &PgPool,
    record: NodeStatusRecord,
) -> Result<(), CrawlerRepositoryError> {
    query::<Postgres>(
        r#"
INSERT INTO node_status (
    endpoint,
    label,
    description,
    status,
    checked_at,
    message
)
VALUES ($1, $2, $3, $4::"NODE_STATUS", $5, $6)
"#,
    )
    .bind(record.endpoint)
    .bind(record.label)
    .bind(record.description)
    .bind(record.status.as_storage_str())
    .bind(record.checked_at)
    .bind(record.message)
    .execute(pool)
    .await
    .map_err(|err| map_postgres_err("insert node status", err))?;

    Ok(())
}

pub(super) async fn delete_node_status_older_than(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
) -> Result<u64, CrawlerRepositoryError> {
    let result = query::<Postgres>(
        "
DELETE FROM node_status
WHERE checked_at < $1
",
    )
    .bind(cutoff)
    .execute(pool)
    .await
    .map_err(|err| map_postgres_err("delete old node status rows", err))?;

    Ok(result.rows_affected())
}

pub(super) async fn list_node_status(
    pool: &PgPool,
) -> Result<Vec<NodeStatusItem>, CrawlerRepositoryError> {
    let history_since = Utc::now() - Duration::days(DEFAULT_HISTORY_DAYS);
    let latest_rows = query::<Postgres>(
        "
SELECT DISTINCT ON (endpoint)
    endpoint,
    label,
    description,
    status::text AS status,
    checked_at,
    message
FROM node_status
ORDER BY endpoint, checked_at DESC, node_status_id DESC
",
    )
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list latest node status rows", err))?;

    let history_rows = query::<Postgres>(
        "
SELECT
    endpoint,
    label,
    description,
    status::text AS status,
    checked_at,
    message
FROM node_status
WHERE checked_at >= $1
ORDER BY endpoint, checked_at DESC, node_status_id DESC
",
    )
    .bind(history_since)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list node status history rows", err))?;

    let mut history_by_endpoint = HashMap::<String, Vec<NodeStatusRecord>>::new();
    for row in history_rows {
        let record = row_to_status_record(row)?;
        history_by_endpoint
            .entry(record.endpoint.clone())
            .or_default()
            .push(record);
    }

    latest_rows
        .into_iter()
        .map(row_to_status_record)
        .map(|latest| {
            latest.map(|latest| {
                let history = history_by_endpoint
                    .remove(&latest.endpoint)
                    .unwrap_or_else(Vec::new);
                NodeStatusItem::from_latest_and_history(latest, history)
            })
        })
        .collect()
}

fn row_to_status_record(
    row: sqlx_postgres::PgRow,
) -> Result<NodeStatusRecord, CrawlerRepositoryError> {
    let status = row
        .try_get::<String, _>("status")
        .map_err(|err| map_postgres_err("decode node status", err))?;
    let status = NodeStatus::from_storage_str(&status)
        .map_err(|err| CrawlerRepositoryError::new(format!("decode node status: {err}")))?;

    Ok(NodeStatusRecord {
        endpoint: row
            .try_get("endpoint")
            .map_err(|err| map_postgres_err("decode status endpoint", err))?,
        label: row
            .try_get("label")
            .map_err(|err| map_postgres_err("decode status label", err))?,
        description: row
            .try_get("description")
            .map_err(|err| map_postgres_err("decode status description", err))?,
        status,
        checked_at: row
            .try_get("checked_at")
            .map_err(|err| map_postgres_err("decode status checked_at", err))?,
        message: row
            .try_get("message")
            .map_err(|err| map_postgres_err("decode status message", err))?,
    })
}
