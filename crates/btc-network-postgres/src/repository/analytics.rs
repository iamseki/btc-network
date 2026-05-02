use btc_network::crawler::{
    AsnNodeCountItem, CountNodesByAsnRow, CrawlRunCheckpointItem, CrawlRunDetail, CrawlRunId,
    CrawlRunListItem, CrawlerRepositoryError, FailureClassificationCount, LastRunAsnCountItem,
    LastRunAsnOrganizationCountItem, LastRunCountryCountItem, LastRunNetworkTypeCountItem,
    LastRunNodeSummaryItem, LastRunProtocolVersionCountItem, LastRunServicesCountItem,
    LastRunStartHeightCountItem, LastRunUserAgentCountItem, NetworkOutcomeCount,
};
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::{PgPool, Postgres};

use super::map_postgres_err;

const LATEST_FINISHED_RUN_ID_SQL: &str = "
SELECT run_id
FROM crawler_run_checkpoints
WHERE phase = 'finished'
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 1
";

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
        failure_classification,
        asn,
        asn_organization
    FROM node_observations
    ORDER BY endpoint, observed_at DESC, crawl_run_id DESC
) latest_by_endpoint
WHERE failure_classification IS NULL
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
    unique_nodes,
    persisted_observation_rows,
    writer_backlog
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
    COUNT(*) FILTER (WHERE failure_classification IS NULL) AS verified_nodes,
    COUNT(*) FILTER (WHERE failure_classification IS NOT NULL) AS failed_nodes,
    COALESCE(
        ROUND(
            (
                100.0 * COUNT(*) FILTER (WHERE failure_classification IS NULL)
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

#[derive(Debug)]
struct StringCountDbRow {
    value: String,
    node_count: i64,
}

#[derive(Debug)]
struct I32CountDbRow {
    value: i32,
    node_count: i64,
}

#[derive(Debug)]
struct AsnCountDbRow {
    asn: i32,
    asn_organization: Option<String>,
    node_count: i64,
}

#[derive(Debug)]
struct LastRunNodeSummaryDbRow {
    endpoint: String,
    network_type: String,
    protocol_version: i32,
    user_agent: String,
    services: String,
    start_height: i32,
    country: Option<String>,
    asn: Option<i32>,
    asn_organization: Option<String>,
}

enum StringDistributionColumn {
    Services,
    UserAgent,
    NetworkType,
    Country,
    AsnOrganization,
}

impl StringDistributionColumn {
    fn select_expr(&self) -> &'static str {
        match self {
            Self::Services => "services",
            Self::UserAgent => "user_agent",
            Self::NetworkType => "network_type",
            Self::Country => "country",
            Self::AsnOrganization => "asn_organization",
        }
    }

    fn context(&self) -> &'static str {
        match self {
            Self::Services => "list last-run services counts",
            Self::UserAgent => "list last-run user agent counts",
            Self::NetworkType => "list last-run network type counts",
            Self::Country => "list last-run country counts",
            Self::AsnOrganization => "list last-run ASN organization counts",
        }
    }
}

enum I32DistributionColumn {
    ProtocolVersion,
    StartHeight,
}

impl I32DistributionColumn {
    fn select_expr(&self) -> &'static str {
        match self {
            Self::ProtocolVersion => "protocol_version",
            Self::StartHeight => "start_height",
        }
    }

    fn context(&self) -> &'static str {
        match self {
            Self::ProtocolVersion => "list last-run protocol version counts",
            Self::StartHeight => "list last-run start height counts",
        }
    }
}

pub(super) async fn list_last_run_services(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError> {
    query_last_run_string_distribution(pool, StringDistributionColumn::Services, limit)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| LastRunServicesCountItem {
                    services: row.value,
                    node_count: row.node_count.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_last_run_protocol_versions(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError> {
    query_last_run_i32_distribution(pool, I32DistributionColumn::ProtocolVersion, limit)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| LastRunProtocolVersionCountItem {
                    protocol_version: row.value,
                    node_count: row.node_count.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_last_run_user_agents(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError> {
    query_last_run_string_distribution(pool, StringDistributionColumn::UserAgent, limit)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| LastRunUserAgentCountItem {
                    user_agent: row.value,
                    node_count: row.node_count.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_last_run_network_types(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError> {
    query_last_run_string_distribution(pool, StringDistributionColumn::NetworkType, limit)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| LastRunNetworkTypeCountItem {
                    network_type: row.value,
                    node_count: row.node_count.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_last_run_countries(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError> {
    query_last_run_string_distribution(pool, StringDistributionColumn::Country, limit)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| LastRunCountryCountItem {
                    country: row.value,
                    node_count: row.node_count.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_last_run_asns(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError> {
    let limit = limit.min(i64::MAX as usize) as i64;
    let rows = query::<Postgres>(&format!(
        "
SELECT
    asn,
    asn_organization,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = ({LATEST_FINISHED_RUN_ID_SQL})
  AND protocol_version IS NOT NULL
  AND asn IS NOT NULL
GROUP BY asn, asn_organization
ORDER BY node_count DESC, asn ASC
LIMIT $1
"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list last-run ASN counts", err))?;

    rows.into_iter()
        .map(
            |row| -> Result<LastRunAsnCountItem, CrawlerRepositoryError> {
                let db_row = AsnCountDbRow {
                    asn: row
                        .try_get("asn")
                        .map_err(|err| map_postgres_err("decode asn", err))?,
                    asn_organization: row
                        .try_get("asn_organization")
                        .map_err(|err| map_postgres_err("decode asn_organization", err))?,
                    node_count: row
                        .try_get("node_count")
                        .map_err(|err| map_postgres_err("decode node_count", err))?,
                };

                Ok(LastRunAsnCountItem {
                    asn: db_row.asn.max(0) as u32,
                    asn_organization: db_row.asn_organization,
                    node_count: db_row.node_count.max(0) as u64,
                })
            },
        )
        .collect()
}

pub(super) async fn list_last_run_start_heights(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError> {
    query_last_run_i32_distribution(pool, I32DistributionColumn::StartHeight, limit)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| LastRunStartHeightCountItem {
                    start_height: row.value,
                    node_count: row.node_count.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_last_run_asn_organizations(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError> {
    query_last_run_string_distribution(pool, StringDistributionColumn::AsnOrganization, limit)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| LastRunAsnOrganizationCountItem {
                    asn_organization: row.value,
                    node_count: row.node_count.max(0) as u64,
                })
                .collect()
        })
}

pub(super) async fn list_last_run_nodes(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<LastRunNodeSummaryItem>, CrawlerRepositoryError> {
    let limit = limit.min(i64::MAX as usize) as i64;
    let rows = query::<Postgres>(&format!(
        "
SELECT
    endpoint,
    network_type,
    protocol_version,
    user_agent,
    services,
    start_height,
    country,
    asn,
    asn_organization
FROM node_observations
WHERE crawl_run_id = ({LATEST_FINISHED_RUN_ID_SQL})
  AND protocol_version IS NOT NULL
ORDER BY observed_at DESC, endpoint ASC
LIMIT $1
"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list last-run nodes", err))?;

    rows.into_iter()
        .map(
            |row| -> Result<LastRunNodeSummaryItem, CrawlerRepositoryError> {
                let db_row = LastRunNodeSummaryDbRow {
                    endpoint: row
                        .try_get("endpoint")
                        .map_err(|err| map_postgres_err("decode endpoint", err))?,
                    network_type: row
                        .try_get("network_type")
                        .map_err(|err| map_postgres_err("decode network_type", err))?,
                    protocol_version: row
                        .try_get("protocol_version")
                        .map_err(|err| map_postgres_err("decode protocol_version", err))?,
                    user_agent: row
                        .try_get("user_agent")
                        .map_err(|err| map_postgres_err("decode user_agent", err))?,
                    services: row
                        .try_get("services")
                        .map_err(|err| map_postgres_err("decode services", err))?,
                    start_height: row
                        .try_get("start_height")
                        .map_err(|err| map_postgres_err("decode start_height", err))?,
                    country: row
                        .try_get("country")
                        .map_err(|err| map_postgres_err("decode country", err))?,
                    asn: row
                        .try_get("asn")
                        .map_err(|err| map_postgres_err("decode asn", err))?,
                    asn_organization: row
                        .try_get("asn_organization")
                        .map_err(|err| map_postgres_err("decode asn_organization", err))?,
                };

                Ok(LastRunNodeSummaryItem {
                    endpoint: db_row.endpoint,
                    network_type: db_row.network_type,
                    protocol_version: db_row.protocol_version,
                    user_agent: db_row.user_agent,
                    services: db_row.services,
                    start_height: db_row.start_height,
                    country: db_row.country,
                    asn: db_row.asn.map(|value| value.max(0) as u32),
                    asn_organization: db_row.asn_organization,
                })
            },
        )
        .collect()
}

async fn query_last_run_string_distribution(
    pool: &PgPool,
    column: StringDistributionColumn,
    limit: usize,
) -> Result<Vec<StringCountDbRow>, CrawlerRepositoryError> {
    let select_expr = column.select_expr();
    let sql = format!(
        "
SELECT
    {select_expr} AS value,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = ({LATEST_FINISHED_RUN_ID_SQL})
  AND protocol_version IS NOT NULL
  AND {select_expr} IS NOT NULL
GROUP BY {select_expr}
ORDER BY node_count DESC, value ASC
LIMIT $1
"
    );
    let limit = limit.min(i64::MAX as usize) as i64;
    let rows = query::<Postgres>(&sql)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|err| map_postgres_err(column.context(), err))?;

    rows.into_iter()
        .map(|row| -> Result<StringCountDbRow, CrawlerRepositoryError> {
            Ok(StringCountDbRow {
                value: row
                    .try_get("value")
                    .map_err(|err| map_postgres_err("decode distribution value", err))?,
                node_count: row
                    .try_get("node_count")
                    .map_err(|err| map_postgres_err("decode node_count", err))?,
            })
        })
        .collect()
}

async fn query_last_run_i32_distribution(
    pool: &PgPool,
    column: I32DistributionColumn,
    limit: usize,
) -> Result<Vec<I32CountDbRow>, CrawlerRepositoryError> {
    let select_expr = column.select_expr();
    let sql = format!(
        "
SELECT
    {select_expr} AS value,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = ({LATEST_FINISHED_RUN_ID_SQL})
  AND protocol_version IS NOT NULL
  AND {select_expr} IS NOT NULL
GROUP BY {select_expr}
ORDER BY node_count DESC, value ASC
LIMIT $1
"
    );
    let limit = limit.min(i64::MAX as usize) as i64;
    let rows = query::<Postgres>(&sql)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|err| map_postgres_err(column.context(), err))?;

    rows.into_iter()
        .map(|row| -> Result<I32CountDbRow, CrawlerRepositoryError> {
            Ok(I32CountDbRow {
                value: row
                    .try_get("value")
                    .map_err(|err| map_postgres_err("decode distribution value", err))?,
                node_count: row
                    .try_get("node_count")
                    .map_err(|err| map_postgres_err("decode node_count", err))?,
            })
        })
        .collect()
}
