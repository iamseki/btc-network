use btc_network::crawler::{
    AsnNodeCountItem, CountNodesByAsnRow, CrawlPhase, CrawlRunCheckpointItem, CrawlRunDetail,
    CrawlRunId, CrawlRunListItem, CrawlRunPhaseFilter, CrawlerRepositoryError,
    FailureClassificationCount, LastRunAsnCountItem, LastRunAsnOrganizationCountItem,
    LastRunCountryCountItem, LastRunNetworkTypeCountItem, LastRunNodePageCursor,
    LastRunNodeSummaryItem, LastRunNodeSummaryPage, LastRunProtocolVersionCountItem,
    LastRunServicesCountItem, LastRunStartHeightCountItem, LastRunUserAgentCountItem,
    NetworkOutcomeCount, SybilClusterType, SybilMetricSignal, SybilMetricsReport, SybilSignalKind,
    SybilSignalLevel,
};
use chrono::{DateTime, Utc};
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

const SYBIL_SIGNAL_CAP: usize = 20;
const SYBIL_TOP_CLUSTER_LIMIT: usize = 10;
const TOP_ASN_SHARE_WATCH_THRESHOLD: f64 = 0.08;
const ASN_HHI_WATCH_THRESHOLD: f64 = 0.15;
const TOP_PREFIX_SHARE_WATCH_THRESHOLD: f64 = 0.05;
const PREFIX_DENSITY_WATCH_THRESHOLD: f64 = 3.0;
const FINGERPRINT_UNIFORMITY_REVIEW_THRESHOLD: f64 = 0.80;
const HEIGHT_UNIFORMITY_REVIEW_THRESHOLD: f64 = 0.80;
const MIN_UNIFORM_CLUSTER_NODE_COUNT: u64 = 3;

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
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: usize,
) -> Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError> {
    query_count_nodes_by_asn_window(pool, start, end, limit)
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

async fn query_count_nodes_by_asn_window(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: usize,
) -> Result<Vec<CountNodesByAsnDbRow>, CrawlerRepositoryError> {
    let limit = limit.min(i64::MAX as usize) as i64;
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
    WHERE observed_at >= $1
      AND observed_at < $2
    ORDER BY endpoint, observed_at DESC, crawl_run_id DESC
) latest_by_endpoint
WHERE failure_classification IS NULL
GROUP BY asn, asn_organization
ORDER BY verified_nodes DESC, asn ASC NULLS FIRST
LIMIT $3
",
    )
    .bind(start)
    .bind(end)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("count nodes by ASN in window", err))?;

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

struct LastRunContextDbRow {
    run_id: CrawlRunId,
    phase: String,
    observed_at: DateTime<Utc>,
}

#[derive(Debug)]
struct SybilClusterCountDbRow {
    cluster_key: String,
    cluster_label: Option<String>,
    node_count: i64,
}

#[derive(Debug)]
struct SybilUniformityDbRow {
    cluster_key: String,
    cluster_label: Option<String>,
    node_count: i64,
    matching_node_count: i64,
    share: f64,
}

struct ScoredSybilSignal {
    signal: SybilMetricSignal,
    strength: f64,
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

pub(super) async fn get_last_run_sybil_metrics(
    pool: &PgPool,
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Option<SybilMetricsReport>, CrawlerRepositoryError> {
    let Some(context) = query_last_run_context(pool, &phase_filter).await? else {
        return Ok(None);
    };
    let verified_node_count = query_verified_node_count(pool, &context.run_id).await?;
    let mut signals = Vec::new();

    if verified_node_count > 0 {
        add_concentration_signals(pool, &context.run_id, verified_node_count, &mut signals).await?;
        add_uniformity_signals(pool, &context.run_id, &mut signals).await?;
        sort_and_cap_sybil_signals(&mut signals);
    }

    Ok(Some(SybilMetricsReport {
        run_id: context.run_id.to_string(),
        phase: context.phase,
        observed_at: context.observed_at.to_rfc3339(),
        verified_node_count,
        signals: signals
            .into_iter()
            .take(SYBIL_SIGNAL_CAP)
            .map(|value| value.signal)
            .collect(),
    }))
}

pub(super) async fn list_last_run_services(
    pool: &PgPool,
    limit: usize,
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError> {
    query_run_string_distribution(
        pool,
        StringDistributionColumn::Services,
        latest_run_id_sql(&phase_filter),
        limit,
    )
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
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError> {
    query_run_i32_distribution(
        pool,
        I32DistributionColumn::ProtocolVersion,
        latest_run_id_sql(&phase_filter),
        limit,
    )
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
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError> {
    query_run_string_distribution(
        pool,
        StringDistributionColumn::UserAgent,
        latest_run_id_sql(&phase_filter),
        limit,
    )
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
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError> {
    query_run_string_distribution(
        pool,
        StringDistributionColumn::NetworkType,
        latest_run_id_sql(&phase_filter),
        limit,
    )
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
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError> {
    query_run_string_distribution(
        pool,
        StringDistributionColumn::Country,
        latest_run_id_sql(&phase_filter),
        limit,
    )
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
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError> {
    let limit = limit.min(i64::MAX as usize) as i64;
    let run_id_sql = latest_run_id_sql(&phase_filter);
    let rows = query::<Postgres>(&format!(
        "
SELECT
    asn,
    asn_organization,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = ({run_id_sql})
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
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError> {
    query_run_i32_distribution(
        pool,
        I32DistributionColumn::StartHeight,
        latest_run_id_sql(&phase_filter),
        limit,
    )
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
    phase_filter: CrawlRunPhaseFilter,
) -> Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError> {
    query_run_string_distribution(
        pool,
        StringDistributionColumn::AsnOrganization,
        latest_run_id_sql(&phase_filter),
        limit,
    )
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
    cursor: Option<LastRunNodePageCursor>,
) -> Result<LastRunNodeSummaryPage, CrawlerRepositoryError> {
    let query_limit = limit.saturating_add(1).min(i64::MAX as usize) as i64;
    let cursor_observed_at = cursor.as_ref().map(|value| value.observed_at);
    let cursor_endpoint = cursor.as_ref().map(|value| value.endpoint.clone());
    let cursor_id = cursor.as_ref().map(|value| value.node_observation_id);
    let rows = query::<Postgres>(&format!(
        "
SELECT
    node_observation_id,
    observed_at,
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
  AND (
    $2::TIMESTAMPTZ IS NULL
    OR observed_at < $2
    OR (observed_at = $2 AND endpoint > $3)
    OR (observed_at = $2 AND endpoint = $3 AND node_observation_id < $4)
  )
ORDER BY observed_at DESC, endpoint ASC, node_observation_id DESC
LIMIT $1
"
    ))
    .bind(query_limit)
    .bind(cursor_observed_at)
    .bind(cursor_endpoint)
    .bind(cursor_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_postgres_err("list last-run nodes", err))?;

    let has_next_page = rows.len() > limit;
    let rows = rows.into_iter().take(limit).collect::<Vec<_>>();
    let next_cursor = if has_next_page {
        rows.last()
            .map(
                |row| -> Result<LastRunNodePageCursor, CrawlerRepositoryError> {
                    Ok(LastRunNodePageCursor {
                        observed_at: row
                            .try_get("observed_at")
                            .map_err(|err| map_postgres_err("decode observed_at", err))?,
                        endpoint: row
                            .try_get("endpoint")
                            .map_err(|err| map_postgres_err("decode endpoint", err))?,
                        node_observation_id: row
                            .try_get("node_observation_id")
                            .map_err(|err| map_postgres_err("decode node_observation_id", err))?,
                    })
                },
            )
            .transpose()?
    } else {
        None
    };

    let items = rows
        .into_iter()
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
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LastRunNodeSummaryPage { items, next_cursor })
}

async fn query_last_run_context(
    pool: &PgPool,
    phase_filter: &CrawlRunPhaseFilter,
) -> Result<Option<LastRunContextDbRow>, CrawlerRepositoryError> {
    let where_clause = latest_run_where_clause(phase_filter);
    let sql = format!(
        "
SELECT
    run_id,
    phase,
    checkpointed_at AS observed_at
FROM crawler_run_checkpoints
{where_clause}
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 1
"
    );
    let row = query::<Postgres>(&sql)
        .fetch_optional(pool)
        .await
        .map_err(|err| map_postgres_err("get last-run sybil metrics context", err))?;

    row.map(
        |row| -> Result<LastRunContextDbRow, CrawlerRepositoryError> {
            let run_id = row
                .try_get("run_id")
                .map_err(|err| map_postgres_err("decode run_id", err))?;
            Ok(LastRunContextDbRow {
                run_id: CrawlRunId::new(run_id),
                phase: row
                    .try_get("phase")
                    .map_err(|err| map_postgres_err("decode phase", err))?,
                observed_at: row
                    .try_get("observed_at")
                    .map_err(|err| map_postgres_err("decode observed_at", err))?,
            })
        },
    )
    .transpose()
}

async fn query_verified_node_count(
    pool: &PgPool,
    run_id: &CrawlRunId,
) -> Result<u64, CrawlerRepositoryError> {
    let row = query::<Postgres>(
        "
SELECT COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = $1
  AND protocol_version IS NOT NULL
  AND failure_classification IS NULL
",
    )
    .bind(run_id.as_uuid())
    .fetch_one(pool)
    .await
    .map_err(|err| map_postgres_err("count last-run verified nodes", err))?;
    let node_count = row
        .try_get::<i64, _>("node_count")
        .map_err(|err| map_postgres_err("decode verified node count", err))?;

    Ok(node_count.max(0) as u64)
}

async fn add_concentration_signals(
    pool: &PgPool,
    run_id: &CrawlRunId,
    verified_node_count: u64,
    signals: &mut Vec<ScoredSybilSignal>,
) -> Result<(), CrawlerRepositoryError> {
    let asn_rows = query_asn_sybil_clusters(pool, run_id, usize::MAX).await?;
    let prefix_rows = query_string_sybil_clusters(
        pool,
        run_id,
        "prefix",
        "prefix",
        "prefix",
        SYBIL_TOP_CLUSTER_LIMIT,
    )
    .await?;
    let country_rows = query_string_sybil_clusters(
        pool,
        run_id,
        "country",
        "country",
        "country",
        SYBIL_TOP_CLUSTER_LIMIT,
    )
    .await?;

    if let Some(top_asn) = asn_rows.first() {
        push_share_signal(
            signals,
            SybilSignalKind::TopAsnShare,
            SybilClusterType::Asn,
            top_asn,
            verified_node_count,
            Some(TOP_ASN_SHARE_WATCH_THRESHOLD),
            SybilSignalLevel::Watch,
        );
    }

    let asn_hhi = hhi(&asn_rows, verified_node_count);
    if asn_hhi >= ASN_HHI_WATCH_THRESHOLD {
        signals.push(ScoredSybilSignal {
            signal: SybilMetricSignal {
                level: SybilSignalLevel::Watch,
                kind: SybilSignalKind::AsnHhi,
                cluster_type: SybilClusterType::Asn,
                cluster_key: "all_asns".to_string(),
                cluster_label: None,
                node_count: verified_node_count,
                share: None,
                threshold: Some(ASN_HHI_WATCH_THRESHOLD),
                hhi: Some(round_ratio(asn_hhi)),
                density: None,
            },
            strength: asn_hhi / ASN_HHI_WATCH_THRESHOLD,
        });
    }

    if let Some(top_prefix) = prefix_rows.first() {
        push_share_signal(
            signals,
            SybilSignalKind::TopPrefixShare,
            SybilClusterType::Prefix,
            top_prefix,
            verified_node_count,
            Some(TOP_PREFIX_SHARE_WATCH_THRESHOLD),
            SybilSignalLevel::Watch,
        );

        let density = top_prefix.node_count.max(0) as f64;
        if density >= PREFIX_DENSITY_WATCH_THRESHOLD {
            signals.push(ScoredSybilSignal {
                signal: SybilMetricSignal {
                    level: SybilSignalLevel::Watch,
                    kind: SybilSignalKind::PrefixDensity,
                    cluster_type: SybilClusterType::Prefix,
                    cluster_key: top_prefix.cluster_key.clone(),
                    cluster_label: top_prefix.cluster_label.clone(),
                    node_count: top_prefix.node_count.max(0) as u64,
                    share: Some(round_ratio(share(
                        top_prefix.node_count.max(0) as u64,
                        verified_node_count,
                    ))),
                    threshold: Some(PREFIX_DENSITY_WATCH_THRESHOLD),
                    hhi: None,
                    density: Some(density),
                },
                strength: density / PREFIX_DENSITY_WATCH_THRESHOLD,
            });
        }
    }

    if let Some(top_country) = country_rows.first() {
        push_share_signal(
            signals,
            SybilSignalKind::TopCountryShare,
            SybilClusterType::Country,
            top_country,
            verified_node_count,
            None,
            SybilSignalLevel::Info,
        );
    }

    Ok(())
}

async fn add_uniformity_signals(
    pool: &PgPool,
    run_id: &CrawlRunId,
    signals: &mut Vec<ScoredSybilSignal>,
) -> Result<(), CrawlerRepositoryError> {
    for row in query_fingerprint_uniformity(
        pool,
        run_id,
        "asn",
        "asn",
        "MIN(asn_organization) OVER (PARTITION BY asn)",
    )
    .await?
    {
        push_uniformity_signal(
            signals,
            SybilSignalKind::ClusterFingerprintUniformity,
            SybilClusterType::Asn,
            &row,
            FINGERPRINT_UNIFORMITY_REVIEW_THRESHOLD,
        );
    }
    for row in query_fingerprint_uniformity(pool, run_id, "prefix", "prefix", "prefix").await? {
        push_uniformity_signal(
            signals,
            SybilSignalKind::ClusterFingerprintUniformity,
            SybilClusterType::Prefix,
            &row,
            FINGERPRINT_UNIFORMITY_REVIEW_THRESHOLD,
        );
    }
    for row in query_height_uniformity(
        pool,
        run_id,
        "asn",
        "asn",
        "MIN(asn_organization) OVER (PARTITION BY asn)",
    )
    .await?
    {
        push_uniformity_signal(
            signals,
            SybilSignalKind::ClusterHeightUniformity,
            SybilClusterType::Asn,
            &row,
            HEIGHT_UNIFORMITY_REVIEW_THRESHOLD,
        );
    }
    for row in query_height_uniformity(pool, run_id, "prefix", "prefix", "prefix").await? {
        push_uniformity_signal(
            signals,
            SybilSignalKind::ClusterHeightUniformity,
            SybilClusterType::Prefix,
            &row,
            HEIGHT_UNIFORMITY_REVIEW_THRESHOLD,
        );
    }

    Ok(())
}

async fn query_asn_sybil_clusters(
    pool: &PgPool,
    run_id: &CrawlRunId,
    limit: usize,
) -> Result<Vec<SybilClusterCountDbRow>, CrawlerRepositoryError> {
    let sql = "
SELECT
    asn::text AS cluster_key,
    MIN(asn_organization) AS cluster_label,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = $1
  AND protocol_version IS NOT NULL
  AND failure_classification IS NULL
  AND asn IS NOT NULL
GROUP BY asn
ORDER BY node_count DESC, asn ASC
LIMIT $2
";
    query_sybil_cluster_counts(pool, sql, "list sybil ASN clusters", run_id, limit).await
}

async fn query_string_sybil_clusters(
    pool: &PgPool,
    run_id: &CrawlRunId,
    select_expr: &str,
    label_expr: &str,
    context_label: &'static str,
    limit: usize,
) -> Result<Vec<SybilClusterCountDbRow>, CrawlerRepositoryError> {
    let sql = format!(
        "
SELECT
    {select_expr} AS cluster_key,
    {label_expr} AS cluster_label,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = $1
  AND protocol_version IS NOT NULL
  AND failure_classification IS NULL
  AND {select_expr} IS NOT NULL
GROUP BY {select_expr}, {label_expr}
ORDER BY node_count DESC, cluster_key ASC
LIMIT $2
"
    );
    query_sybil_cluster_counts(pool, &sql, context_label, run_id, limit).await
}

async fn query_sybil_cluster_counts(
    pool: &PgPool,
    sql: &str,
    context: &'static str,
    run_id: &CrawlRunId,
    limit: usize,
) -> Result<Vec<SybilClusterCountDbRow>, CrawlerRepositoryError> {
    let limit = limit.min(i64::MAX as usize) as i64;
    let rows = query::<Postgres>(sql)
        .bind(run_id.as_uuid())
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|err| map_postgres_err(context, err))?;

    rows.into_iter()
        .map(
            |row| -> Result<SybilClusterCountDbRow, CrawlerRepositoryError> {
                Ok(SybilClusterCountDbRow {
                    cluster_key: row
                        .try_get("cluster_key")
                        .map_err(|err| map_postgres_err("decode cluster_key", err))?,
                    cluster_label: row
                        .try_get("cluster_label")
                        .map_err(|err| map_postgres_err("decode cluster_label", err))?,
                    node_count: row
                        .try_get("node_count")
                        .map_err(|err| map_postgres_err("decode node_count", err))?,
                })
            },
        )
        .collect()
}

async fn query_fingerprint_uniformity(
    pool: &PgPool,
    run_id: &CrawlRunId,
    cluster_expr: &str,
    key_expr: &str,
    label_expr: &str,
) -> Result<Vec<SybilUniformityDbRow>, CrawlerRepositoryError> {
    let sql = format!(
        "
WITH verified AS (
    SELECT
        {key_expr}::text AS cluster_key,
        {label_expr} AS cluster_label,
        protocol_version,
        services,
        user_agent,
        relay
    FROM node_observations
    WHERE crawl_run_id = $1
      AND protocol_version IS NOT NULL
      AND failure_classification IS NULL
      AND {cluster_expr} IS NOT NULL
),
cluster_counts AS (
    SELECT cluster_key, cluster_label, COUNT(*) AS node_count
    FROM verified
    GROUP BY cluster_key, cluster_label
),
fingerprint_counts AS (
    SELECT
        cluster_key,
        cluster_label,
        protocol_version,
        services,
        user_agent,
        relay,
        COUNT(*) AS matching_node_count
    FROM verified
    GROUP BY cluster_key, cluster_label, protocol_version, services, user_agent, relay
)
SELECT
    cluster_counts.cluster_key,
    cluster_counts.cluster_label,
    cluster_counts.node_count,
    MAX(fingerprint_counts.matching_node_count) AS matching_node_count,
    (
        MAX(fingerprint_counts.matching_node_count)::double precision
        / NULLIF(cluster_counts.node_count, 0)::double precision
    ) AS share
FROM cluster_counts
JOIN fingerprint_counts
  ON fingerprint_counts.cluster_key = cluster_counts.cluster_key
 AND COALESCE(fingerprint_counts.cluster_label, '') = COALESCE(cluster_counts.cluster_label, '')
WHERE cluster_counts.node_count >= $2
GROUP BY cluster_counts.cluster_key, cluster_counts.cluster_label, cluster_counts.node_count
HAVING (
    MAX(fingerprint_counts.matching_node_count)::double precision
    / NULLIF(cluster_counts.node_count, 0)::double precision
) >= $3
ORDER BY share DESC, node_count DESC, cluster_key ASC
LIMIT $4
"
    );
    query_uniformity_rows(
        pool,
        &sql,
        "list sybil fingerprint uniformity clusters",
        run_id,
        FINGERPRINT_UNIFORMITY_REVIEW_THRESHOLD,
    )
    .await
}

async fn query_height_uniformity(
    pool: &PgPool,
    run_id: &CrawlRunId,
    cluster_expr: &str,
    key_expr: &str,
    label_expr: &str,
) -> Result<Vec<SybilUniformityDbRow>, CrawlerRepositoryError> {
    let sql = format!(
        "
WITH verified AS (
    SELECT
        {key_expr}::text AS cluster_key,
        {label_expr} AS cluster_label,
        FLOOR(start_height::double precision / 100.0)::integer AS height_bucket
    FROM node_observations
    WHERE crawl_run_id = $1
      AND protocol_version IS NOT NULL
      AND failure_classification IS NULL
      AND start_height IS NOT NULL
      AND {cluster_expr} IS NOT NULL
),
cluster_counts AS (
    SELECT cluster_key, cluster_label, COUNT(*) AS node_count
    FROM verified
    GROUP BY cluster_key, cluster_label
),
height_counts AS (
    SELECT cluster_key, cluster_label, height_bucket, COUNT(*) AS matching_node_count
    FROM verified
    GROUP BY cluster_key, cluster_label, height_bucket
)
SELECT
    cluster_counts.cluster_key,
    cluster_counts.cluster_label,
    cluster_counts.node_count,
    MAX(height_counts.matching_node_count) AS matching_node_count,
    (
        MAX(height_counts.matching_node_count)::double precision
        / NULLIF(cluster_counts.node_count, 0)::double precision
    ) AS share
FROM cluster_counts
JOIN height_counts
  ON height_counts.cluster_key = cluster_counts.cluster_key
 AND COALESCE(height_counts.cluster_label, '') = COALESCE(cluster_counts.cluster_label, '')
WHERE cluster_counts.node_count >= $2
GROUP BY cluster_counts.cluster_key, cluster_counts.cluster_label, cluster_counts.node_count
HAVING (
    MAX(height_counts.matching_node_count)::double precision
    / NULLIF(cluster_counts.node_count, 0)::double precision
) >= $3
ORDER BY share DESC, node_count DESC, cluster_key ASC
LIMIT $4
"
    );
    query_uniformity_rows(
        pool,
        &sql,
        "list sybil height uniformity clusters",
        run_id,
        HEIGHT_UNIFORMITY_REVIEW_THRESHOLD,
    )
    .await
}

async fn query_uniformity_rows(
    pool: &PgPool,
    sql: &str,
    context: &'static str,
    run_id: &CrawlRunId,
    threshold: f64,
) -> Result<Vec<SybilUniformityDbRow>, CrawlerRepositoryError> {
    let rows = query::<Postgres>(sql)
        .bind(run_id.as_uuid())
        .bind(MIN_UNIFORM_CLUSTER_NODE_COUNT as i64)
        .bind(threshold)
        .bind(SYBIL_TOP_CLUSTER_LIMIT.min(i64::MAX as usize) as i64)
        .fetch_all(pool)
        .await
        .map_err(|err| map_postgres_err(context, err))?;

    rows.into_iter()
        .map(
            |row| -> Result<SybilUniformityDbRow, CrawlerRepositoryError> {
                Ok(SybilUniformityDbRow {
                    cluster_key: row
                        .try_get("cluster_key")
                        .map_err(|err| map_postgres_err("decode cluster_key", err))?,
                    cluster_label: row
                        .try_get("cluster_label")
                        .map_err(|err| map_postgres_err("decode cluster_label", err))?,
                    node_count: row
                        .try_get("node_count")
                        .map_err(|err| map_postgres_err("decode node_count", err))?,
                    matching_node_count: row
                        .try_get("matching_node_count")
                        .map_err(|err| map_postgres_err("decode matching_node_count", err))?,
                    share: row
                        .try_get("share")
                        .map_err(|err| map_postgres_err("decode share", err))?,
                })
            },
        )
        .collect()
}

fn push_share_signal(
    signals: &mut Vec<ScoredSybilSignal>,
    kind: SybilSignalKind,
    cluster_type: SybilClusterType,
    row: &SybilClusterCountDbRow,
    verified_node_count: u64,
    threshold: Option<f64>,
    threshold_level: SybilSignalLevel,
) {
    let share = share(row.node_count.max(0) as u64, verified_node_count);
    let level = threshold
        .filter(|threshold| share >= *threshold)
        .map(|_| threshold_level)
        .unwrap_or(SybilSignalLevel::Info);
    let strength = threshold
        .map(|threshold| share / threshold)
        .unwrap_or(share);

    signals.push(ScoredSybilSignal {
        signal: SybilMetricSignal {
            level,
            kind,
            cluster_type,
            cluster_key: row.cluster_key.clone(),
            cluster_label: row.cluster_label.clone(),
            node_count: row.node_count.max(0) as u64,
            share: Some(round_ratio(share)),
            threshold,
            hhi: None,
            density: None,
        },
        strength,
    });
}

fn push_uniformity_signal(
    signals: &mut Vec<ScoredSybilSignal>,
    kind: SybilSignalKind,
    cluster_type: SybilClusterType,
    row: &SybilUniformityDbRow,
    threshold: f64,
) {
    signals.push(ScoredSybilSignal {
        signal: SybilMetricSignal {
            level: SybilSignalLevel::Review,
            kind,
            cluster_type,
            cluster_key: row.cluster_key.clone(),
            cluster_label: row.cluster_label.clone(),
            node_count: row.node_count.max(0) as u64,
            share: Some(round_ratio(row.share)),
            threshold: Some(threshold),
            hhi: None,
            density: None,
        },
        strength: (row.matching_node_count.max(0) as f64) / (row.node_count.max(1) as f64),
    });
}

fn hhi(rows: &[SybilClusterCountDbRow], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }

    rows.iter()
        .map(|row| share(row.node_count.max(0) as u64, total).powi(2))
        .sum()
}

fn share(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }

    numerator as f64 / denominator as f64
}

fn round_ratio(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

fn sort_and_cap_sybil_signals(signals: &mut Vec<ScoredSybilSignal>) {
    signals.sort_by(|left, right| {
        sybil_level_rank(left.signal.level)
            .cmp(&sybil_level_rank(right.signal.level))
            .then_with(|| right.strength.total_cmp(&left.strength))
            .then_with(|| {
                sybil_kind_rank(left.signal.kind).cmp(&sybil_kind_rank(right.signal.kind))
            })
            .then_with(|| left.signal.cluster_key.cmp(&right.signal.cluster_key))
    });
    signals.truncate(SYBIL_SIGNAL_CAP);
}

fn sybil_level_rank(level: SybilSignalLevel) -> u8 {
    match level {
        SybilSignalLevel::Review => 0,
        SybilSignalLevel::Watch => 1,
        SybilSignalLevel::Info => 2,
    }
}

fn sybil_kind_rank(kind: SybilSignalKind) -> u8 {
    match kind {
        SybilSignalKind::ClusterFingerprintUniformity => 0,
        SybilSignalKind::ClusterHeightUniformity => 1,
        SybilSignalKind::TopPrefixShare => 2,
        SybilSignalKind::TopAsnShare => 3,
        SybilSignalKind::AsnHhi => 4,
        SybilSignalKind::PrefixDensity => 5,
        SybilSignalKind::TopCountryShare => 6,
    }
}

async fn query_run_string_distribution(
    pool: &PgPool,
    column: StringDistributionColumn,
    run_id_sql: String,
    limit: usize,
) -> Result<Vec<StringCountDbRow>, CrawlerRepositoryError> {
    let select_expr = column.select_expr();
    let sql = format!(
        "
SELECT
    {select_expr} AS value,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = ({run_id_sql})
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

fn latest_run_id_sql(phase_filter: &CrawlRunPhaseFilter) -> String {
    let where_clause = latest_run_where_clause(phase_filter);

    format!(
        "
SELECT run_id
FROM crawler_run_checkpoints
{where_clause}
ORDER BY checkpointed_at DESC, checkpoint_sequence DESC
LIMIT 1
"
    )
}

fn latest_run_where_clause(phase_filter: &CrawlRunPhaseFilter) -> String {
    match phase_filter {
        CrawlRunPhaseFilter::Finished => "WHERE phase = 'finished'".to_string(),
        CrawlRunPhaseFilter::Any => String::new(),
        CrawlRunPhaseFilter::OneOf(phases) => {
            let phases = phases
                .iter()
                .map(|phase| format!("'{}'", crawl_phase_sql_value(*phase)))
                .collect::<Vec<_>>();

            if phases.is_empty() {
                "WHERE phase = 'finished'".to_string()
            } else {
                format!("WHERE phase IN ({})", phases.join(", "))
            }
        }
    }
}

fn crawl_phase_sql_value(phase: CrawlPhase) -> &'static str {
    match phase {
        CrawlPhase::Bootstrap => "bootstrap",
        CrawlPhase::Crawling => "crawling",
        CrawlPhase::Draining => "draining",
        CrawlPhase::Finished => "finished",
    }
}

async fn query_run_i32_distribution(
    pool: &PgPool,
    column: I32DistributionColumn,
    run_id_sql: String,
    limit: usize,
) -> Result<Vec<I32CountDbRow>, CrawlerRepositoryError> {
    let select_expr = column.select_expr();
    let sql = format!(
        "
SELECT
    {select_expr} AS value,
    COUNT(*) AS node_count
FROM node_observations
WHERE crawl_run_id = ({run_id_sql})
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
