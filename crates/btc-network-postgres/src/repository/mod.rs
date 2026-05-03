use btc_network::crawler::{
    AsnNodeCountItem, CountNodesByAsnRow, CrawlEndpoint, CrawlRunCheckpoint, CrawlRunDetail,
    CrawlRunId, CrawlRunListItem, CrawlerAnalyticsReader, CrawlerRepository,
    CrawlerRepositoryError, LastRunAsnCountItem, LastRunAsnOrganizationCountItem,
    LastRunCountryCountItem, LastRunNetworkTypeCountItem, LastRunNodeSummaryItem,
    LastRunProtocolVersionCountItem, LastRunServicesCountItem, LastRunStartHeightCountItem,
    LastRunUserAgentCountItem, PersistedNodeObservation, RepositoryFuture,
    RepositoryRuntimeMetrics, UnreachableNodeUpdate,
};
use btc_network::status::{NodeStatusItem, NodeStatusRecord};
use chrono::{DateTime, Utc};
use sqlx_postgres::PgPool;

use crate::config::{PostgresConfigError, PostgresConnectionConfig};

mod analytics;
mod runs;
mod status;
mod unreachable;
mod writes;

/// PostgreSQL-backed implementation of the crawler write and analytics ports.
pub struct PostgresCrawlerRepository {
    pool: PgPool,
    max_connections: usize,
}

impl PostgresCrawlerRepository {
    pub fn new(config: &PostgresConnectionConfig) -> Result<Self, PostgresConfigError> {
        Ok(Self {
            pool: config.pool()?,
            max_connections: config.max_connections(),
        })
    }

    pub fn with_pool(pool: PgPool) -> Self {
        Self {
            pool,
            max_connections: 0,
        }
    }
}

impl CrawlerRepository for PostgresCrawlerRepository {
    fn insert_observation<'a>(
        &'a self,
        observation: PersistedNodeObservation,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        self.insert_observations_stream(vec![observation])
    }

    fn insert_observations_stream<'a>(
        &'a self,
        observations: Vec<PersistedNodeObservation>,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async move { writes::insert_observations_stream(&self.pool, observations).await })
    }

    fn insert_run_checkpoint<'a>(
        &'a self,
        checkpoint: CrawlRunCheckpoint,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async move { writes::insert_run_checkpoint(&self.pool, checkpoint).await })
    }

    fn get_run_checkpoint<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::get_run_checkpoint(&self.pool, run_id).await })
    }

    fn list_runs<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::list_runs(&self.pool).await })
    }

    fn count_nodes_by_asn<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::count_nodes_by_asn(&self.pool).await })
    }

    fn load_unreachable_nodes<'a>(
        &'a self,
        since: DateTime<Utc>,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlEndpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { unreachable::load_unreachable_nodes(&self.pool, since).await })
    }

    fn apply_unreachable_node_updates<'a>(
        &'a self,
        updates: Vec<UnreachableNodeUpdate>,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(
            async move { unreachable::apply_unreachable_node_updates(&self.pool, updates).await },
        )
    }

    fn insert_node_status<'a>(
        &'a self,
        record: NodeStatusRecord,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async move { status::insert_node_status(&self.pool, record).await })
    }

    fn delete_node_status_older_than<'a>(
        &'a self,
        cutoff: DateTime<Utc>,
    ) -> RepositoryFuture<'a, Result<u64, CrawlerRepositoryError>> {
        Box::pin(async move { status::delete_node_status_older_than(&self.pool, cutoff).await })
    }

    fn runtime_metrics(&self) -> RepositoryRuntimeMetrics {
        let pool_size = self.pool.size() as usize;
        let pool_idle = self.pool.num_idle() as usize;

        RepositoryRuntimeMetrics {
            pool_max_connections: (self.max_connections > 0).then_some(self.max_connections),
            pool_size: Some(pool_size),
            pool_idle: Some(pool_idle),
            pool_acquired: Some(pool_size.saturating_sub(pool_idle)),
        }
    }
}

impl CrawlerAnalyticsReader for PostgresCrawlerRepository {
    fn list_crawl_runs<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunListItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::list_crawl_runs(&self.pool, limit).await })
    }

    fn get_crawl_run<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
        checkpoint_limit: usize,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunDetail>, CrawlerRepositoryError>> {
        Box::pin(
            async move { analytics::get_crawl_run(&self.pool, run_id, checkpoint_limit).await },
        )
    }

    fn count_nodes_by_asn<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::count_nodes_by_asn_limited(&self.pool, limit).await })
    }

    fn list_last_run_services<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::list_last_run_services(&self.pool, limit).await })
    }

    fn list_last_run_protocol_versions<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move { analytics::list_last_run_protocol_versions(&self.pool, limit).await })
    }

    fn list_last_run_user_agents<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::list_last_run_user_agents(&self.pool, limit).await })
    }

    fn list_last_run_network_types<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move { analytics::list_last_run_network_types(&self.pool, limit).await })
    }

    fn list_last_run_countries<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::list_last_run_countries(&self.pool, limit).await })
    }

    fn list_last_run_asns<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::list_last_run_asns(&self.pool, limit).await })
    }

    fn list_last_run_start_heights<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move { analytics::list_last_run_start_heights(&self.pool, limit).await })
    }

    fn list_last_run_asn_organizations<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError>>
    {
        Box::pin(async move { analytics::list_last_run_asn_organizations(&self.pool, limit).await })
    }

    fn list_last_run_nodes<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunNodeSummaryItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::list_last_run_nodes(&self.pool, limit).await })
    }

    fn list_node_status<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<NodeStatusItem>, CrawlerRepositoryError>> {
        Box::pin(async move { status::list_node_status(&self.pool).await })
    }
}

pub(super) fn map_postgres_err(
    context: &'static str,
    source: sqlx_core::Error,
) -> CrawlerRepositoryError {
    CrawlerRepositoryError::new(format!("{context}: {source}"))
}
