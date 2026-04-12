use btc_network::crawler::{
    AsnNodeCountItem, CountNodesByAsnRow, CrawlEndpoint, CrawlRunCheckpoint, CrawlRunDetail,
    CrawlRunId, CrawlRunListItem, CrawlRunRecoveryPoint, CrawlerAnalyticsReader, CrawlerRepository,
    CrawlerRepositoryError, PersistedNodeObservation, RepositoryFuture, RepositoryRuntimeMetrics,
};
use sqlx_postgres::PgPool;

use crate::config::{PostgresConfigError, PostgresConnectionConfig};

mod analytics;
mod runs;
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

    fn insert_run_recovery_point<'a>(
        &'a self,
        recovery_point: CrawlRunRecoveryPoint,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async move { writes::insert_run_recovery_point(&self.pool, recovery_point).await })
    }

    fn get_run_checkpoint<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::get_run_checkpoint(&self.pool, run_id).await })
    }

    fn get_latest_active_run_checkpoint<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::get_latest_active_run_checkpoint(&self.pool).await })
    }

    fn get_latest_active_run_recovery_point<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunRecoveryPoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::get_latest_active_run_recovery_point(&self.pool).await })
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

    fn list_observed_endpoints_for_run<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlEndpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::list_observed_endpoints_for_run(&self.pool, run_id).await })
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
}

pub(super) fn map_postgres_err(
    context: &'static str,
    source: sqlx_core::Error,
) -> CrawlerRepositoryError {
    CrawlerRepositoryError::new(format!("{context}: {source}"))
}
