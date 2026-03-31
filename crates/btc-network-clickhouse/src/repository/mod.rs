mod analytics;
mod runs;
#[cfg(test)]
mod tests;
mod writes;

use btc_network::crawler::{
    AsnNodeCountItem, CountNodesByAsnRow, CrawlRunCheckpoint, CrawlRunDetail, CrawlRunId,
    CrawlRunListItem, CrawlerAnalyticsReader, CrawlerRepository, CrawlerRepositoryError,
    PersistedNodeObservation, RepositoryFuture,
};
use clickhouse::Client;

use crate::config::ClickHouseConnectionConfig;

const NODE_OBSERVATIONS_TABLE: &str = "node_observations";
const CRAWLER_RUN_CHECKPOINTS_TABLE: &str = "crawler_run_checkpoints";

pub struct ClickHouseCrawlerRepository {
    client: Client,
}

impl ClickHouseCrawlerRepository {
    pub fn new(config: &ClickHouseConnectionConfig) -> Self {
        Self {
            client: config.client(),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

impl CrawlerRepository for ClickHouseCrawlerRepository {
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
        Box::pin(
            async move { writes::insert_observations_stream(&self.client, observations).await },
        )
    }

    fn insert_run_checkpoint<'a>(
        &'a self,
        checkpoint: CrawlRunCheckpoint,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async move { writes::insert_run_checkpoint(&self.client, checkpoint).await })
    }

    fn get_run_checkpoint<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::get_run_checkpoint(&self.client, run_id).await })
    }

    fn list_runs<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move { runs::list_runs(&self.client).await })
    }

    fn count_nodes_by_asn<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::count_nodes_by_asn(&self.client).await })
    }
}

impl CrawlerAnalyticsReader for ClickHouseCrawlerRepository {
    fn list_crawl_runs<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunListItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::list_crawl_runs(&self.client, limit).await })
    }

    fn get_crawl_run<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
        checkpoint_limit: usize,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunDetail>, CrawlerRepositoryError>> {
        Box::pin(
            async move { analytics::get_crawl_run(&self.client, run_id, checkpoint_limit).await },
        )
    }

    fn count_nodes_by_asn<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError>> {
        Box::pin(async move { analytics::count_nodes_by_asn_limited(&self.client, limit).await })
    }
}

pub(super) fn map_clickhouse_err(
    context: &'static str,
) -> impl FnOnce(clickhouse::error::Error) -> CrawlerRepositoryError {
    move |err| CrawlerRepositoryError::new(format!("{context}: {err}"))
}
