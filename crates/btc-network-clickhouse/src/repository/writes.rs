use btc_network::crawler::{CrawlRunCheckpoint, CrawlerRepositoryError, PersistedNodeObservation};
use clickhouse::Client;

use crate::rows::{
    NodeObservationRow, RunCheckpointRow, from_checkpoint, from_persisted_observation,
};

use super::{CRAWLER_RUN_CHECKPOINTS_TABLE, NODE_OBSERVATIONS_TABLE, map_clickhouse_err};

pub(super) async fn insert_observations_stream(
    client: &Client,
    observations: Vec<PersistedNodeObservation>,
) -> Result<(), CrawlerRepositoryError> {
    let mut insert = client
        .insert::<NodeObservationRow>(NODE_OBSERVATIONS_TABLE)
        .await
        .map_err(map_clickhouse_err("start observation insert"))?;

    for observation in observations {
        insert
            .write(&from_persisted_observation(observation))
            .await
            .map_err(map_clickhouse_err("write observation row"))?;
    }

    insert
        .end()
        .await
        .map_err(map_clickhouse_err("finish observation insert"))
}

pub(super) async fn insert_run_checkpoint(
    client: &Client,
    checkpoint: CrawlRunCheckpoint,
) -> Result<(), CrawlerRepositoryError> {
    let mut insert = client
        .insert::<RunCheckpointRow>(CRAWLER_RUN_CHECKPOINTS_TABLE)
        .await
        .map_err(map_clickhouse_err("start checkpoint insert"))?;

    insert
        .write(&from_checkpoint(checkpoint))
        .await
        .map_err(map_clickhouse_err("write checkpoint row"))?;

    insert
        .end()
        .await
        .map_err(map_clickhouse_err("finish checkpoint insert"))
}
