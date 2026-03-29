use btc_network::crawler::{
    CountNodesByAsnRow, CrawlRunCheckpoint, CrawlRunId, CrawlerRepository, CrawlerRepositoryError,
    PersistedNodeObservation, RepositoryFuture,
};
use clickhouse::{Client, sql::Identifier};

use crate::config::ClickHouseConnectionConfig;
use crate::rows::{
    CountNodesByAsnDbRow, NodeObservationRow, RunCheckpointRow, from_checkpoint,
    from_persisted_observation, to_checkpoint, to_count_nodes_by_asn,
};

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
        Box::pin(async move {
            let mut insert = self
                .client
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
        })
    }

    fn insert_run_checkpoint<'a>(
        &'a self,
        checkpoint: CrawlRunCheckpoint,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async move {
            let mut insert = self
                .client
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
        })
    }

    fn get_run_checkpoint<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move {
            self.client
                .query(
                    "SELECT ?fields FROM ? WHERE run_id = ? ORDER BY checkpointed_at DESC, checkpoint_sequence DESC LIMIT 1",
                )
                .bind(Identifier(CRAWLER_RUN_CHECKPOINTS_TABLE))
                .bind(run_id.as_str())
                .fetch_optional::<RunCheckpointRow>()
                .await
                .map(|row| row.map(to_checkpoint))
                .map_err(map_clickhouse_err("fetch latest run checkpoint"))
        })
    }

    fn list_runs<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async move {
            self.client
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
",
                )
                .bind(Identifier(CRAWLER_RUN_CHECKPOINTS_TABLE))
                .fetch_all::<RunCheckpointRow>()
                .await
                .map(|rows| rows.into_iter().map(to_checkpoint).collect())
                .map_err(map_clickhouse_err("list crawler runs"))
        })
    }

    fn count_nodes_by_asn<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
        Box::pin(async move {
            self.client
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
",
                )
                .bind(Identifier(NODE_OBSERVATIONS_TABLE))
                .fetch_all::<CountNodesByAsnDbRow>()
                .await
                .map(|rows| rows.into_iter().map(to_count_nodes_by_asn).collect())
                .map_err(map_clickhouse_err("count nodes by ASN"))
        })
    }
}

fn map_clickhouse_err(
    context: &'static str,
) -> impl FnOnce(clickhouse::error::Error) -> CrawlerRepositoryError {
    move |err| CrawlerRepositoryError::new(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_network::crawler::{
        BatchId, CountNodesByAsnRow, CrawlEndpoint, CrawlNetwork, CrawlPhase, CrawlRunCheckpoint,
        CrawlRunId, CrawlRunMetrics, HandshakeStatus, IpEnrichment, ObservationConfidence,
        ObservationId, RawNodeObservation,
    };
    use chrono::Utc;
    use clickhouse::test::{self, handlers};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn sample_observation() -> PersistedNodeObservation {
        RawNodeObservation {
            observed_at: Utc::now(),
            crawl_run_id: CrawlRunId::new("run-1"),
            endpoint: CrawlEndpoint::new(
                "1.1.1.7",
                8333,
                CrawlNetwork::Ipv4,
                Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7))),
            ),
            handshake_status: HandshakeStatus::Succeeded,
            confidence: ObservationConfidence::Verified,
            protocol_version: Some(70016),
            services: Some(1),
            user_agent: Some("/Satoshi:27.0.0/".to_string()),
            start_height: Some(900_000),
            relay: Some(true),
            discovered_count: 8,
            latency: Some(Duration::from_millis(125)),
            failure_classification: None,
        }
        .into_persisted(
            ObservationId::new("observation-1"),
            BatchId::new("batch-1"),
            IpEnrichment::matched(
                Some(64512),
                Some("Example ASN".to_string()),
                Some("US".to_string()),
                Some("1.1.1.0/24".to_string()),
            ),
        )
    }

    fn sample_checkpoint() -> CrawlRunCheckpoint {
        CrawlRunCheckpoint {
            run_id: CrawlRunId::new("run-1"),
            phase: CrawlPhase::Crawling,
            checkpointed_at: Utc::now(),
            checkpoint_sequence: 1,
            started_at: Utc::now(),
            stop_reason: None,
            failure_reason: None,
            metrics: CrawlRunMetrics {
                frontier_size: 1,
                in_flight_work: 2,
                scheduled_tasks: 3,
                successful_handshakes: 4,
                failed_tasks: 1,
                queued_nodes_total: 5,
                unique_nodes: 6,
                discovered_node_states: 7,
                persisted_observation_rows: 8,
                writer_backlog: 0,
            },
            resume_state: Some("{\"frontier\":[]}".to_string()),
            caller: Some("test".to_string()),
        }
    }

    #[tokio::test]
    async fn repository_streams_observation_rows_with_expected_shape() {
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let repository = ClickHouseCrawlerRepository::with_client(client);
        let recording = mock.add(handlers::record());

        repository
            .insert_observations_stream(vec![sample_observation()])
            .await
            .expect("insert observations");

        let rows: Vec<NodeObservationRow> = recording.collect().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].observation_id, "observation-1");
        assert_eq!(rows[0].endpoint, "1.1.1.7:8333");
        assert_eq!(rows[0].network_type, "ipv4");
        assert_eq!(rows[0].confidence_level, "verified");
        assert_eq!(rows[0].asn, Some(64512));
    }

    #[tokio::test]
    async fn repository_fetches_latest_checkpoint_for_run() {
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let repository = ClickHouseCrawlerRepository::with_client(client);
        let checkpoint = from_checkpoint(sample_checkpoint());
        mock.add(handlers::provide(vec![checkpoint.clone()]));

        let result = repository
            .get_run_checkpoint(&CrawlRunId::new("run-1"))
            .await
            .expect("get checkpoint")
            .expect("checkpoint exists");

        assert_eq!(result.run_id.as_str(), "run-1");
        assert_eq!(result.phase, CrawlPhase::Crawling);
        assert_eq!(
            result.metrics.unique_nodes,
            checkpoint.unique_nodes as usize
        );
    }

    #[tokio::test]
    async fn repository_counts_latest_verified_nodes_by_asn() {
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let repository = ClickHouseCrawlerRepository::with_client(client);
        mock.add(handlers::provide(vec![
            CountNodesByAsnDbRow {
                asn: Some(64512),
                asn_organization: Some("Example ASN".to_string()),
                verified_nodes: 4,
            },
            CountNodesByAsnDbRow {
                asn: None,
                asn_organization: None,
                verified_nodes: 1,
            },
        ]));

        let rows = repository
            .count_nodes_by_asn()
            .await
            .expect("count nodes by asn");

        assert_eq!(
            rows,
            vec![
                CountNodesByAsnRow {
                    asn: Some(64512),
                    asn_organization: Some("Example ASN".to_string()),
                    verified_nodes: 4,
                },
                CountNodesByAsnRow {
                    asn: None,
                    asn_organization: None,
                    verified_nodes: 1,
                },
            ]
        );
    }
    #[tokio::test]
    async fn repository_list_runs_query_includes_argmax_latest_checkpoint_shape() {
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let repository = ClickHouseCrawlerRepository::with_client(client.clone());
        let recording = mock.add(handlers::record_ddl());

        repository.list_runs().await.expect("list runs");

        let query = recording.query().await;
        assert!(query.contains("argMax(phase, tuple(checkpointed_at, checkpoint_sequence))"));
        assert!(query.contains("latest_checkpoint_sequence AS checkpoint_sequence"));
        assert!(query.contains("GROUP BY run_id"));
        assert!(query.contains("crawler_run_checkpoints"));
    }
}
