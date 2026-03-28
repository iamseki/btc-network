use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;

use super::domain::{
    CountNodesByAsnRow, CrawlEndpoint, CrawlRunCheckpoint, CrawlRunId, IpEnrichment,
    PersistedNodeObservation,
};

pub type RepositoryFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerRepositoryError {
    message: String,
}

impl CrawlerRepositoryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for CrawlerRepositoryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CrawlerRepositoryError {}

pub trait IpEnrichmentProvider: Send + Sync {
    fn enrich(&self, endpoint: &CrawlEndpoint) -> IpEnrichment;
}

pub trait CrawlerRepository: Send + Sync {
    fn insert_observation<'a>(
        &'a self,
        observation: PersistedNodeObservation,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>>;

    fn insert_observations_stream<'a>(
        &'a self,
        observations: Vec<PersistedNodeObservation>,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>>;

    fn insert_run_checkpoint<'a>(
        &'a self,
        checkpoint: CrawlRunCheckpoint,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>>;

    fn get_run_checkpoint<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>;

    fn list_runs<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>>;

    fn count_nodes_by_asn<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::{
        BatchId, CrawlNetwork, CrawlPhase, CrawlRunMetrics, HandshakeStatus, ObservationConfidence,
        ObservationId, RawNodeObservation,
    };
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Clone)]
    struct StaticIpEnrichmentProvider {
        enrichment: IpEnrichment,
    }

    impl IpEnrichmentProvider for StaticIpEnrichmentProvider {
        fn enrich(&self, _endpoint: &CrawlEndpoint) -> IpEnrichment {
            self.enrichment.clone()
        }
    }

    #[derive(Default)]
    struct InMemoryCrawlerRepository {
        observations: Mutex<Vec<PersistedNodeObservation>>,
        checkpoints: Mutex<Vec<CrawlRunCheckpoint>>,
        counts: Mutex<Vec<CountNodesByAsnRow>>,
    }

    impl CrawlerRepository for InMemoryCrawlerRepository {
        fn insert_observation<'a>(
            &'a self,
            observation: PersistedNodeObservation,
        ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
            Box::pin(async move {
                self.observations
                    .lock()
                    .expect("observations lock")
                    .push(observation);
                Ok(())
            })
        }

        fn insert_observations_stream<'a>(
            &'a self,
            observations: Vec<PersistedNodeObservation>,
        ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
            Box::pin(async move {
                self.observations
                    .lock()
                    .expect("observations lock")
                    .extend(observations);
                Ok(())
            })
        }

        fn insert_run_checkpoint<'a>(
            &'a self,
            checkpoint: CrawlRunCheckpoint,
        ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
            Box::pin(async move {
                self.checkpoints
                    .lock()
                    .expect("checkpoints lock")
                    .push(checkpoint);
                Ok(())
            })
        }

        fn get_run_checkpoint<'a>(
            &'a self,
            run_id: &'a CrawlRunId,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
        {
            Box::pin(async move {
                let checkpoint = self
                    .checkpoints
                    .lock()
                    .expect("checkpoints lock")
                    .iter()
                    .rev()
                    .find(|checkpoint| checkpoint.run_id == *run_id)
                    .cloned();
                Ok(checkpoint)
            })
        }

        fn list_runs<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
            Box::pin(async move { Ok(self.checkpoints.lock().expect("checkpoints lock").clone()) })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
            Box::pin(async move { Ok(self.counts.lock().expect("counts lock").clone()) })
        }
    }

    fn sample_raw_observation() -> RawNodeObservation {
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
            discovered_count: 3,
            latency: Some(Duration::from_millis(125)),
            failure_classification: None,
        }
    }

    fn sample_checkpoint() -> CrawlRunCheckpoint {
        CrawlRunCheckpoint {
            run_id: CrawlRunId::new("run-1"),
            phase: CrawlPhase::Crawling,
            checkpointed_at: Utc::now(),
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
                unique_nodes: 5,
                discovered_node_states: 4,
                persisted_observation_rows: 2,
                writer_backlog: 0,
            },
            resume_state: None,
            caller: Some("test".to_string()),
        }
    }

    #[test]
    fn enrichment_provider_is_mock_friendly() {
        let provider: &dyn IpEnrichmentProvider = &StaticIpEnrichmentProvider {
            enrichment: IpEnrichment::matched(
                Some(64512),
                Some("Example ASN".to_string()),
                Some("US".to_string()),
                Some("1.1.1.0/24".to_string()),
            ),
        };

        let enrichment = provider.enrich(&sample_raw_observation().endpoint);

        assert_eq!(enrichment.asn, Some(64512));
        assert_eq!(enrichment.country.as_deref(), Some("US"));
    }

    #[tokio::test]
    async fn repository_trait_supports_test_double_for_observations_and_checkpoints() {
        let repository: &dyn CrawlerRepository = &InMemoryCrawlerRepository::default();
        let persisted = sample_raw_observation().into_persisted(
            ObservationId::new("observation-1"),
            BatchId::new("batch-1"),
            IpEnrichment::not_applicable(),
        );
        let checkpoint = sample_checkpoint();

        repository
            .insert_observation(persisted.clone())
            .await
            .expect("insert observation");
        repository
            .insert_run_checkpoint(checkpoint.clone())
            .await
            .expect("insert checkpoint");

        let saved_checkpoint = repository
            .get_run_checkpoint(&checkpoint.run_id)
            .await
            .expect("get checkpoint")
            .expect("checkpoint exists");
        let runs = repository.list_runs().await.expect("list runs");

        assert_eq!(saved_checkpoint, checkpoint);
        assert_eq!(runs, vec![checkpoint]);

        repository
            .insert_observations_stream(vec![persisted.clone()])
            .await
            .expect("insert stream");
    }
}
