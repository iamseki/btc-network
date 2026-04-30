use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;

use super::domain::{
    CountNodesByAsnRow, CrawlEndpoint, CrawlRunCheckpoint, CrawlRunId, IpEnrichment,
    PersistedNodeObservation, UnreachableNodeUpdate,
};
use super::{
    AsnNodeCountItem, CrawlRunDetail, CrawlRunListItem, LastRunAsnCountItem,
    LastRunAsnOrganizationCountItem, LastRunCountryCountItem, LastRunNetworkTypeCountItem,
    LastRunNodeSummaryItem, LastRunProtocolVersionCountItem, LastRunServicesCountItem,
    LastRunStartHeightCountItem, LastRunUserAgentCountItem,
};

/// Boxed async result type used by crawler storage and analytics ports.
pub type RepositoryFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Best-effort adapter runtime stats for periodic progress logging.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepositoryRuntimeMetrics {
    pub pool_max_connections: Option<usize>,
    pub pool_size: Option<usize>,
    pub pool_idle: Option<usize>,
    pub pool_acquired: Option<usize>,
}

/// Adapter-level error returned by crawler storage and analytics ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerRepositoryError {
    message: String,
}

impl CrawlerRepositoryError {
    /// Creates a repository error from a caller-provided message.
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

/// Read-only IP enrichment contract for crawler endpoint metadata.
///
/// Implementations may return "not applicable" or "unavailable" results when
/// the endpoint should not or cannot be enriched.
pub trait IpEnrichmentProvider: Send + Sync {
    fn enrich(&self, endpoint: &CrawlEndpoint) -> IpEnrichment;
}

/// Storage contract for durable crawler observations, checkpoints, and read models.
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

    /// Returns the latest durable checkpoint for a specific run.
    ///
    /// Implementations must use `checkpoint_sequence` as a deterministic tie-breaker
    /// whenever two checkpoints share the same persisted timestamp.
    fn get_run_checkpoint<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>;

    /// Returns one latest checkpoint summary per run.
    ///
    /// Implementations must aggregate fields from the same winning checkpoint row and
    /// use `checkpoint_sequence` as a deterministic tie-breaker for timestamp collisions.
    fn list_runs<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>>;

    /// Returns latest verified-node counts grouped by ASN across persisted data.
    fn count_nodes_by_asn<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>>;

    fn load_unreachable_nodes<'a>(
        &'a self,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlEndpoint>, CrawlerRepositoryError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn apply_unreachable_node_updates<'a>(
        &'a self,
        _updates: Vec<UnreachableNodeUpdate>,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async { Ok(()) })
    }

    fn runtime_metrics(&self) -> RepositoryRuntimeMetrics {
        RepositoryRuntimeMetrics::default()
    }
}

/// Read-only analytics contract for browser-safe crawler UI surfaces.
pub trait CrawlerAnalyticsReader: Send + Sync {
    /// Returns the newest crawl runs, ordered from most recent to oldest.
    fn list_crawl_runs<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunListItem>, CrawlerRepositoryError>>;

    /// Returns one crawl run plus its recent checkpoints and derived analytics.
    fn get_crawl_run<'a>(
        &'a self,
        run_id: &'a CrawlRunId,
        checkpoint_limit: usize,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunDetail>, CrawlerRepositoryError>>;

    /// Returns latest verified-node counts grouped by ASN for analytics views.
    fn count_nodes_by_asn<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by services.
    fn list_last_run_services<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by protocol version.
    fn list_last_run_protocol_versions<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by user agent.
    fn list_last_run_user_agents<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by network type.
    fn list_last_run_network_types<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by country.
    fn list_last_run_countries<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by ASN.
    fn list_last_run_asns<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by start height.
    fn list_last_run_start_heights<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified-node counts grouped by ASN organization.
    fn list_last_run_asn_organizations<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError>>;

    /// Returns latest finished-run verified node rows for table-oriented UI views.
    fn list_last_run_nodes<'a>(
        &'a self,
        limit: usize,
    ) -> RepositoryFuture<'a, Result<Vec<LastRunNodeSummaryItem>, CrawlerRepositoryError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::{
        AsnNodeCountItem, CrawlNetwork, CrawlPhase, CrawlRunCheckpointItem, CrawlRunDetail,
        CrawlRunListItem, CrawlRunMetrics, FailureClassificationCount, NetworkOutcomeCount,
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
        crawl_runs: Mutex<Vec<CrawlRunListItem>>,
        crawl_run_detail: Mutex<Option<CrawlRunDetail>>,
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

    impl CrawlerAnalyticsReader for InMemoryCrawlerRepository {
        fn list_crawl_runs<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunListItem>, CrawlerRepositoryError>> {
            Box::pin(async move { Ok(self.crawl_runs.lock().expect("crawl runs lock").clone()) })
        }

        fn get_crawl_run<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
            _checkpoint_limit: usize,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunDetail>, CrawlerRepositoryError>> {
            Box::pin(async move {
                Ok(self
                    .crawl_run_detail
                    .lock()
                    .expect("crawl run detail lock")
                    .clone())
            })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<AsnNodeCountItem>, CrawlerRepositoryError>> {
            Box::pin(async move {
                Ok(self
                    .counts
                    .lock()
                    .expect("counts lock")
                    .clone()
                    .into_iter()
                    .map(Into::into)
                    .collect())
            })
        }

        fn list_last_run_services<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunServicesCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_protocol_versions<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<
            'a,
            Result<Vec<LastRunProtocolVersionCountItem>, CrawlerRepositoryError>,
        > {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_user_agents<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunUserAgentCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_network_types<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunNetworkTypeCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_countries<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunCountryCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_asns<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunAsnCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_start_heights<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunStartHeightCountItem>, CrawlerRepositoryError>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_asn_organizations<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<
            'a,
            Result<Vec<LastRunAsnOrganizationCountItem>, CrawlerRepositoryError>,
        > {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_last_run_nodes<'a>(
            &'a self,
            _limit: usize,
        ) -> RepositoryFuture<'a, Result<Vec<LastRunNodeSummaryItem>, CrawlerRepositoryError>>
        {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    fn sample_raw_observation() -> RawNodeObservation {
        RawNodeObservation {
            observed_at: Utc::now(),
            crawl_run_id: CrawlRunId::from_u128(1),
            endpoint: CrawlEndpoint::new(
                "1.1.1.7",
                8333,
                CrawlNetwork::Ipv4,
                Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7))),
            ),
            protocol_version: Some(70016),
            services: Some(1),
            user_agent: Some("/Satoshi:27.0.0/".to_string()),
            start_height: Some(900_000),
            relay: Some(true),
            discovered_peer_addresses_count: 3,
            latency: Some(Duration::from_millis(125)),
            failure_classification: None,
        }
    }

    fn sample_checkpoint() -> CrawlRunCheckpoint {
        CrawlRunCheckpoint {
            run_id: CrawlRunId::from_u128(1),
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
                unique_nodes: 5,
                persisted_observation_rows: 2,
                writer_backlog: 0,
            },
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
        let persisted = sample_raw_observation()
            .into_persisted(ObservationId::from_u128(1), IpEnrichment::not_applicable());
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

    #[tokio::test]
    async fn analytics_reader_trait_supports_test_double_for_run_reads() {
        let checkpoint_item = CrawlRunCheckpointItem {
            phase: "completed".to_string(),
            checkpointed_at: "2026-03-30T12:00:00+00:00".to_string(),
            checkpoint_sequence: 2,
            stop_reason: Some("idle timeout".to_string()),
            failure_reason: None,
            frontier_size: 0,
            in_flight_work: 0,
            scheduled_tasks: 10,
            successful_handshakes: 4,
            failed_tasks: 6,
            unique_nodes: 12,
            persisted_observation_rows: 10,
            writer_backlog: 0,
        };
        let run = CrawlRunListItem {
            run_id: CrawlRunId::from_u128(1).to_string(),
            phase: "completed".to_string(),
            started_at: "2026-03-30T11:00:00+00:00".to_string(),
            last_checkpointed_at: "2026-03-30T12:00:00+00:00".to_string(),
            stop_reason: Some("idle timeout".to_string()),
            failure_reason: None,
            scheduled_tasks: 10,
            successful_handshakes: 4,
            failed_tasks: 6,
            unique_nodes: 12,
            persisted_observation_rows: 10,
            success_pct: 40.0,
            scheduled_pct: 83.33,
            unscheduled_gap: 2,
        };
        let detail = CrawlRunDetail {
            run: run.clone(),
            checkpoints: vec![checkpoint_item],
            failure_counts: vec![FailureClassificationCount {
                classification: "connect".to_string(),
                observations: 6,
            }],
            network_outcomes: vec![NetworkOutcomeCount {
                network_type: "ipv4".to_string(),
                observations: 10,
                verified_nodes: 4,
                failed_nodes: 6,
                verified_pct: 40.0,
            }],
        };
        let repository = InMemoryCrawlerRepository {
            crawl_runs: Mutex::new(vec![run.clone()]),
            crawl_run_detail: Mutex::new(Some(detail.clone())),
            ..InMemoryCrawlerRepository::default()
        };
        let reader: &dyn CrawlerAnalyticsReader = &repository;

        let runs = reader.list_crawl_runs(10).await.expect("list runs");
        let fetched_detail = reader
            .get_crawl_run(&CrawlRunId::from_u128(1), 10)
            .await
            .expect("get run")
            .expect("run detail");

        assert_eq!(runs, vec![run]);
        assert_eq!(fetched_detail, detail);
    }
}
