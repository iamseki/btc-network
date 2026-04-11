use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tracing::{info, warn};

use super::domain::{CrawlEndpoint, CrawlRunId, IpEnrichment, ObservationId, RawNodeObservation};
use super::node::NodeProcessor;
use super::ports::IpEnrichmentProvider;
use super::types::{CrawlState, CrawlerConfig, CrawlerStats, NodeVisit};
use crate::crawler::PersistedNodeObservation;

pub(crate) struct WorkerContext {
    pub(crate) config: CrawlerConfig,
    pub(crate) run_id: CrawlRunId,
    pub(crate) state: Arc<Mutex<CrawlState>>,
    pub(crate) stats: Arc<CrawlerStats>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) queue_rx: Arc<Mutex<mpsc::UnboundedReceiver<CrawlEndpoint>>>,
    pub(crate) queue_tx: mpsc::UnboundedSender<CrawlEndpoint>,
    pub(crate) observation_tx: mpsc::Sender<PersistedNodeObservation>,
    pub(crate) processor: Arc<dyn NodeProcessor>,
    pub(crate) enrichment_provider: Arc<dyn IpEnrichmentProvider>,
    pub(crate) connect_limiter: Arc<Semaphore>,
}

/// Runs one crawler worker loop.
///
/// A worker owns the per-endpoint processing path:
/// dequeue one pending endpoint, mark it in flight, run the node processor,
/// enqueue the persisted observation for the writer task, merge discovered
/// nodes back into shared state, and queue any newly discovered follow-up work.
///
/// Workers do not write directly to the repository and they do not decide when
/// the crawl should stop overall. Those responsibilities stay with the writer
/// and lifecycle/coordinator tasks.
pub(crate) async fn run_worker(context: WorkerContext) {
    let WorkerContext {
        config,
        run_id,
        state,
        stats,
        stop,
        queue_rx,
        queue_tx,
        observation_tx,
        processor,
        enrichment_provider,
        connect_limiter,
    } = context;

    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }

        let node_cycle_started = Instant::now();
        let queue_lock_wait_started = Instant::now();
        let mut guard = queue_rx.lock().await;
        let queue_lock_wait = queue_lock_wait_started.elapsed();
        let queue_lock_hold_started = Instant::now();
        let maybe_endpoint = match guard.try_recv() {
            Ok(endpoint) => Some(endpoint),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
        };
        let queue_lock_hold = queue_lock_hold_started.elapsed();
        drop(guard);

        observe_lock_contention(
            &stats,
            queue_lock_wait,
            queue_lock_hold,
            Duration::ZERO,
            Duration::ZERO,
        );

        let Some(endpoint) = maybe_endpoint else {
            stats
                .queue_empty_polls_total
                .fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };

        {
            let mut guard = state.lock().await;
            guard.pending_nodes.remove(&endpoint);
            guard.in_flight_nodes.insert(endpoint.clone());
        }

        stats.scheduled.fetch_add(1, Ordering::Relaxed);
        stats.in_flight.fetch_add(1, Ordering::Relaxed);
        let _in_flight_guard = InFlightGuard::new(stats.as_ref());

        let process_started = Instant::now();
        let Ok(_connect_permit) = connect_limiter.acquire().await else {
            stop.store(true, Ordering::Relaxed);
            warn!(
                "[crawler] connect limiter closed while processing {}",
                endpoint.canonical
            );
            return;
        };
        let visit_result = processor.process(endpoint.clone(), config).await;
        let process_elapsed = process_started.elapsed();

        match visit_result {
            Ok(visit) => {
                stats.success.fetch_add(1, Ordering::Relaxed);
                stats.discovered_node_states.fetch_add(1, Ordering::Relaxed);

                let discovered_peer_addresses_count = visit.discovered.len();
                let raw = RawNodeObservation::from_success(
                    Utc::now(),
                    run_id.clone(),
                    visit.node.clone(),
                    &visit.state,
                    discovered_peer_addresses_count,
                    visit.latency,
                );
                let persisted = build_persisted_observation(raw, enrichment_provider.as_ref());
                if !enqueue_observation(
                    &stats,
                    &stop,
                    &observation_tx,
                    persisted,
                    endpoint.canonical.as_str(),
                )
                .await
                {
                    return;
                }

                let state_lock_wait_started = Instant::now();
                let mut guard = state.lock().await;
                let state_lock_wait = state_lock_wait_started.elapsed();
                let state_lock_hold_started = Instant::now();
                guard.in_flight_nodes.remove(&endpoint);
                let discovered = apply_visit_to_state(&mut guard, visit, config.max_tracked_nodes);
                let state_lock_hold = state_lock_hold_started.elapsed();
                drop(guard);
                observe_lock_contention(
                    &stats,
                    Duration::ZERO,
                    Duration::ZERO,
                    state_lock_wait,
                    state_lock_hold,
                );
                let queued_count = discovered.len();

                if !discovered.is_empty() {
                    stats
                        .queued_total
                        .fetch_add(queued_count, Ordering::Relaxed);
                    for candidate in discovered {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        let _ = queue_tx.send(candidate);
                    }
                }

                if config.verbose {
                    info!(
                        node = %endpoint.canonical,
                        queue_lock_wait_ms = queue_lock_wait.as_millis(),
                        queue_recv_wait_ms = 0,
                        queue_lock_hold_ms = queue_lock_hold.as_millis(),
                        process_ms = process_elapsed.as_millis(),
                        state_lock_wait_ms = state_lock_wait.as_millis(),
                        state_lock_hold_ms = state_lock_hold.as_millis(),
                        discovered_peer_addresses = discovered_peer_addresses_count,
                        queued_nodes = queued_count,
                        node_total_ms = node_cycle_started.elapsed().as_millis(),
                        "[crawler] worker timing"
                    );
                }
            }
            Err(err) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);

                let raw = RawNodeObservation::from_failure(
                    Utc::now(),
                    run_id.clone(),
                    err.node.clone(),
                    err.classification.clone(),
                    err.latency,
                );
                let persisted = build_persisted_observation(raw, enrichment_provider.as_ref());
                if !enqueue_observation(
                    &stats,
                    &stop,
                    &observation_tx,
                    persisted,
                    err.node.canonical.as_str(),
                )
                .await
                {
                    return;
                }

                state.lock().await.in_flight_nodes.remove(&endpoint);

                if config.verbose {
                    info!(
                        node = %endpoint.canonical,
                        queue_lock_wait_ms = queue_lock_wait.as_millis(),
                        queue_recv_wait_ms = 0,
                        queue_lock_hold_ms = queue_lock_hold.as_millis(),
                        process_ms = process_elapsed.as_millis(),
                        node_total_ms = node_cycle_started.elapsed().as_millis(),
                        "[crawler] worker timing"
                    );
                    warn!(
                        "[crawler] failed to process node {}: {}",
                        endpoint.canonical, err.message
                    );
                }
            }
        }
    }
}

fn observe_lock_contention(
    stats: &CrawlerStats,
    queue_lock_wait: Duration,
    queue_lock_hold: Duration,
    state_lock_wait: Duration,
    state_lock_hold: Duration,
) {
    stats
        .queue_lock_wait_micros_total
        .fetch_add(queue_lock_wait.as_micros() as u64, Ordering::Relaxed);
    stats
        .queue_lock_hold_micros_total
        .fetch_add(queue_lock_hold.as_micros() as u64, Ordering::Relaxed);
    stats
        .state_lock_wait_micros_total
        .fetch_add(state_lock_wait.as_micros() as u64, Ordering::Relaxed);
    stats
        .state_lock_hold_micros_total
        .fetch_add(state_lock_hold.as_micros() as u64, Ordering::Relaxed);
}

struct InFlightGuard<'a> {
    stats: &'a CrawlerStats,
}

impl<'a> InFlightGuard<'a> {
    fn new(stats: &'a CrawlerStats) -> Self {
        Self { stats }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.stats.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn enqueue_observation(
    stats: &Arc<CrawlerStats>,
    stop: &Arc<AtomicBool>,
    observation_tx: &mpsc::Sender<PersistedNodeObservation>,
    observation: PersistedNodeObservation,
    endpoint_label: &str,
) -> bool {
    stats.writer_backlog.fetch_add(1, Ordering::Relaxed);
    if observation_tx.send(observation).await.is_err() {
        stats.writer_backlog.fetch_sub(1, Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
        warn!("[crawler] observation writer channel closed while processing {endpoint_label}");
        return false;
    }
    true
}

fn build_persisted_observation(
    raw: RawNodeObservation,
    enrichment_provider: &dyn IpEnrichmentProvider,
) -> PersistedNodeObservation {
    let enrichment = if raw.supports_ip_enrichment() {
        enrichment_provider.enrich(&raw.endpoint)
    } else {
        IpEnrichment::not_applicable()
    };

    raw.into_persisted(ObservationId::now_v7(), enrichment)
}

pub(crate) async fn seed_initial_nodes(
    state: &Arc<Mutex<CrawlState>>,
    stats: &Arc<CrawlerStats>,
    queue_tx: &mpsc::UnboundedSender<CrawlEndpoint>,
    seeds: Vec<CrawlEndpoint>,
    max_tracked_nodes: usize,
) {
    let mut newly_queued = Vec::new();
    {
        let mut guard = state.lock().await;
        for endpoint in seeds {
            if try_track_endpoint(&mut guard, endpoint.clone(), max_tracked_nodes) {
                guard.pending_nodes.insert(endpoint.clone());
                newly_queued.push(endpoint);
            }
        }
    }

    if !newly_queued.is_empty() {
        stats
            .queued_total
            .fetch_add(newly_queued.len(), Ordering::Relaxed);
        for endpoint in newly_queued {
            let _ = queue_tx.send(endpoint);
        }
    }
}

pub(crate) fn apply_visit_to_state(
    state: &mut CrawlState,
    visit: NodeVisit,
    max_tracked_nodes: usize,
) -> Vec<CrawlEndpoint> {
    let NodeVisit {
        node,
        state: _,
        discovered,
        latency: _,
    } = visit;
    state.seen_nodes.insert(node);

    let mut new_nodes = Vec::new();
    for endpoint in discovered {
        if endpoint.socket_addr().is_none() {
            continue;
        }

        if try_track_endpoint(state, endpoint.clone(), max_tracked_nodes) {
            state.pending_nodes.insert(endpoint.clone());
            new_nodes.push(endpoint);
        }
    }

    if !new_nodes.is_empty() {
        state.last_new_node_at = Instant::now();
    }

    new_nodes
}

fn try_track_endpoint(
    state: &mut CrawlState,
    endpoint: CrawlEndpoint,
    max_tracked_nodes: usize,
) -> bool {
    if state.seen_nodes.contains(&endpoint) {
        return false;
    }

    if state.seen_nodes.len() >= max_tracked_nodes {
        return false;
    }

    state.seen_nodes.insert(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::node::NodeProcessor;
    use crate::crawler::types::NodeVisitResult;
    use crate::crawler::{CrawlNetwork, CrawlRunId, HandshakeStatus};
    use crate::wire::message::Services;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

    struct MockProcessor {
        calls: AtomicUsize,
        responses: StdMutex<HashMap<CrawlEndpoint, NodeVisitResult>>,
    }

    impl MockProcessor {
        fn new(responses: HashMap<CrawlEndpoint, NodeVisitResult>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                responses: StdMutex::new(responses),
            }
        }
    }

    impl NodeProcessor for MockProcessor {
        fn process<'a>(
            &'a self,
            endpoint: CrawlEndpoint,
            _config: CrawlerConfig,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NodeVisitResult> + Send + 'a>>
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = self
                .responses
                .lock()
                .expect("mock responses lock")
                .remove(&endpoint)
                .unwrap_or_else(|| {
                    Err(Box::new(crate::crawler::types::NodeVisitFailure {
                        node: endpoint,
                        latency: Duration::from_millis(1),
                        classification: crate::crawler::FailureClassification::Other(
                            "missing mock response".to_string(),
                        ),
                        message: "missing mock response".to_string(),
                    }))
                });
            Box::pin(async move { result })
        }
    }

    #[derive(Clone)]
    struct StaticIpEnrichmentProvider {
        enrichment: IpEnrichment,
    }

    impl IpEnrichmentProvider for StaticIpEnrichmentProvider {
        fn enrich(&self, _endpoint: &CrawlEndpoint) -> IpEnrichment {
            self.enrichment.clone()
        }
    }

    fn test_config() -> CrawlerConfig {
        CrawlerConfig {
            max_concurrency: 1,
            max_tracked_nodes: 16,
            max_runtime: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            lifecycle_tick: Duration::from_millis(5),
            checkpoint_interval: Duration::from_millis(30),
            connect_timeout: Duration::from_millis(50),
            connect_max_attempts: 1,
            connect_retry_backoff: Duration::ZERO,
            io_timeout: Duration::from_millis(50),
            shutdown_grace_period: Duration::from_secs(1),
            max_connect_in_flight: 1,
            verbose: false,
        }
    }

    fn test_endpoint(octet: u8) -> CrawlEndpoint {
        CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, octet),
            8333,
        )))
    }

    fn overlay_endpoint() -> CrawlEndpoint {
        CrawlEndpoint::new("overlaynode", 8333, CrawlNetwork::TorV3, None)
    }

    fn public_endpoint(octet: u8) -> CrawlEndpoint {
        CrawlEndpoint::from_socket_addr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, octet),
            8333,
        )))
    }

    fn visit_for(node: CrawlEndpoint, discovered: Vec<CrawlEndpoint>) -> NodeVisit {
        NodeVisit {
            node,
            state: crate::crawler::NodeState {
                version: 70016,
                services: Services::NODE_WITNESS.bits(),
                user_agent: "/Satoshi:27.0.0/".to_string(),
                start_height: 900000,
                relay: Some(true),
                timestamp: 1700000000,
            },
            discovered,
            latency: Duration::from_millis(10),
        }
    }

    #[test]
    fn apply_visit_inserts_state_and_only_new_connectable_nodes() {
        let node = test_endpoint(2);
        let already_known = test_endpoint(3);
        let new_node = test_endpoint(4);

        let mut state = CrawlState::new();
        state.seen_nodes.insert(already_known.clone());
        state.pending_nodes.insert(already_known.clone());
        let before = state.last_new_node_at;

        let visit = visit_for(
            node.clone(),
            vec![already_known, new_node.clone(), overlay_endpoint()],
        );
        let inserted = apply_visit_to_state(&mut state, visit, test_config().max_tracked_nodes);

        assert_eq!(inserted, vec![new_node.clone()]);
        assert!(state.seen_nodes.contains(&node));
        assert!(state.pending_nodes.contains(&new_node));
        assert!(state.last_new_node_at >= before);
    }

    #[test]
    fn apply_visit_with_empty_discoveries_does_not_touch_last_new_node_time() {
        let node = test_endpoint(2);
        let mut state = CrawlState::new();
        let before = state.last_new_node_at;

        let inserted = apply_visit_to_state(
            &mut state,
            visit_for(node, vec![]),
            test_config().max_tracked_nodes,
        );

        assert!(inserted.is_empty());
        assert_eq!(state.last_new_node_at, before);
    }

    #[test]
    fn apply_visit_keeps_processed_node_in_seen_set() {
        let node = test_endpoint(2);
        let mut state = CrawlState::new();
        state.seen_nodes.insert(node.clone());

        apply_visit_to_state(
            &mut state,
            visit_for(node.clone(), vec![]),
            test_config().max_tracked_nodes,
        );

        assert!(state.seen_nodes.contains(&node));
    }

    #[tokio::test]
    async fn worker_exits_when_stop_is_true() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(true));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let (obs_tx, _obs_rx) = mpsc::channel(1);
        let _ = in_tx.send(test_endpoint(2));
        drop(in_tx);

        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(HashMap::new()));
        let enrichment: Arc<dyn IpEnrichmentProvider> = Arc::new(StaticIpEnrichmentProvider {
            enrichment: IpEnrichment::unavailable(),
        });
        run_worker(WorkerContext {
            config,
            run_id: CrawlRunId::from_u128(1),
            state,
            stats: Arc::clone(&stats),
            stop,
            queue_rx: Arc::new(Mutex::new(in_rx)),
            queue_tx: out_tx,
            observation_tx: obs_tx,
            processor: Arc::clone(&processor),
            enrichment_provider: enrichment,
            connect_limiter: Arc::new(Semaphore::new(1)),
        })
        .await;

        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn worker_processes_item_updates_state_and_emits_persisted_observation() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let (obs_tx, mut obs_rx) = mpsc::channel(4);

        let node = public_endpoint(2);
        let discovered = public_endpoint(3);
        let _ = in_tx.send(node.clone());
        drop(in_tx);

        let mut responses = HashMap::new();
        responses.insert(
            node.clone(),
            Ok(visit_for(
                node.clone(),
                vec![discovered.clone(), overlay_endpoint()],
            )),
        );
        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(responses));
        let enrichment: Arc<dyn IpEnrichmentProvider> = Arc::new(StaticIpEnrichmentProvider {
            enrichment: IpEnrichment::matched(
                Some(64512),
                Some("Example ASN".to_string()),
                Some("US".to_string()),
                Some("1.1.1.0/24".to_string()),
            ),
        });

        run_worker(WorkerContext {
            config,
            run_id: CrawlRunId::from_u128(1),
            state: Arc::clone(&state),
            stats: Arc::clone(&stats),
            stop,
            queue_rx: Arc::new(Mutex::new(in_rx)),
            queue_tx: out_tx,
            observation_tx: obs_tx,
            processor: Arc::clone(&processor),
            enrichment_provider: enrichment,
            connect_limiter: Arc::new(Semaphore::new(1)),
        })
        .await;

        let persisted = obs_rx.recv().await.expect("persisted observation");
        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 1);
        assert_eq!(stats.success.load(Ordering::Relaxed), 1);
        assert_eq!(stats.failed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.queued_total.load(Ordering::Relaxed), 1);
        assert_eq!(stats.discovered_node_states.load(Ordering::Relaxed), 1);
        assert_eq!(out_rx.try_recv().ok(), Some(discovered.clone()));
        assert!(out_rx.try_recv().is_err());
        assert_eq!(persisted.raw.handshake_status, HandshakeStatus::Succeeded);
        assert_eq!(persisted.enrichment.asn, Some(64512));

        let guard = state.lock().await;
        assert!(guard.seen_nodes.contains(&node));
        assert!(guard.pending_nodes.contains(&discovered));
        assert!(!guard.in_flight_nodes.contains(&node));
    }

    #[tokio::test]
    async fn worker_persists_failed_observation_without_enrichment_for_overlay_endpoint() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let (obs_tx, mut obs_rx) = mpsc::channel(4);

        let node = overlay_endpoint();
        let _ = in_tx.send(node.clone());
        drop(in_tx);

        let mut responses = HashMap::new();
        responses.insert(
            node.clone(),
            Err(Box::new(crate::crawler::types::NodeVisitFailure {
                node: node.clone(),
                latency: Duration::from_millis(10),
                classification: crate::crawler::FailureClassification::Connect,
                message: "connect failed".to_string(),
            })),
        );
        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(responses));
        let enrichment: Arc<dyn IpEnrichmentProvider> = Arc::new(StaticIpEnrichmentProvider {
            enrichment: IpEnrichment::matched(
                Some(64512),
                Some("Example ASN".to_string()),
                Some("US".to_string()),
                Some("203.0.113.0/24".to_string()),
            ),
        });

        run_worker(WorkerContext {
            config,
            run_id: CrawlRunId::from_u128(1),
            state,
            stats: Arc::clone(&stats),
            stop,
            queue_rx: Arc::new(Mutex::new(in_rx)),
            queue_tx: out_tx,
            observation_tx: obs_tx,
            processor: Arc::clone(&processor),
            enrichment_provider: enrichment,
            connect_limiter: Arc::new(Semaphore::new(1)),
        })
        .await;

        let persisted = obs_rx.recv().await.expect("persisted observation");
        assert_eq!(persisted.raw.handshake_status, HandshakeStatus::Failed);
        assert_eq!(
            persisted.enrichment.status,
            crate::crawler::IpEnrichmentStatus::NotApplicable
        );
    }

    #[tokio::test]
    async fn seed_initial_nodes_deduplicates_and_tracks_pending_frontier() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let (queue_tx, mut queue_rx) = mpsc::unbounded_channel();

        let a = test_endpoint(2);
        let b = test_endpoint(3);
        let seeds = vec![a.clone(), b.clone(), a.clone()];

        seed_initial_nodes(
            &state,
            &stats,
            &queue_tx,
            seeds,
            test_config().max_tracked_nodes,
        )
        .await;

        assert_eq!(stats.queued_total.load(Ordering::Relaxed), 2);
        let first = queue_rx.try_recv().expect("first queued");
        let second = queue_rx.try_recv().expect("second queued");
        assert!(queue_rx.try_recv().is_err());
        assert_ne!(first, second);

        let guard = state.lock().await;
        assert_eq!(guard.seen_nodes.len(), 2);
        assert_eq!(guard.pending_nodes.len(), 2);
        assert!(guard.seen_nodes.contains(&a));
        assert!(guard.seen_nodes.contains(&b));
        assert!(guard.in_flight_nodes.is_empty());
    }

    #[test]
    fn build_persisted_observation_uses_not_applicable_for_non_routable_endpoint() {
        let raw = RawNodeObservation::from_failure(
            Utc::now(),
            CrawlRunId::from_u128(1),
            CrawlEndpoint::new(
                "10.0.0.2",
                8333,
                CrawlNetwork::Ipv4,
                Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ),
            crate::crawler::FailureClassification::Connect,
            Duration::from_millis(1),
        );
        let enrichment = StaticIpEnrichmentProvider {
            enrichment: IpEnrichment::matched(
                Some(1),
                Some("ignored".to_string()),
                Some("US".to_string()),
                Some("10.0.0.0/24".to_string()),
            ),
        };

        let persisted = build_persisted_observation(raw, &enrichment);

        assert_eq!(
            persisted.enrichment.status,
            crate::crawler::IpEnrichmentStatus::NotApplicable
        );
    }

    #[test]
    fn apply_visit_respects_max_tracked_nodes_limit() {
        let mut state = CrawlState::new();
        state.seen_nodes.insert(test_endpoint(2));
        state.seen_nodes.insert(test_endpoint(3));

        let inserted = apply_visit_to_state(
            &mut state,
            visit_for(test_endpoint(4), vec![test_endpoint(5)]),
            2,
        );

        assert!(inserted.is_empty());
        assert!(!state.pending_nodes.contains(&test_endpoint(5)));
    }

    #[tokio::test]
    async fn seed_initial_nodes_respects_max_tracked_nodes_limit() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let (queue_tx, mut queue_rx) = mpsc::unbounded_channel();

        seed_initial_nodes(
            &state,
            &stats,
            &queue_tx,
            vec![test_endpoint(2), test_endpoint(3)],
            1,
        )
        .await;

        assert_eq!(stats.queued_total.load(Ordering::Relaxed), 1);
        assert!(queue_rx.try_recv().is_ok());
        assert!(queue_rx.try_recv().is_err());
        assert_eq!(state.lock().await.seen_nodes.len(), 1);
    }
}
