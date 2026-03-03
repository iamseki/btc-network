use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use super::node::NodeProcessor;
use super::types::{CrawlState, CrawlerConfig, CrawlerStats, NodeVisit};

pub(crate) async fn run_worker(
    config: CrawlerConfig,
    state: Arc<Mutex<CrawlState>>,
    stats: Arc<CrawlerStats>,
    stop: Arc<AtomicBool>,
    queue_rx: Arc<Mutex<mpsc::UnboundedReceiver<SocketAddr>>>,
    queue_tx: mpsc::UnboundedSender<SocketAddr>,
    processor: Arc<dyn NodeProcessor>,
) {
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }

        let next = tokio::time::timeout(Duration::from_millis(250), async {
            let mut guard = queue_rx.lock().await;
            guard.recv().await
        })
        .await;

        let maybe_addr = match next {
            Ok(v) => v,
            Err(_) => continue,
        };

        let Some(addr) = maybe_addr else {
            return;
        };

        stats.scheduled.fetch_add(1, Ordering::Relaxed);

        let processor = Arc::clone(&processor);
        let visit_result =
            tokio::task::spawn_blocking(move || processor.process(addr, config)).await;

        match visit_result {
            Ok(Ok(visit)) => {
                stats.success.fetch_add(1, Ordering::Relaxed);

                let discovered = {
                    let mut guard = state.lock().await;
                    apply_visit_to_state(&mut guard, visit)
                };

                if !discovered.is_empty() {
                    stats
                        .queued_total
                        .fetch_add(discovered.len(), Ordering::Relaxed);
                    for candidate in discovered {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        let _ = queue_tx.send(candidate);
                    }
                }
            }
            Ok(Err(err)) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                if config.verbose {
                    warn!("[crawler] failed to process node {addr}: {err}");
                }
            }
            Err(err) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                if config.verbose {
                    warn!("[crawler] blocking task join error for {addr}: {err}");
                }
            }
        }
    }
}

pub(crate) async fn seed_initial_nodes(
    state: &Arc<Mutex<CrawlState>>,
    stats: &Arc<CrawlerStats>,
    queue_tx: &mpsc::UnboundedSender<SocketAddr>,
    seeds: Vec<SocketAddr>,
) {
    let mut newly_queued = Vec::new();
    {
        let mut guard = state.lock().await;
        for addr in seeds {
            if guard.queued_nodes.insert(addr) {
                newly_queued.push(addr);
            }
        }
    }

    if !newly_queued.is_empty() {
        stats
            .queued_total
            .fetch_add(newly_queued.len(), Ordering::Relaxed);
        for addr in newly_queued {
            let _ = queue_tx.send(addr);
        }
    }
}

pub(crate) fn apply_visit_to_state(state: &mut CrawlState, visit: NodeVisit) -> Vec<SocketAddr> {
    state.node_states.insert(visit.node, visit.state);

    let mut new_nodes = Vec::new();
    for addr in visit.discovered {
        if state.queued_nodes.insert(addr) {
            new_nodes.push(addr);
        }
    }

    if !new_nodes.is_empty() {
        state.last_new_node_at = Instant::now();
    }

    new_nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::NodeState;
    use crate::crawler::node::NodeProcessor;
    use crate::wire::message::Services;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

    struct MockProcessor {
        calls: AtomicUsize,
        responses: StdMutex<HashMap<SocketAddr, Result<NodeVisit, String>>>,
    }

    impl MockProcessor {
        fn new(responses: HashMap<SocketAddr, Result<NodeVisit, String>>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                responses: StdMutex::new(responses),
            }
        }
    }

    impl NodeProcessor for MockProcessor {
        fn process(&self, addr: SocketAddr, _config: CrawlerConfig) -> Result<NodeVisit, String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.responses
                .lock()
                .expect("mock responses lock")
                .remove(&addr)
                .unwrap_or_else(|| Err("missing mock response".to_string()))
        }
    }

    struct StopDuringProcessProcessor {
        stop: Arc<AtomicBool>,
        visit: NodeVisit,
    }

    impl NodeProcessor for StopDuringProcessProcessor {
        fn process(&self, _addr: SocketAddr, _config: CrawlerConfig) -> Result<NodeVisit, String> {
            self.stop.store(true, Ordering::Relaxed);
            Ok(self.visit.clone())
        }
    }

    fn test_config() -> CrawlerConfig {
        CrawlerConfig {
            max_concurrency: 1,
            max_runtime: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            janitor_tick: Duration::from_millis(5),
            connect_timeout: Duration::from_millis(50),
            io_timeout: Duration::from_millis(50),
            verbose: false,
        }
    }

    fn test_node(octet: u8) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, octet), 8333))
    }

    fn visit_for(node: SocketAddr, discovered: Vec<SocketAddr>) -> NodeVisit {
        NodeVisit {
            node,
            state: NodeState {
                version: 70016,
                services: Services::NODE_WITNESS.bits(),
                user_agent: "/Satoshi:27.0.0/".to_string(),
                start_height: 900000,
                relay: Some(true),
                timestamp: 1700000000,
            },
            discovered,
        }
    }

    #[test]
    fn apply_visit_inserts_state_and_only_new_nodes() {
        let node = test_node(2);
        let already_known = test_node(3);
        let new_node = test_node(4);

        let mut state = CrawlState::new();
        state.queued_nodes.insert(already_known);
        let before = state.last_new_node_at;

        let visit = visit_for(node, vec![already_known, new_node]);
        let inserted = apply_visit_to_state(&mut state, visit);

        assert_eq!(inserted, vec![new_node]);
        assert!(state.node_states.contains_key(&node));
        assert!(state.last_new_node_at >= before);
    }

    #[test]
    fn apply_visit_with_empty_discoveries_does_not_touch_last_new_node_time() {
        let node = test_node(2);
        let mut state = CrawlState::new();
        let before = state.last_new_node_at;

        let inserted = apply_visit_to_state(&mut state, visit_for(node, vec![]));

        assert!(inserted.is_empty());
        assert_eq!(state.last_new_node_at, before);
    }

    #[test]
    fn apply_visit_overwrites_existing_node_state() {
        let node = test_node(2);
        let mut state = CrawlState::new();
        state.node_states.insert(
            node,
            NodeState {
                version: 1,
                services: 0,
                user_agent: "old".to_string(),
                start_height: 1,
                relay: Some(false),
                timestamp: 1,
            },
        );

        apply_visit_to_state(&mut state, visit_for(node, vec![]));

        let saved = state.node_states.get(&node).expect("node state");
        assert_eq!(saved.version, 70016);
        assert_eq!(saved.user_agent, "/Satoshi:27.0.0/");
    }

    #[tokio::test]
    async fn worker_exits_when_stop_is_true() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(true));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let _ = in_tx.send(test_node(2));
        drop(in_tx);

        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(HashMap::new()));
        run_worker(
            config,
            state,
            Arc::clone(&stats),
            stop,
            Arc::new(Mutex::new(in_rx)),
            out_tx,
            Arc::clone(&processor),
        )
        .await;

        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn worker_exits_when_queue_is_closed_and_empty() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = mpsc::unbounded_channel::<SocketAddr>();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        drop(in_tx);

        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(HashMap::new()));
        run_worker(
            config,
            state,
            Arc::clone(&stats),
            stop,
            Arc::new(Mutex::new(in_rx)),
            out_tx,
            Arc::clone(&processor),
        )
        .await;

        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 0);
        assert_eq!(stats.success.load(Ordering::Relaxed), 0);
        assert_eq!(stats.failed.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn worker_processes_item_and_updates_state() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();

        let node = test_node(2);
        let discovered = test_node(3);
        let _ = in_tx.send(node);
        drop(in_tx);

        let mut responses = HashMap::new();
        responses.insert(node, Ok(visit_for(node, vec![discovered])));
        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(responses));

        run_worker(
            config,
            Arc::clone(&state),
            Arc::clone(&stats),
            stop,
            Arc::new(Mutex::new(in_rx)),
            out_tx,
            Arc::clone(&processor),
        )
        .await;

        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 1);
        assert_eq!(stats.success.load(Ordering::Relaxed), 1);
        assert_eq!(stats.failed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.queued_total.load(Ordering::Relaxed), 1);
        assert_eq!(out_rx.try_recv().ok(), Some(discovered));

        let guard = state.lock().await;
        assert!(guard.node_states.contains_key(&node));
        assert!(guard.queued_nodes.contains(&discovered));
    }

    #[tokio::test]
    async fn worker_counts_failures_on_process_error() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();

        let node = test_node(2);
        let _ = in_tx.send(node);
        drop(in_tx);

        let mut responses = HashMap::new();
        responses.insert(node, Err("boom".to_string()));
        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(responses));

        run_worker(
            config,
            Arc::clone(&state),
            Arc::clone(&stats),
            stop,
            Arc::new(Mutex::new(in_rx)),
            out_tx,
            Arc::clone(&processor),
        )
        .await;

        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 1);
        assert_eq!(stats.success.load(Ordering::Relaxed), 0);
        assert_eq!(stats.failed.load(Ordering::Relaxed), 1);
        assert_eq!(state.lock().await.node_states.len(), 0);
    }

    #[tokio::test]
    async fn worker_deduplicates_discovered_nodes_across_visits() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();

        let node_a = test_node(2);
        let node_b = test_node(3);
        let shared_discovered = test_node(9);

        let _ = in_tx.send(node_a);
        let _ = in_tx.send(node_b);
        drop(in_tx);

        let mut responses = HashMap::new();
        responses.insert(node_a, Ok(visit_for(node_a, vec![shared_discovered])));
        responses.insert(node_b, Ok(visit_for(node_b, vec![shared_discovered])));
        let processor: Arc<dyn NodeProcessor> = Arc::new(MockProcessor::new(responses));

        run_worker(
            config,
            Arc::clone(&state),
            Arc::clone(&stats),
            stop,
            Arc::new(Mutex::new(in_rx)),
            out_tx,
            Arc::clone(&processor),
        )
        .await;

        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 2);
        assert_eq!(stats.success.load(Ordering::Relaxed), 2);
        assert_eq!(stats.queued_total.load(Ordering::Relaxed), 1);
        assert_eq!(out_rx.try_recv().ok(), Some(shared_discovered));
        assert!(out_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn worker_stops_before_enqueuing_discovered_nodes_when_stop_flips() {
        let config = test_config();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();

        let node = test_node(2);
        let discovered = vec![test_node(3), test_node(4), test_node(5)];
        let _ = in_tx.send(node);
        drop(in_tx);

        let processor: Arc<dyn NodeProcessor> = Arc::new(StopDuringProcessProcessor {
            stop: Arc::clone(&stop),
            visit: visit_for(node, discovered),
        });

        run_worker(
            config,
            Arc::clone(&state),
            Arc::clone(&stats),
            Arc::clone(&stop),
            Arc::new(Mutex::new(in_rx)),
            out_tx,
            Arc::clone(&processor),
        )
        .await;

        assert_eq!(stats.scheduled.load(Ordering::Relaxed), 1);
        assert_eq!(stats.success.load(Ordering::Relaxed), 1);
        assert!(out_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn seed_initial_nodes_deduplicates_and_does_not_touch_node_states() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let (queue_tx, mut queue_rx) = mpsc::unbounded_channel();

        let a = test_node(2);
        let b = test_node(3);
        let seeds = vec![a, b, a];

        seed_initial_nodes(&state, &stats, &queue_tx, seeds).await;

        assert_eq!(stats.queued_total.load(Ordering::Relaxed), 2);
        let first = queue_rx.try_recv().expect("first queued");
        let second = queue_rx.try_recv().expect("second queued");
        assert!(queue_rx.try_recv().is_err());
        assert_ne!(first, second);

        let guard = state.lock().await;
        assert_eq!(guard.queued_nodes.len(), 2);
        assert!(guard.queued_nodes.contains(&a));
        assert!(guard.queued_nodes.contains(&b));
        assert!(guard.node_states.is_empty());
    }
}
