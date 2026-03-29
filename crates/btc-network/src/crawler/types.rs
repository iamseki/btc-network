use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use super::domain::{CrawlEndpoint, FailureClassification};

/// Runtime configuration for the crawler orchestration loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrawlerConfig {
    /// Maximum number of worker tasks polling and processing nodes concurrently.
    pub max_concurrency: usize,
    /// Maximum number of unique endpoints tracked in-memory during a crawl.
    pub max_tracked_nodes: usize,
    /// Hard wall-clock runtime limit for the full crawl.
    pub max_runtime: Duration,
    /// Stop when no new nodes were queued during this window.
    pub idle_timeout: Duration,
    /// Lifecycle polling interval used to evaluate stop policies.
    pub lifecycle_tick: Duration,
    /// TCP connect timeout used per node.
    pub connect_timeout: Duration,
    /// Per-connection read/write timeout used by session I/O.
    pub io_timeout: Duration,
    /// Enables extra per-node logs.
    pub verbose: bool,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 1000,
            max_tracked_nodes: 100_000,
            max_runtime: Duration::from_secs(60 * 60),
            idle_timeout: Duration::from_secs(5 * 60),
            lifecycle_tick: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(10),
            verbose: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeState {
    /// Version protocol number advertised by the peer.
    pub version: i32,
    /// Raw service capability bitfield from the peer `version`.
    pub services: u64,
    /// Advertised peer user agent.
    pub user_agent: String,
    /// Advertised best known block height.
    pub start_height: i32,
    /// Relay preference from `version` message when present.
    pub relay: Option<bool>,
    /// Peer timestamp from `version` message.
    pub timestamp: i64,
}

/// High-level crawl execution metrics.
#[derive(Debug, Clone)]
pub struct CrawlSummary {
    pub scheduled_tasks: usize,
    pub successful_handshakes: usize,
    pub failed_tasks: usize,
    pub queued_nodes_total: usize,
    pub unique_nodes: usize,
    pub discovered_node_states: usize,
    pub elapsed: Duration,
}

#[derive(Debug, Default)]
pub(crate) struct CrawlerStats {
    pub(crate) scheduled: AtomicUsize,
    pub(crate) success: AtomicUsize,
    pub(crate) failed: AtomicUsize,
    pub(crate) queued_total: AtomicUsize,
    pub(crate) in_flight: AtomicUsize,
    pub(crate) persisted_rows: AtomicUsize,
    pub(crate) writer_backlog: AtomicUsize,
}

#[derive(Debug)]
pub(crate) struct CrawlState {
    pub(crate) seen_nodes: HashSet<CrawlEndpoint>,
    pub(crate) pending_nodes: HashSet<CrawlEndpoint>,
    pub(crate) node_states: HashMap<CrawlEndpoint, NodeState>,
    pub(crate) last_new_node_at: Instant,
}

impl CrawlState {
    pub(crate) fn new() -> Self {
        Self {
            seen_nodes: HashSet::new(),
            pending_nodes: HashSet::new(),
            node_states: HashMap::new(),
            last_new_node_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NodeVisit {
    pub(crate) node: CrawlEndpoint,
    pub(crate) state: NodeState,
    pub(crate) discovered: Vec<CrawlEndpoint>,
    pub(crate) latency: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct NodeVisitFailure {
    pub(crate) node: CrawlEndpoint,
    pub(crate) latency: Duration,
    pub(crate) classification: FailureClassification,
    pub(crate) message: String,
}
