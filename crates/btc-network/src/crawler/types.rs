use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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
    /// Maximum number of TCP connect attempts per node, including the first try.
    pub connect_max_attempts: usize,
    /// Base exponential backoff between failed TCP connect attempts.
    pub connect_retry_backoff: Duration,
    /// Per-connection read/write timeout used by session I/O.
    pub io_timeout: Duration,
    /// Maximum time to wait for worker tasks to drain after shutdown starts.
    pub shutdown_grace_period: Duration,
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
            connect_max_attempts: 3,
            connect_retry_backoff: Duration::from_millis(250),
            io_timeout: Duration::from_secs(10),
            shutdown_grace_period: Duration::from_secs(15),
            verbose: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub(crate) in_flight_nodes: HashSet<CrawlEndpoint>,
    pub(crate) node_states: HashMap<CrawlEndpoint, NodeState>,
    pub(crate) last_new_node_at: Instant,
}

impl CrawlState {
    pub(crate) fn new() -> Self {
        Self {
            seen_nodes: HashSet::new(),
            pending_nodes: HashSet::new(),
            in_flight_nodes: HashSet::new(),
            node_states: HashMap::new(),
            last_new_node_at: Instant::now(),
        }
    }

    pub(crate) fn to_resume_state(&self) -> CrawlResumeState {
        let mut seen_nodes = self.seen_nodes.iter().cloned().collect::<Vec<_>>();
        seen_nodes.sort_by(|left, right| left.canonical.cmp(&right.canonical));

        let mut pending_nodes = self.pending_nodes.iter().cloned().collect::<Vec<_>>();
        pending_nodes.sort_by(|left, right| left.canonical.cmp(&right.canonical));

        let mut in_flight_nodes = self.in_flight_nodes.iter().cloned().collect::<Vec<_>>();
        in_flight_nodes.sort_by(|left, right| left.canonical.cmp(&right.canonical));

        let mut node_states = self
            .node_states
            .iter()
            .map(|(endpoint, state)| ResumeNodeState {
                endpoint: endpoint.clone(),
                state: state.clone(),
            })
            .collect::<Vec<_>>();
        node_states.sort_by(|left, right| left.endpoint.canonical.cmp(&right.endpoint.canonical));

        CrawlResumeState {
            seen_nodes,
            pending_nodes,
            in_flight_nodes,
            node_states,
        }
    }

    pub(crate) fn from_resume_state(resume_state: CrawlResumeState) -> Self {
        let mut state = Self::new();

        for endpoint in resume_state.seen_nodes {
            state.seen_nodes.insert(endpoint);
        }

        for endpoint in resume_state.pending_nodes {
            state.seen_nodes.insert(endpoint.clone());
            state.pending_nodes.insert(endpoint);
        }

        for endpoint in resume_state.in_flight_nodes {
            state.seen_nodes.insert(endpoint.clone());
            state.pending_nodes.insert(endpoint);
        }

        for node_state in resume_state.node_states {
            state.seen_nodes.insert(node_state.endpoint.clone());
            state
                .node_states
                .insert(node_state.endpoint, node_state.state);
        }

        state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CrawlResumeState {
    pub(crate) seen_nodes: Vec<CrawlEndpoint>,
    pub(crate) pending_nodes: Vec<CrawlEndpoint>,
    pub(crate) in_flight_nodes: Vec<CrawlEndpoint>,
    pub(crate) node_states: Vec<ResumeNodeState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResumeNodeState {
    pub(crate) endpoint: CrawlEndpoint,
    pub(crate) state: NodeState,
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

pub(crate) type NodeVisitError = Box<NodeVisitFailure>;
pub(crate) type NodeVisitResult = Result<NodeVisit, NodeVisitError>;
