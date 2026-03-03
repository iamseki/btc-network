mod janitor;
mod node;
mod types;
mod worker;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

use janitor::run_janitor;
use node::{DefaultNodeProcessor, NodeProcessor, resolve_seed_nodes};
use types::{CrawlState, CrawlerStats};
pub use types::{CrawlSummary, CrawlerConfig, NodeState};
use worker::{run_worker, seed_initial_nodes};

/// Bitcoin peer crawler orchestration.
///
/// This component coordinates:
/// - seed bootstrap
/// - bounded-concurrency workers
/// - janitor stop policies (max runtime + idle timeout)
/// - aggregated crawl summary output
///
/// TODO:
/// - benchmark lock contention (`Mutex` wait/hold times) under deterministic load
/// - add repository layer abstraction for durable crawler state (currently in-memory)
pub struct Crawler {
    config: CrawlerConfig,
}

impl Crawler {
    /// Creates a crawler with the provided runtime configuration.
    pub fn new(config: CrawlerConfig) -> Self {
        Self { config }
    }

    /// Executes a crawl run until stop policies are met.
    pub async fn run(&self) -> Result<CrawlSummary, Box<dyn Error>> {
        let started_at = Instant::now();
        let seeds = resolve_seed_nodes();
        if seeds.is_empty() {
            return Err("no seed addresses resolved".into());
        }

        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));

        let (queue_tx, queue_rx) = mpsc::unbounded_channel::<SocketAddr>();
        let queue_rx = Arc::new(Mutex::new(queue_rx));

        seed_initial_nodes(&state, &stats, &queue_tx, seeds).await;

        let janitor_handle = tokio::spawn(run_janitor(
            Arc::clone(&state),
            Arc::clone(&stop),
            self.config.max_runtime,
            self.config.idle_timeout,
            self.config.janitor_tick,
        ));
        let signal_handle = tokio::spawn(run_signal_shutdown(Arc::clone(&stop)));

        let worker_count = effective_worker_count(self.config.max_concurrency);
        let mut workers = Vec::with_capacity(worker_count);

        let processor: Arc<dyn NodeProcessor> = Arc::new(DefaultNodeProcessor);
        for _ in 0..worker_count {
            workers.push(tokio::spawn(run_worker(
                self.config,
                Arc::clone(&state),
                Arc::clone(&stats),
                Arc::clone(&stop),
                Arc::clone(&queue_rx),
                queue_tx.clone(),
                Arc::clone(&processor),
            )));
        }

        for handle in workers {
            if let Err(err) = handle.await {
                warn!("[crawler] worker join error: {err}");
            }
        }

        stop.store(true, Ordering::Relaxed);
        let _ = janitor_handle.await;
        signal_handle.abort();

        let state_guard = state.lock().await;
        Ok(CrawlSummary {
            scheduled_tasks: stats.scheduled.load(Ordering::Relaxed),
            successful_handshakes: stats.success.load(Ordering::Relaxed),
            failed_tasks: stats.failed.load(Ordering::Relaxed),
            queued_nodes_total: stats.queued_total.load(Ordering::Relaxed),
            unique_nodes: state_guard.queued_nodes.len(),
            discovered_node_states: state_guard.node_states.len(),
            elapsed: started_at.elapsed(),
        })
    }
}

fn effective_worker_count(max_concurrency: usize) -> usize {
    max_concurrency.max(1)
}

async fn run_signal_shutdown(stop: Arc<AtomicBool>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(err) => {
                warn!("[crawler] failed to install SIGTERM handler: {err}");
                return;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("[crawler] received Ctrl+C/SIGINT, shutting down gracefully");
            }
            _ = term.recv() => {
                info!("[crawler] received SIGTERM, shutting down gracefully");
            }
        }
    }

    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("[crawler] received Ctrl+C/SIGINT, shutting down gracefully");
        }
    }

    stop.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::effective_worker_count;

    #[test]
    fn worker_count_is_at_least_one() {
        assert_eq!(effective_worker_count(0), 1);
        assert_eq!(effective_worker_count(1), 1);
        assert_eq!(effective_worker_count(8), 8);
    }
}
