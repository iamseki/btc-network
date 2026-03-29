mod domain;
mod lifecycle;
mod node;
mod ports;
mod types;
mod worker;

use std::error::Error;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

pub use domain::{
    BatchId, CountNodesByAsnRow, CrawlEndpoint, CrawlNetwork, CrawlPhase, CrawlRunCheckpoint,
    CrawlRunId, CrawlRunMetrics, FailureClassification, HandshakeStatus, IpEnrichment,
    IpEnrichmentStatus, ObservationConfidence, ObservationId, PersistedNodeObservation,
    RawNodeObservation, StartCrawlRequest, StopCrawlRequest,
};
use lifecycle::{run_checkpoint_emitter, run_lifecycle, snapshot_checkpoint};
use node::{DefaultNodeProcessor, NodeProcessor, resolve_seed_nodes};
pub use ports::{
    CrawlerRepository, CrawlerRepositoryError, IpEnrichmentProvider, RepositoryFuture,
};
use types::{CrawlState, CrawlerStats};
pub use types::{CrawlSummary, CrawlerConfig, NodeState};
use worker::{run_worker, seed_initial_nodes};

pub struct Crawler {
    config: CrawlerConfig,
    repository: Arc<dyn CrawlerRepository>,
    enrichment_provider: Arc<dyn IpEnrichmentProvider>,
}

impl Crawler {
    pub fn new(config: CrawlerConfig) -> Self {
        Self::with_adapters(
            config,
            Arc::new(NoopCrawlerRepository),
            Arc::new(UnavailableIpEnrichmentProvider),
        )
    }

    pub fn with_adapters(
        config: CrawlerConfig,
        repository: Arc<dyn CrawlerRepository>,
        enrichment_provider: Arc<dyn IpEnrichmentProvider>,
    ) -> Self {
        Self {
            config,
            repository,
            enrichment_provider,
        }
    }

    pub async fn run(&self) -> Result<CrawlSummary, Box<dyn Error>> {
        let seed_nodes = resolve_seed_nodes()
            .into_iter()
            .map(CrawlEndpoint::from_socket_addr)
            .collect::<Vec<_>>();
        let request = StartCrawlRequest {
            config: self.config,
            seed_nodes,
        };
        let processor: Arc<dyn NodeProcessor> = Arc::new(DefaultNodeProcessor);

        self.run_with_request(request, processor).await
    }

    async fn run_with_request(
        &self,
        request: StartCrawlRequest,
        processor: Arc<dyn NodeProcessor>,
    ) -> Result<CrawlSummary, Box<dyn Error>> {
        if request.seed_nodes.is_empty() {
            return Err("no seed addresses resolved".into());
        }

        let started_at = Instant::now();
        let started_at_utc = Utc::now();
        let run_id = CrawlRunId::new(format!(
            "crawl-{}-{:016x}",
            started_at_utc.timestamp_millis(),
            rand::random::<u64>()
        ));

        claim_active_run(active_run_slot(), run_id.clone()).await?;
        let result = self
            .run_active_request(run_id, request, processor, started_at, started_at_utc)
            .await;
        release_active_run(active_run_slot()).await;

        result
    }

    async fn run_active_request(
        &self,
        run_id: CrawlRunId,
        request: StartCrawlRequest,
        processor: Arc<dyn NodeProcessor>,
        started_at: Instant,
        started_at_utc: DateTime<Utc>,
    ) -> Result<CrawlSummary, Box<dyn Error>> {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let phase = Arc::new(Mutex::new(CrawlPhase::Bootstrap));

        let (queue_tx, queue_rx) = mpsc::unbounded_channel::<CrawlEndpoint>();
        let queue_rx = Arc::new(Mutex::new(queue_rx));
        let (observation_tx, observation_rx) =
            mpsc::channel::<PersistedNodeObservation>(writer_channel_capacity(request.config));

        seed_initial_nodes(&state, &stats, &queue_tx, request.seed_nodes).await;
        write_checkpoint(
            Arc::clone(&self.repository),
            run_id.clone(),
            CrawlPhase::Bootstrap,
            &state,
            &stats,
            started_at_utc,
            None,
            None,
        )
        .await?;

        {
            let mut guard = phase.lock().await;
            *guard = CrawlPhase::Crawling;
        }
        write_checkpoint(
            Arc::clone(&self.repository),
            run_id.clone(),
            CrawlPhase::Crawling,
            &state,
            &stats,
            started_at_utc,
            None,
            None,
        )
        .await?;

        let writer_handle = tokio::spawn(run_observation_writer(
            Arc::clone(&self.repository),
            Arc::clone(&stats),
            Arc::clone(&stop),
            observation_rx,
            writer_batch_size(request.config),
        ));
        let lifecycle_handle = tokio::spawn(run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            request.config.max_runtime,
            request.config.idle_timeout,
            request.config.lifecycle_tick,
        ));
        let checkpoint_handle = tokio::spawn(run_checkpoint_emitter(
            Arc::clone(&self.repository),
            run_id.clone(),
            Arc::clone(&phase),
            Arc::clone(&state),
            Arc::clone(&stats),
            Arc::clone(&stop),
            started_at_utc,
            request.config.lifecycle_tick,
        ));
        let signal_handle = tokio::spawn(run_signal_shutdown(Arc::clone(&stop)));

        let worker_count = effective_worker_count(request.config.max_concurrency);
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            workers.push(tokio::spawn(run_worker(
                request.config,
                run_id.clone(),
                Arc::clone(&state),
                Arc::clone(&stats),
                Arc::clone(&stop),
                Arc::clone(&queue_rx),
                queue_tx.clone(),
                observation_tx.clone(),
                Arc::clone(&processor),
                Arc::clone(&self.enrichment_provider),
            )));
        }
        drop(queue_tx);
        drop(observation_tx);

        let mut failure_reason = None;
        for handle in workers {
            if let Err(err) = handle.await {
                warn!("[crawler] worker join error: {err}");
                stop.store(true, Ordering::Relaxed);
                failure_reason = Some(format!("worker join error: {err}"));
            }
        }

        {
            let mut guard = phase.lock().await;
            *guard = CrawlPhase::Draining;
        }
        write_checkpoint(
            Arc::clone(&self.repository),
            run_id.clone(),
            CrawlPhase::Draining,
            &state,
            &stats,
            started_at_utc,
            Some("workers drained".to_string()),
            failure_reason.clone(),
        )
        .await?;

        stop.store(true, Ordering::Relaxed);
        let writer_result = match writer_handle.await {
            Ok(result) => result,
            Err(err) => Err(CrawlerRepositoryError::new(format!(
                "writer task join error: {err}"
            ))),
        };
        if let Err(err) = writer_result {
            failure_reason = Some(err.to_string());
        }

        let _ = lifecycle_handle.await;
        let _ = checkpoint_handle.await;
        signal_handle.abort();

        let final_phase = if failure_reason.is_some() {
            CrawlPhase::Failed
        } else {
            CrawlPhase::Completed
        };
        {
            let mut guard = phase.lock().await;
            *guard = final_phase;
        }
        write_checkpoint(
            Arc::clone(&self.repository),
            run_id,
            final_phase,
            &state,
            &stats,
            started_at_utc,
            Some("crawl finished".to_string()),
            failure_reason.clone(),
        )
        .await?;

        if let Some(reason) = failure_reason {
            return Err(reason.into());
        }

        let state_guard = state.lock().await;
        Ok(CrawlSummary {
            scheduled_tasks: stats.scheduled.load(Ordering::Relaxed),
            successful_handshakes: stats.success.load(Ordering::Relaxed),
            failed_tasks: stats.failed.load(Ordering::Relaxed),
            queued_nodes_total: stats.queued_total.load(Ordering::Relaxed),
            unique_nodes: state_guard.seen_nodes.len(),
            discovered_node_states: state_guard.node_states.len(),
            elapsed: started_at.elapsed(),
        })
    }
}

fn effective_worker_count(max_concurrency: usize) -> usize {
    max_concurrency.max(1)
}

fn writer_channel_capacity(config: CrawlerConfig) -> usize {
    effective_worker_count(config.max_concurrency).max(1) * 2
}

fn writer_batch_size(config: CrawlerConfig) -> usize {
    effective_worker_count(config.max_concurrency).max(1)
}

fn active_run_slot() -> &'static Arc<Mutex<Option<CrawlRunId>>> {
    static ACTIVE_RUN: OnceLock<Arc<Mutex<Option<CrawlRunId>>>> = OnceLock::new();
    ACTIVE_RUN.get_or_init(|| Arc::new(Mutex::new(None)))
}

async fn claim_active_run(
    active_run: &Arc<Mutex<Option<CrawlRunId>>>,
    run_id: CrawlRunId,
) -> Result<(), Box<dyn Error>> {
    let mut guard = active_run.lock().await;
    if let Some(existing) = guard.as_ref() {
        return Err(format!("crawl run {} is already active", existing.as_str()).into());
    }

    *guard = Some(run_id);
    Ok(())
}

async fn release_active_run(active_run: &Arc<Mutex<Option<CrawlRunId>>>) {
    let mut guard = active_run.lock().await;
    *guard = None;
}

async fn write_checkpoint(
    repository: Arc<dyn CrawlerRepository>,
    run_id: CrawlRunId,
    phase: CrawlPhase,
    state: &Arc<Mutex<CrawlState>>,
    stats: &Arc<CrawlerStats>,
    started_at: DateTime<Utc>,
    stop_reason: Option<String>,
    failure_reason: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let mut checkpoint = snapshot_checkpoint(run_id, phase, state, stats, started_at).await;
    checkpoint.stop_reason = stop_reason;
    checkpoint.failure_reason = failure_reason;
    repository.insert_run_checkpoint(checkpoint).await?;
    Ok(())
}

async fn run_observation_writer(
    repository: Arc<dyn CrawlerRepository>,
    stats: Arc<CrawlerStats>,
    stop: Arc<AtomicBool>,
    mut observation_rx: mpsc::Receiver<PersistedNodeObservation>,
    batch_size: usize,
) -> Result<(), CrawlerRepositoryError> {
    let batch_size = batch_size.max(1);

    loop {
        let Some(first) = observation_rx.recv().await else {
            return Ok(());
        };

        let mut batch = vec![first];
        while batch.len() < batch_size {
            match observation_rx.try_recv() {
                Ok(observation) => batch.push(observation),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let batch_len = batch.len();
        if let Err(err) = repository.insert_observations_stream(batch).await {
            stop.store(true, Ordering::Relaxed);
            return Err(err);
        }

        stats.persisted_rows.fetch_add(batch_len, Ordering::Relaxed);
        stats.writer_backlog.fetch_sub(batch_len, Ordering::Relaxed);
    }
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

struct UnavailableIpEnrichmentProvider;

impl IpEnrichmentProvider for UnavailableIpEnrichmentProvider {
    fn enrich(&self, _endpoint: &CrawlEndpoint) -> IpEnrichment {
        IpEnrichment::unavailable()
    }
}

struct NoopCrawlerRepository;

impl CrawlerRepository for NoopCrawlerRepository {
    fn insert_observation<'a>(
        &'a self,
        _observation: PersistedNodeObservation,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async { Ok(()) })
    }

    fn insert_observations_stream<'a>(
        &'a self,
        _observations: Vec<PersistedNodeObservation>,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async { Ok(()) })
    }

    fn insert_run_checkpoint<'a>(
        &'a self,
        _checkpoint: CrawlRunCheckpoint,
    ) -> RepositoryFuture<'a, Result<(), CrawlerRepositoryError>> {
        Box::pin(async { Ok(()) })
    }

    fn get_run_checkpoint<'a>(
        &'a self,
        _run_id: &'a CrawlRunId,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async { Ok(None) })
    }

    fn list_runs<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn count_nodes_by_asn<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_count_is_at_least_one() {
        assert_eq!(effective_worker_count(0), 1);
        assert_eq!(effective_worker_count(1), 1);
        assert_eq!(effective_worker_count(8), 8);
    }

    #[tokio::test]
    async fn active_run_claim_rejects_second_run() {
        let active_run = Arc::new(Mutex::new(None));

        claim_active_run(&active_run, CrawlRunId::new("run-1"))
            .await
            .expect("first claim");
        let err = claim_active_run(&active_run, CrawlRunId::new("run-2"))
            .await
            .expect_err("second claim should fail");

        assert!(err.to_string().contains("already active"));

        release_active_run(&active_run).await;
        claim_active_run(&active_run, CrawlRunId::new("run-3"))
            .await
            .expect("claim after release");
    }

    #[tokio::test]
    async fn active_run_slot_is_shared_process_wide() {
        release_active_run(active_run_slot()).await;
        claim_active_run(active_run_slot(), CrawlRunId::new("run-1"))
            .await
            .expect("claim shared slot");

        let err = claim_active_run(active_run_slot(), CrawlRunId::new("run-2"))
            .await
            .expect_err("second shared claim should fail");

        assert!(err.to_string().contains("already active"));
        release_active_run(active_run_slot()).await;
    }
}
