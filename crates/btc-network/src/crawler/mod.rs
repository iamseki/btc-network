mod analytics;
mod domain;
mod lifecycle;
mod node;
mod ports;
mod types;
mod worker;

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, mpsc};
use tokio::task::{JoinError, JoinHandle};
use tracing::{info, warn};

pub use analytics::{
    AsnNodeCountItem, CrawlRunCheckpointItem, CrawlRunDetail, CrawlRunListItem,
    FailureClassificationCount, NetworkOutcomeCount,
};
pub use domain::{
    BatchId, CountNodesByAsnRow, CrawlEndpoint, CrawlNetwork, CrawlPhase, CrawlRunCheckpoint,
    CrawlRunId, CrawlRunMetrics, FailureClassification, HandshakeStatus, IpEnrichment,
    IpEnrichmentStatus, ObservationConfidence, ObservationId, PersistedNodeObservation,
    RawNodeObservation, StartCrawlRequest, StopCrawlRequest,
};
use lifecycle::{
    CheckpointEmitterContext, deserialize_resume_state, run_checkpoint_emitter, run_lifecycle,
    snapshot_checkpoint,
};
use node::{DefaultNodeProcessor, NodeProcessor, resolve_seed_nodes};
pub use ports::{
    CrawlerAnalyticsReader, CrawlerRepository, CrawlerRepositoryError, IpEnrichmentProvider,
    RepositoryFuture,
};
use types::{CrawlState, CrawlerStats};
pub use types::{CrawlSummary, CrawlerConfig, NodeState};
use worker::{run_worker, seed_initial_nodes};

/// High-level crawler facade that wires runtime orchestration to storage and
/// enrichment adapters.
///
/// The crawler owns concurrency, recovery, checkpointing, and stop-policy
/// evaluation. Protocol parsing and peer-session behavior remain in the shared
/// lower layers.
pub struct Crawler {
    config: CrawlerConfig,
    repository: Arc<dyn CrawlerRepository>,
    enrichment_provider: Arc<dyn IpEnrichmentProvider>,
}

impl Crawler {
    /// Builds a crawler with in-memory no-op adapters.
    ///
    /// Useful for tests or local experimentation where durable persistence and
    /// IP enrichment are not required.
    pub fn new(config: CrawlerConfig) -> Self {
        Self::with_adapters(
            config,
            Arc::new(NoopCrawlerRepository),
            Arc::new(UnavailableIpEnrichmentProvider),
        )
    }

    /// Builds a crawler with explicit storage and enrichment adapters.
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

    /// Starts a crawl from the configured Bitcoin DNS seeds.
    ///
    /// If the repository exposes a durable active checkpoint, startup will try
    /// to recover that run before beginning a fresh crawl. Recovery assumes one
    /// crawler coordinator process writes to a given persistence database at a
    /// time. That single-active-run constraint is enforced outside this crawler
    /// implementation.
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

        self.run_with_request_or_recover(request, processor).await
    }

    async fn run_with_request_or_recover(
        &self,
        request: StartCrawlRequest,
        processor: Arc<dyn NodeProcessor>,
    ) -> Result<CrawlSummary, Box<dyn Error>> {
        if let Some(summary) = self
            .try_recover_latest_run(request.config, Arc::clone(&processor))
            .await?
        {
            return Ok(summary);
        }

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

        self.run_active_request(run_id, request, processor, started_at, started_at_utc)
            .await
    }

    async fn try_recover_latest_run(
        &self,
        config: CrawlerConfig,
        processor: Arc<dyn NodeProcessor>,
    ) -> Result<Option<CrawlSummary>, Box<dyn Error>> {
        let Some(checkpoint) = self.repository.get_latest_active_run_checkpoint().await? else {
            return Ok(None);
        };

        let state = match restore_state_from_checkpoint(&checkpoint) {
            Ok(state) => state,
            Err(err) => {
                self.mark_recovery_failed(&checkpoint, err).await?;
                return Ok(None);
            }
        };

        let run_id = checkpoint.run_id.clone();
        let started_at = recovered_started_at(checkpoint.started_at);

        info!(
            run_id = %run_id.as_str(),
            checkpoint_phase = ?checkpoint.phase,
            checkpoint_sequence = checkpoint.checkpoint_sequence,
            "[crawler] recovering active run from durable checkpoint"
        );

        self.run_recovered_request(checkpoint, state, processor, started_at, config)
        .await
        .map(Some)
    }

    async fn mark_recovery_failed(
        &self,
        checkpoint: &CrawlRunCheckpoint,
        reason: String,
    ) -> Result<(), CrawlerRepositoryError> {
        warn!(
            run_id = %checkpoint.run_id.as_str(),
            checkpoint_phase = ?checkpoint.phase,
            checkpoint_sequence = checkpoint.checkpoint_sequence,
            reason = %reason,
            "[crawler] failed to restore run from durable checkpoint; writing terminal failure checkpoint"
        );

        let mut failed_checkpoint = checkpoint.clone();
        failed_checkpoint.phase = CrawlPhase::Failed;
        failed_checkpoint.checkpointed_at = Utc::now();
        failed_checkpoint.checkpoint_sequence += 1;
        failed_checkpoint.stop_reason = Some("startup recovery failed".to_string());
        failed_checkpoint.failure_reason = Some(reason);
        failed_checkpoint.caller = Some("startup-recovery".to_string());

        self.repository
            .insert_run_checkpoint(failed_checkpoint)
            .await
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
        let checkpoint_sequence = Arc::new(AtomicU64::new(0));
        let phase = Arc::new(Mutex::new(CrawlPhase::Bootstrap));

        let checkpoint_context = CheckpointWriteContext {
            repository: Arc::clone(&self.repository),
            run_id: run_id.clone(),
            state: Arc::clone(&state),
            stats: Arc::clone(&stats),
            checkpoint_sequence: Arc::clone(&checkpoint_sequence),
            started_at: started_at_utc,
        };

        let (queue_tx, _queue_rx) = mpsc::unbounded_channel::<CrawlEndpoint>();

        seed_initial_nodes(
            &state,
            &stats,
            &queue_tx,
            request.seed_nodes,
            request.config.max_tracked_nodes,
        )
        .await;
        write_checkpoint(&checkpoint_context, CrawlPhase::Bootstrap, None, None).await?;

        {
            let mut guard = phase.lock().await;
            let from_phase = *guard;
            *guard = CrawlPhase::Crawling;
            info!(
                run_id = %run_id.as_str(),
                from_phase = ?from_phase,
                to_phase = ?CrawlPhase::Crawling,
                "[crawler] phase transition"
            );
        }
        write_checkpoint(&checkpoint_context, CrawlPhase::Crawling, None, None).await?;

        let initial_frontier = pending_frontier(&state).await;

        self.run_loaded_request(
            run_id,
            request.config,
            processor,
            started_at,
            started_at_utc,
            state,
            stats,
            checkpoint_sequence,
            phase,
            initial_frontier,
        )
        .await
    }

    async fn run_recovered_request(
        &self,
        checkpoint: CrawlRunCheckpoint,
        restored_state: CrawlState,
        processor: Arc<dyn NodeProcessor>,
        started_at: Instant,
        config: CrawlerConfig,
    ) -> Result<CrawlSummary, Box<dyn Error>> {
        let run_id = checkpoint.run_id.clone();
        let started_at_utc = checkpoint.started_at;
        let state = Arc::new(Mutex::new(restored_state));
        let stats = Arc::new(restore_stats_from_checkpoint(&checkpoint));
        let checkpoint_sequence = Arc::new(AtomicU64::new(checkpoint.checkpoint_sequence));
        let phase = Arc::new(Mutex::new(CrawlPhase::Crawling));
        let checkpoint_context = CheckpointWriteContext {
            repository: Arc::clone(&self.repository),
            run_id: run_id.clone(),
            state: Arc::clone(&state),
            stats: Arc::clone(&stats),
            checkpoint_sequence: Arc::clone(&checkpoint_sequence),
            started_at: started_at_utc,
        };

        info!(
            run_id = %run_id.as_str(),
            from_phase = ?checkpoint.phase,
            to_phase = ?CrawlPhase::Crawling,
            "[crawler] phase transition"
        );
        write_checkpoint(
            &checkpoint_context,
            CrawlPhase::Crawling,
            Some(format!(
                "recovered from {:?} checkpoint {}",
                checkpoint.phase, checkpoint.checkpoint_sequence
            )),
            None,
        )
        .await?;

        let initial_frontier = pending_frontier(&state).await;

        self.run_loaded_request(
            run_id,
            config,
            processor,
            started_at,
            started_at_utc,
            state,
            stats,
            checkpoint_sequence,
            phase,
            initial_frontier,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_loaded_request(
        &self,
        run_id: CrawlRunId,
        config: CrawlerConfig,
        processor: Arc<dyn NodeProcessor>,
        started_at: Instant,
        started_at_utc: DateTime<Utc>,
        state: Arc<Mutex<CrawlState>>,
        stats: Arc<CrawlerStats>,
        checkpoint_sequence: Arc<AtomicU64>,
        phase: Arc<Mutex<CrawlPhase>>,
        initial_frontier: Vec<CrawlEndpoint>,
    ) -> Result<CrawlSummary, Box<dyn Error>> {
        let stop = Arc::new(AtomicBool::new(false));

        let checkpoint_context = CheckpointWriteContext {
            repository: Arc::clone(&self.repository),
            run_id: run_id.clone(),
            state: Arc::clone(&state),
            stats: Arc::clone(&stats),
            checkpoint_sequence: Arc::clone(&checkpoint_sequence),
            started_at: started_at_utc,
        };

        let (queue_tx, queue_rx) = mpsc::unbounded_channel::<CrawlEndpoint>();
        for endpoint in initial_frontier {
            let _ = queue_tx.send(endpoint);
        }
        let queue_rx = Arc::new(Mutex::new(queue_rx));
        let (observation_tx, observation_rx) =
            mpsc::channel::<PersistedNodeObservation>(writer_channel_capacity(config));

        // Split long-running crawler responsibilities into focused tasks:
        // workers visit nodes and enqueue observations, the writer persists
        // observation batches, the lifecycle task flips `stop` on policy
        // conditions, the checkpoint emitter persists background progress, and
        // the signal task translates process signals into graceful shutdown.
        let writer_handle = AbortOnDropHandle::new(tokio::spawn(run_observation_writer(
            Arc::clone(&self.repository),
            Arc::clone(&stats),
            Arc::clone(&stop),
            observation_rx,
            writer_batch_size(config),
        )));
        let lifecycle_handle = AbortOnDropHandle::new(tokio::spawn(run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            started_at,
            config.max_runtime,
            config.idle_timeout,
            config.lifecycle_tick,
        )));
        let checkpoint_handle = AbortOnDropHandle::new(tokio::spawn(run_checkpoint_emitter(
            CheckpointEmitterContext {
                repository: Arc::clone(&self.repository),
                run_id: run_id.clone(),
                phase: Arc::clone(&phase),
                state: Arc::clone(&state),
                stats: Arc::clone(&stats),
                checkpoint_sequence: Arc::clone(&checkpoint_sequence),
                stop: Arc::clone(&stop),
                started_at: started_at_utc,
                tick_every: config.lifecycle_tick,
            },
        )));
        let signal_handle =
            AbortOnDropHandle::new(tokio::spawn(run_signal_shutdown(Arc::clone(&stop))));

        let worker_count = effective_worker_count(config.max_concurrency);
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            workers.push(AbortOnDropHandle::new(tokio::spawn(run_worker(
                worker::WorkerContext {
                    config,
                    run_id: run_id.clone(),
                    state: Arc::clone(&state),
                    stats: Arc::clone(&stats),
                    stop: Arc::clone(&stop),
                    queue_rx: Arc::clone(&queue_rx),
                    queue_tx: queue_tx.clone(),
                    observation_tx: observation_tx.clone(),
                    processor: Arc::clone(&processor),
                    enrichment_provider: Arc::clone(&self.enrichment_provider),
                },
            ))));
        }
        drop(queue_tx);
        drop(observation_tx);

        let mut task_set = CrawlTaskSet::new(
            Arc::clone(&stop),
            workers,
            writer_handle,
            lifecycle_handle,
            checkpoint_handle,
            signal_handle,
        );

        let mut failure_reason = None;
        let drained_workers = drain_workers_with_grace_period(
            &mut task_set.worker_handles,
            config.shutdown_grace_period,
            &stop,
            &mut failure_reason,
        )
        .await;

        if !drained_workers {
            warn!(
                "[crawler] worker shutdown grace period elapsed after {:?}; aborting remaining workers",
                config.shutdown_grace_period
            );
        }

        {
            let mut guard = phase.lock().await;
            let from_phase = *guard;
            *guard = CrawlPhase::Draining;
            info!(
                run_id = %checkpoint_context.run_id.as_str(),
                from_phase = ?from_phase,
                to_phase = ?CrawlPhase::Draining,
                "[crawler] phase transition"
            );
        }
        write_checkpoint(
            &checkpoint_context,
            CrawlPhase::Draining,
            Some(if drained_workers {
                "workers drained".to_string()
            } else {
                format!(
                    "worker shutdown grace period elapsed after {:?}; forced abort",
                    config.shutdown_grace_period
                )
            }),
            failure_reason.clone(),
        )
        .await?;

        stop.store(true, Ordering::Relaxed);
        let writer_result =
            task_set.writer_handle.join().await.map_err(|err| {
                CrawlerRepositoryError::new(format!("writer task join error: {err}"))
            })?;
        if let Err(err) = writer_result {
            record_failure(&mut failure_reason, err.to_string());
        }

        let _ = task_set.lifecycle_handle.join().await;
        let checkpoint_result = task_set.checkpoint_handle.join().await.map_err(|err| {
            CrawlerRepositoryError::new(format!("checkpoint emitter join error: {err}"))
        })?;
        if let Err(err) = checkpoint_result {
            record_failure(&mut failure_reason, err.to_string());
        }
        task_set.signal_handle.abort();

        let final_phase = if failure_reason.is_some() {
            CrawlPhase::Failed
        } else {
            CrawlPhase::Completed
        };
        {
            let mut guard = phase.lock().await;
            let from_phase = *guard;
            *guard = final_phase;
            info!(
                run_id = %checkpoint_context.run_id.as_str(),
                from_phase = ?from_phase,
                to_phase = ?final_phase,
                "[crawler] phase transition"
            );
        }
        write_checkpoint(
            &CheckpointWriteContext {
                run_id,
                ..checkpoint_context
            },
            final_phase,
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

async fn pending_frontier(state: &Arc<Mutex<CrawlState>>) -> Vec<CrawlEndpoint> {
    let mut pending = state
        .lock()
        .await
        .pending_nodes
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    pending.sort_by(|left, right| left.canonical.cmp(&right.canonical));
    pending
}

fn restore_state_from_checkpoint(checkpoint: &CrawlRunCheckpoint) -> Result<CrawlState, String> {
    let resume_state = checkpoint.resume_state.as_deref().ok_or_else(|| {
        format!(
            "checkpoint {} is missing resume state",
            checkpoint.checkpoint_sequence
        )
    })?;
    let resume_state = deserialize_resume_state(resume_state).map_err(|err| {
        format!(
            "checkpoint {} resume state could not be parsed: {err}",
            checkpoint.checkpoint_sequence
        )
    })?;

    Ok(CrawlState::from_resume_state(resume_state))
}

fn restore_stats_from_checkpoint(checkpoint: &CrawlRunCheckpoint) -> CrawlerStats {
    let metrics = &checkpoint.metrics;
    let stats = CrawlerStats::default();
    stats
        .scheduled
        .store(metrics.scheduled_tasks, Ordering::Relaxed);
    stats
        .success
        .store(metrics.successful_handshakes, Ordering::Relaxed);
    stats.failed.store(metrics.failed_tasks, Ordering::Relaxed);
    stats
        .queued_total
        .store(metrics.queued_nodes_total, Ordering::Relaxed);
    stats
        .persisted_rows
        .store(metrics.persisted_observation_rows, Ordering::Relaxed);
    stats.in_flight.store(0, Ordering::Relaxed);
    stats.writer_backlog.store(0, Ordering::Relaxed);
    stats
}

fn recovered_started_at(started_at_utc: DateTime<Utc>) -> Instant {
    let elapsed = (Utc::now() - started_at_utc)
        .to_std()
        .unwrap_or(Duration::ZERO);
    Instant::now() - elapsed
}

fn record_failure(failure_reason: &mut Option<String>, reason: String) {
    if failure_reason.is_none() {
        *failure_reason = Some(reason);
    }
}

async fn drain_workers_with_grace_period(
    worker_handles: &mut Vec<AbortOnDropHandle<()>>,
    shutdown_grace_period: Duration,
    stop: &Arc<AtomicBool>,
    failure_reason: &mut Option<String>,
) -> bool {
    let mut shutdown_started = None;

    while let Some(mut handle) = worker_handles.pop() {
        while !handle.is_finished() {
            if stop.load(Ordering::Relaxed) {
                let started = shutdown_started.get_or_insert_with(Instant::now);
                if started.elapsed() >= shutdown_grace_period {
                    record_failure(
                        failure_reason,
                        format!(
                            "worker shutdown grace period elapsed after {:?}",
                            shutdown_grace_period
                        ),
                    );
                    handle.abort();
                    abort_remaining_workers(worker_handles);
                    stop.store(true, Ordering::Relaxed);
                    return false;
                }
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        match handle.join().await {
            Ok(()) => {}
            Err(err) => {
                warn!("[crawler] worker join error: {err}");
                stop.store(true, Ordering::Relaxed);
                record_failure(failure_reason, format!("worker join error: {err}"));
            }
        }
    }

    true
}

fn abort_remaining_workers(worker_handles: &mut Vec<AbortOnDropHandle<()>>) {
    for handle in worker_handles.iter_mut() {
        handle.abort();
    }
    worker_handles.clear();
}

struct AbortOnDropHandle<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropHandle<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    async fn join(&mut self) -> Result<T, JoinError> {
        let handle = self.handle.take().expect("join handle present");
        handle.await
    }

    fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl<T> Drop for AbortOnDropHandle<T> {
    fn drop(&mut self) {
        self.abort();
    }
}

struct CrawlTaskSet {
    stop: Arc<AtomicBool>,
    worker_handles: Vec<AbortOnDropHandle<()>>,
    writer_handle: AbortOnDropHandle<Result<(), CrawlerRepositoryError>>,
    lifecycle_handle: AbortOnDropHandle<()>,
    checkpoint_handle: AbortOnDropHandle<Result<(), CrawlerRepositoryError>>,
    signal_handle: AbortOnDropHandle<()>,
}

impl CrawlTaskSet {
    fn new(
        stop: Arc<AtomicBool>,
        worker_handles: Vec<AbortOnDropHandle<()>>,
        writer_handle: AbortOnDropHandle<Result<(), CrawlerRepositoryError>>,
        lifecycle_handle: AbortOnDropHandle<()>,
        checkpoint_handle: AbortOnDropHandle<Result<(), CrawlerRepositoryError>>,
        signal_handle: AbortOnDropHandle<()>,
    ) -> Self {
        Self {
            stop,
            worker_handles,
            writer_handle,
            lifecycle_handle,
            checkpoint_handle,
            signal_handle,
        }
    }
}

impl Drop for CrawlTaskSet {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct CheckpointWriteContext {
    repository: Arc<dyn CrawlerRepository>,
    run_id: CrawlRunId,
    state: Arc<Mutex<CrawlState>>,
    stats: Arc<CrawlerStats>,
    checkpoint_sequence: Arc<AtomicU64>,
    started_at: DateTime<Utc>,
}

async fn write_checkpoint(
    context: &CheckpointWriteContext,
    phase: CrawlPhase,
    stop_reason: Option<String>,
    failure_reason: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let mut checkpoint = snapshot_checkpoint(
        context.run_id.clone(),
        phase,
        &context.state,
        &context.stats,
        &context.checkpoint_sequence,
        context.started_at,
    )
    .await;
    checkpoint.stop_reason = stop_reason;
    checkpoint.failure_reason = failure_reason;
    context.repository.insert_run_checkpoint(checkpoint).await?;
    Ok(())
}

/// Persists node observations produced by workers.
///
/// Workers never write directly to the repository. They send one
/// `PersistedNodeObservation` at a time into the bounded channel, and this task
/// owns the durable write boundary by draining that channel into small batches.
/// If the repository write fails, it requests global shutdown through `stop`
/// and returns the repository error to the coordinator.
async fn run_observation_writer(
    repository: Arc<dyn CrawlerRepository>,
    stats: Arc<CrawlerStats>,
    stop: Arc<AtomicBool>,
    mut observation_rx: mpsc::Receiver<PersistedNodeObservation>,
    batch_size: usize,
) -> Result<(), CrawlerRepositoryError> {
    let batch_size = batch_size.max(1);

    loop {
        // Wait for the first item so an idle writer does not spin or emit empty
        // writes.
        let Some(first) = observation_rx.recv().await else {
            return Ok(());
        };

        let mut batch = vec![first];
        // After the first blocking receive, drain whatever is already queued so
        // adapters can amortize persistence without adding extra delay.
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

/// Translates process signals into the crawler's shared shutdown flag.
///
/// This keeps OS signal handling out of the lifecycle policy loop. Runtime
/// limits, persistence failures, and operator interrupts all converge on the
/// same `stop` flag so workers and background tasks follow one shutdown path.
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

        // Treat Ctrl+C/SIGINT and SIGTERM the same way: request graceful
        // shutdown and let the coordinator drain tasks and write terminal
        // checkpoints.
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

    fn get_latest_active_run_checkpoint<'a>(
        &'a self,
    ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
        Box::pin(async { Ok(None) })
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
    use crate::crawler::types::{NodeVisit, NodeVisitResult};
    use crate::wire::message::Services;
    use chrono::Utc;
    use std::collections::VecDeque;
    use std::future::pending;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex as StdSyncMutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    #[test]
    fn worker_count_is_at_least_one() {
        assert_eq!(effective_worker_count(0), 1);
        assert_eq!(effective_worker_count(1), 1);
        assert_eq!(effective_worker_count(8), 8);
    }

    #[derive(Clone)]
    struct StaticNodeProcessor {
        visit: NodeVisit,
    }

    impl NodeProcessor for StaticNodeProcessor {
        fn process<'a>(
            &'a self,
            _endpoint: CrawlEndpoint,
            _config: CrawlerConfig,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NodeVisitResult> + Send + 'a>>
        {
            let visit = self.visit.clone();
            Box::pin(async move { Ok(visit) })
        }
    }

    #[derive(Default)]
    struct FlakyCheckpointRepository {
        checkpoint_results: StdSyncMutex<VecDeque<Result<(), CrawlerRepositoryError>>>,
        observations: StdSyncMutex<Vec<PersistedNodeObservation>>,
        checkpoints: StdSyncMutex<Vec<CrawlRunCheckpoint>>,
    }

    impl FlakyCheckpointRepository {
        fn new(checkpoint_results: Vec<Result<(), CrawlerRepositoryError>>) -> Self {
            Self {
                checkpoint_results: StdSyncMutex::new(VecDeque::from(checkpoint_results)),
                observations: StdSyncMutex::new(Vec::new()),
                checkpoints: StdSyncMutex::new(Vec::new()),
            }
        }
    }

    impl CrawlerRepository for FlakyCheckpointRepository {
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
                let mut results = self
                    .checkpoint_results
                    .lock()
                    .expect("checkpoint results lock");
                match results.pop_front() {
                    Some(result) => result,
                    None => Ok(()),
                }
            })
        }

        fn get_run_checkpoint<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(None) })
        }

        fn list_runs<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(self.checkpoints.lock().expect("checkpoints lock").clone()) })
        }

        fn get_latest_active_run_checkpoint<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
        {
            Box::pin(async {
                Ok(self
                    .checkpoints
                    .lock()
                    .expect("checkpoints lock")
                    .iter()
                    .rev()
                    .find(|checkpoint| {
                        matches!(
                            checkpoint.phase,
                            CrawlPhase::Bootstrap | CrawlPhase::Crawling | CrawlPhase::Draining
                        )
                    })
                    .cloned())
            })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    struct StaticEnrichmentProvider;

    impl IpEnrichmentProvider for StaticEnrichmentProvider {
        fn enrich(&self, _endpoint: &CrawlEndpoint) -> IpEnrichment {
            IpEnrichment::unavailable()
        }
    }

    fn public_endpoint(octet: u8) -> CrawlEndpoint {
        CrawlEndpoint::new(
            format!("1.1.1.{octet}"),
            8333,
            CrawlNetwork::Ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, octet))),
        )
    }

    fn static_visit(endpoint: CrawlEndpoint) -> NodeVisit {
        NodeVisit {
            node: endpoint,
            state: NodeState {
                version: 70016,
                services: Services::NODE_WITNESS.bits(),
                user_agent: "/Satoshi:27.0.0/".to_string(),
                start_height: 900_000,
                relay: Some(true),
                timestamp: Utc::now().timestamp(),
            },
            discovered: Vec::new(),
            latency: Duration::from_millis(5),
        }
    }

    #[derive(Default)]
    struct RecoveryRepository {
        initial_runs: StdSyncMutex<Vec<CrawlRunCheckpoint>>,
        inserted_checkpoints: StdSyncMutex<Vec<CrawlRunCheckpoint>>,
        observations: StdSyncMutex<Vec<PersistedNodeObservation>>,
    }

    impl RecoveryRepository {
        fn with_runs(runs: Vec<CrawlRunCheckpoint>) -> Self {
            Self {
                initial_runs: StdSyncMutex::new(runs),
                inserted_checkpoints: StdSyncMutex::new(Vec::new()),
                observations: StdSyncMutex::new(Vec::new()),
            }
        }
    }

    impl CrawlerRepository for RecoveryRepository {
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
                self.inserted_checkpoints
                    .lock()
                    .expect("inserted checkpoints lock")
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
                let latest_inserted = self
                    .inserted_checkpoints
                    .lock()
                    .expect("inserted checkpoints lock")
                    .iter()
                    .filter(|checkpoint| checkpoint.run_id == *run_id)
                    .max_by(|left, right| {
                        left.checkpointed_at
                            .cmp(&right.checkpointed_at)
                            .then(left.checkpoint_sequence.cmp(&right.checkpoint_sequence))
                    })
                    .cloned();

                if latest_inserted.is_some() {
                    return Ok(latest_inserted);
                }

                Ok(self
                    .initial_runs
                    .lock()
                    .expect("initial runs lock")
                    .iter()
                    .find(|checkpoint| checkpoint.run_id == *run_id)
                    .cloned())
            })
        }

        fn list_runs<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
            Box::pin(
                async move { Ok(self.initial_runs.lock().expect("initial runs lock").clone()) },
            )
        }

        fn get_latest_active_run_checkpoint<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
        {
            Box::pin(async move {
                Ok(self
                    .initial_runs
                    .lock()
                    .expect("initial runs lock")
                    .iter()
                    .filter(|checkpoint| {
                        matches!(
                            checkpoint.phase,
                            CrawlPhase::Bootstrap | CrawlPhase::Crawling | CrawlPhase::Draining
                        )
                    })
                    .max_by(|left, right| {
                        left.checkpointed_at
                            .cmp(&right.checkpointed_at)
                            .then_with(|| left.checkpoint_sequence.cmp(&right.checkpoint_sequence))
                    })
                    .cloned())
            })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    struct SlowNodeProcessor {
        visit: NodeVisit,
        delay: Duration,
    }

    impl NodeProcessor for SlowNodeProcessor {
        fn process<'a>(
            &'a self,
            _endpoint: CrawlEndpoint,
            _config: CrawlerConfig,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NodeVisitResult> + Send + 'a>>
        {
            let visit = self.visit.clone();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(visit)
            })
        }
    }

    struct InFlightGuard<'a> {
        active: &'a AtomicUsize,
    }

    impl Drop for InFlightGuard<'_> {
        fn drop(&mut self) {
            self.active.fetch_sub(1, AtomicOrdering::Relaxed);
        }
    }

    struct BlockingPeriodicCheckpointRepository {
        checkpoint_calls: StdSyncMutex<usize>,
        active_periodic_writes: AtomicUsize,
    }

    impl BlockingPeriodicCheckpointRepository {
        fn new() -> Self {
            Self {
                checkpoint_calls: StdSyncMutex::new(0),
                active_periodic_writes: AtomicUsize::new(0),
            }
        }

        fn active_periodic_writes(&self) -> usize {
            self.active_periodic_writes.load(AtomicOrdering::Relaxed)
        }
    }

    impl CrawlerRepository for BlockingPeriodicCheckpointRepository {
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
            let should_block = {
                let mut calls = self.checkpoint_calls.lock().expect("checkpoint calls lock");
                *calls += 1;
                *calls >= 3
            };

            Box::pin(async move {
                if !should_block {
                    return Ok(());
                }

                self.active_periodic_writes
                    .fetch_add(1, AtomicOrdering::Relaxed);
                let _guard = InFlightGuard {
                    active: &self.active_periodic_writes,
                };
                pending::<Result<(), CrawlerRepositoryError>>().await
            })
        }

        fn get_run_checkpoint<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(None) })
        }

        fn list_runs<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn get_latest_active_run_checkpoint<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
        {
            Box::pin(async { Ok(None) })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn run_with_request_returns_error_when_periodic_checkpointing_fails() {
        let repository = Arc::new(FlakyCheckpointRepository::new(vec![
            Ok(()),
            Ok(()),
            Err(CrawlerRepositoryError::new("periodic checkpoint failed")),
            Ok(()),
            Ok(()),
        ]));
        let crawler = Crawler::with_adapters(
            CrawlerConfig {
                max_concurrency: 1,
                max_tracked_nodes: 16,
                max_runtime: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(1),
                lifecycle_tick: Duration::from_millis(5),
                connect_timeout: Duration::from_millis(50),
                connect_max_attempts: 1,
                connect_retry_backoff: Duration::ZERO,
                io_timeout: Duration::from_millis(50),
                shutdown_grace_period: Duration::from_secs(1),
                verbose: false,
            },
            repository,
            Arc::new(StaticEnrichmentProvider),
        );
        let seed = public_endpoint(7);
        let processor: Arc<dyn NodeProcessor> = Arc::new(StaticNodeProcessor {
            visit: static_visit(seed.clone()),
        });

        let err = crawler
            .run_with_request(
                StartCrawlRequest {
                    config: crawler.config,
                    seed_nodes: vec![seed],
                },
                processor,
            )
            .await
            .expect_err("checkpoint emitter failures should fail the crawl");

        assert!(err.to_string().contains("periodic checkpoint failed"));
    }

    #[tokio::test]
    async fn cancelling_run_aborts_periodic_checkpoint_task() {
        let repository = Arc::new(BlockingPeriodicCheckpointRepository::new());
        let crawler = Arc::new(Crawler::with_adapters(
            CrawlerConfig {
                max_concurrency: 1,
                max_tracked_nodes: 16,
                max_runtime: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(1),
                lifecycle_tick: Duration::from_millis(5),
                connect_timeout: Duration::from_millis(50),
                connect_max_attempts: 1,
                connect_retry_backoff: Duration::ZERO,
                io_timeout: Duration::from_millis(50),
                shutdown_grace_period: Duration::from_millis(20),
                verbose: false,
            },
            repository.clone(),
            Arc::new(StaticEnrichmentProvider),
        ));
        let seed = public_endpoint(9);
        let processor: Arc<dyn NodeProcessor> = Arc::new(SlowNodeProcessor {
            visit: static_visit(seed.clone()),
            delay: Duration::from_millis(100),
        });
        let request = StartCrawlRequest {
            config: crawler.config,
            seed_nodes: vec![seed],
        };

        let crawler_task = {
            let crawler = Arc::clone(&crawler);
            tokio::spawn(async move {
                let _ = crawler.run_with_request(request, processor).await;
            })
        };

        tokio::time::timeout(Duration::from_millis(200), async {
            while repository.active_periodic_writes() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("periodic checkpoint task should start");

        crawler_task.abort();
        let _ = crawler_task.await;

        tokio::time::timeout(Duration::from_millis(200), async {
            while repository.active_periodic_writes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("periodic checkpoint task should be aborted on cancellation");
    }

    #[tokio::test]
    async fn shutdown_grace_period_aborts_stuck_workers() {
        let stop = Arc::new(AtomicBool::new(true));
        let mut worker_handles = vec![AbortOnDropHandle::new(tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }))];
        let mut failure_reason = None;

        let drained = drain_workers_with_grace_period(
            &mut worker_handles,
            Duration::from_millis(20),
            &stop,
            &mut failure_reason,
        )
        .await;

        assert!(!drained, "worker timeout should force an abort");
        assert!(worker_handles.is_empty());
        assert!(
            failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("worker shutdown grace period elapsed"))
        );
    }

    #[tokio::test]
    async fn startup_recovery_resumes_latest_active_run_from_checkpoint() {
        let resumed_node = public_endpoint(21);
        let mut restored_state = CrawlState::new();
        restored_state.seen_nodes.insert(resumed_node.clone());
        // Simulate a crash after dequeue but before the node visit completed.
        restored_state.in_flight_nodes.insert(resumed_node.clone());

        let restored_state = Arc::new(Mutex::new(restored_state));
        let restored_stats = Arc::new(CrawlerStats::default());
        restored_stats.scheduled.store(3, AtomicOrdering::Relaxed);
        restored_stats.success.store(2, AtomicOrdering::Relaxed);
        let checkpoint = snapshot_checkpoint(
            CrawlRunId::new("run-recover-1"),
            CrawlPhase::Crawling,
            &restored_state,
            &restored_stats,
            &Arc::new(AtomicU64::new(0)),
            Utc::now(),
        )
        .await;

        let repository = Arc::new(RecoveryRepository::with_runs(vec![checkpoint.clone()]));
        let crawler = Crawler::with_adapters(
            CrawlerConfig {
                max_concurrency: 1,
                max_tracked_nodes: 16,
                max_runtime: Duration::from_millis(40),
                idle_timeout: Duration::from_millis(20),
                lifecycle_tick: Duration::from_millis(5),
                connect_timeout: Duration::from_millis(50),
                connect_max_attempts: 1,
                connect_retry_backoff: Duration::ZERO,
                io_timeout: Duration::from_millis(50),
                shutdown_grace_period: Duration::from_millis(400),
                verbose: false,
            },
            repository.clone(),
            Arc::new(StaticEnrichmentProvider),
        );
        let processor: Arc<dyn NodeProcessor> = Arc::new(StaticNodeProcessor {
            visit: static_visit(resumed_node.clone()),
        });

        let summary = crawler
            .run_with_request_or_recover(
                StartCrawlRequest {
                    config: crawler.config,
                    seed_nodes: vec![public_endpoint(99)],
                },
                processor,
            )
            .await
            .expect("recovery should succeed");

        assert_eq!(summary.scheduled_tasks, 4);
        assert_eq!(summary.successful_handshakes, 3);

        let observations = repository.observations.lock().expect("observations lock");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].raw.crawl_run_id, checkpoint.run_id);
        assert_eq!(observations[0].raw.endpoint, resumed_node);
        drop(observations);

        let checkpoints = repository
            .inserted_checkpoints
            .lock()
            .expect("inserted checkpoints lock");
        assert!(checkpoints.iter().any(|inserted| {
            inserted.run_id == checkpoint.run_id
                && inserted
                    .stop_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("recovered from"))
        }));
        assert!(
            checkpoints
                .iter()
                .all(|inserted| inserted.run_id == checkpoint.run_id)
        );
    }

    #[tokio::test]
    async fn startup_recovery_marks_invalid_checkpoint_failed_before_new_run() {
        let invalid_checkpoint = CrawlRunCheckpoint {
            run_id: CrawlRunId::new("run-recover-bad"),
            phase: CrawlPhase::Crawling,
            checkpointed_at: Utc::now(),
            checkpoint_sequence: 7,
            started_at: Utc::now(),
            stop_reason: None,
            failure_reason: None,
            metrics: CrawlRunMetrics {
                frontier_size: 1,
                in_flight_work: 0,
                scheduled_tasks: 0,
                successful_handshakes: 0,
                failed_tasks: 0,
                queued_nodes_total: 0,
                unique_nodes: 1,
                discovered_node_states: 0,
                persisted_observation_rows: 0,
                writer_backlog: 0,
            },
            resume_state: None,
            caller: None,
        };

        let repository = Arc::new(RecoveryRepository::with_runs(vec![
            invalid_checkpoint.clone(),
        ]));
        let crawler = Crawler::with_adapters(
            CrawlerConfig {
                max_concurrency: 1,
                max_tracked_nodes: 16,
                max_runtime: Duration::from_millis(40),
                idle_timeout: Duration::from_millis(20),
                lifecycle_tick: Duration::from_millis(5),
                connect_timeout: Duration::from_millis(50),
                connect_max_attempts: 1,
                connect_retry_backoff: Duration::ZERO,
                io_timeout: Duration::from_millis(50),
                shutdown_grace_period: Duration::from_millis(400),
                verbose: false,
            },
            repository.clone(),
            Arc::new(StaticEnrichmentProvider),
        );
        let seed = public_endpoint(31);
        let processor: Arc<dyn NodeProcessor> = Arc::new(StaticNodeProcessor {
            visit: static_visit(seed.clone()),
        });

        crawler
            .run_with_request_or_recover(
                StartCrawlRequest {
                    config: crawler.config,
                    seed_nodes: vec![seed],
                },
                processor,
            )
            .await
            .expect("crawler should fall back to a new run");

        let checkpoints = repository
            .inserted_checkpoints
            .lock()
            .expect("inserted checkpoints lock");
        let failed_checkpoint = checkpoints
            .iter()
            .find(|checkpoint| {
                checkpoint.run_id == invalid_checkpoint.run_id
                    && checkpoint.phase == CrawlPhase::Failed
            })
            .expect("invalid checkpoint should be terminalized");
        assert_eq!(
            failed_checkpoint.stop_reason.as_deref(),
            Some("startup recovery failed")
        );
        assert!(failed_checkpoint.failure_reason.is_some());

        let observations = repository.observations.lock().expect("observations lock");
        assert_eq!(observations.len(), 1);
        assert_ne!(observations[0].raw.crawl_run_id, invalid_checkpoint.run_id);
    }
}
