mod domain;
mod lifecycle;
mod node;
mod ports;
mod types;
mod worker;

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, mpsc};
use tokio::task::{JoinError, JoinHandle};
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

        let active_run_guard = claim_active_run(active_run_slot(), run_id.clone())?;
        let result = self
            .run_active_request(
                run_id,
                request,
                processor,
                started_at,
                started_at_utc,
                active_run_guard,
            )
            .await;

        result
    }

    async fn run_active_request(
        &self,
        run_id: CrawlRunId,
        request: StartCrawlRequest,
        processor: Arc<dyn NodeProcessor>,
        started_at: Instant,
        started_at_utc: DateTime<Utc>,
        _active_run_guard: ActiveRunGuard,
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

        let writer_handle = AbortOnDropHandle::new(tokio::spawn(run_observation_writer(
            Arc::clone(&self.repository),
            Arc::clone(&stats),
            Arc::clone(&stop),
            observation_rx,
            writer_batch_size(request.config),
        )));
        let lifecycle_handle = AbortOnDropHandle::new(tokio::spawn(run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            request.config.max_runtime,
            request.config.idle_timeout,
            request.config.lifecycle_tick,
        )));
        let checkpoint_handle = AbortOnDropHandle::new(tokio::spawn(run_checkpoint_emitter(
            Arc::clone(&self.repository),
            run_id.clone(),
            Arc::clone(&phase),
            Arc::clone(&state),
            Arc::clone(&stats),
            Arc::clone(&stop),
            started_at_utc,
            request.config.lifecycle_tick,
        )));
        let signal_handle =
            AbortOnDropHandle::new(tokio::spawn(run_signal_shutdown(Arc::clone(&stop))));

        let worker_count = effective_worker_count(request.config.max_concurrency);
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            workers.push(AbortOnDropHandle::new(tokio::spawn(run_worker(
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
        for mut handle in task_set.worker_handles.drain(..) {
            if let Err(err) = handle.join().await {
                warn!("[crawler] worker join error: {err}");
                stop.store(true, Ordering::Relaxed);
                record_failure(&mut failure_reason, format!("worker join error: {err}"));
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

fn active_run_slot() -> &'static StdMutex<Option<CrawlRunId>> {
    static ACTIVE_RUN: OnceLock<StdMutex<Option<CrawlRunId>>> = OnceLock::new();
    ACTIVE_RUN.get_or_init(|| StdMutex::new(None))
}

#[derive(Debug)]
struct ActiveRunGuard {
    active_run: &'static StdMutex<Option<CrawlRunId>>,
    run_id: CrawlRunId,
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        release_active_run(self.active_run, &self.run_id);
    }
}

fn claim_active_run(
    active_run: &'static StdMutex<Option<CrawlRunId>>,
    run_id: CrawlRunId,
) -> Result<ActiveRunGuard, Box<dyn Error>> {
    let mut guard = active_run.lock().map_err(|_| "active run slot poisoned")?;
    if let Some(existing) = guard.as_ref() {
        return Err(format!("crawl run {} is already active", existing.as_str()).into());
    }

    *guard = Some(run_id.clone());
    Ok(ActiveRunGuard { active_run, run_id })
}

fn release_active_run(active_run: &'static StdMutex<Option<CrawlRunId>>, run_id: &CrawlRunId) {
    let mut guard = active_run.lock().expect("active run slot lock");
    if guard.as_ref() == Some(run_id) {
        *guard = None;
    }
}

#[cfg(test)]
fn clear_active_run_slot(active_run: &'static StdMutex<Option<CrawlRunId>>) {
    let mut guard = active_run.lock().expect("active run slot lock");
    *guard = None;
}

fn record_failure(failure_reason: &mut Option<String>, reason: String) {
    if failure_reason.is_none() {
        *failure_reason = Some(reason);
    }
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
    use crate::crawler::types::{NodeVisit, NodeVisitFailure};
    use crate::wire::message::Services;
    use chrono::Utc;
    use std::collections::VecDeque;
    use std::future::pending;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex as StdSyncMutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    fn active_run_test_lock() -> &'static Mutex<()> {
        static ACTIVE_RUN_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ACTIVE_RUN_TEST_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn worker_count_is_at_least_one() {
        assert_eq!(effective_worker_count(0), 1);
        assert_eq!(effective_worker_count(1), 1);
        assert_eq!(effective_worker_count(8), 8);
    }

    #[tokio::test]
    async fn active_run_claim_rejects_second_run() {
        let _test_guard = active_run_test_lock().lock().await;
        static ACTIVE_RUN: StdMutex<Option<CrawlRunId>> = StdMutex::new(None);
        clear_active_run_slot(&ACTIVE_RUN);

        let first_guard =
            claim_active_run(&ACTIVE_RUN, CrawlRunId::new("run-1")).expect("first claim");
        let err = claim_active_run(&ACTIVE_RUN, CrawlRunId::new("run-2"))
            .expect_err("second claim should fail");

        assert!(err.to_string().contains("already active"));

        drop(first_guard);
        let third_guard =
            claim_active_run(&ACTIVE_RUN, CrawlRunId::new("run-3")).expect("claim after release");
        drop(third_guard);
    }

    #[tokio::test]
    async fn active_run_slot_is_shared_process_wide() {
        let _test_guard = active_run_test_lock().lock().await;
        clear_active_run_slot(active_run_slot());
        let first_guard = claim_active_run(active_run_slot(), CrawlRunId::new("run-1"))
            .expect("claim shared slot");

        let err = claim_active_run(active_run_slot(), CrawlRunId::new("run-2"))
            .expect_err("second shared claim should fail");

        assert!(err.to_string().contains("already active"));
        drop(first_guard);
    }

    #[tokio::test]
    async fn active_run_guard_releases_slot_when_future_is_cancelled() {
        let _test_guard = active_run_test_lock().lock().await;
        clear_active_run_slot(active_run_slot());

        let handle = tokio::spawn(async {
            let _guard =
                claim_active_run(active_run_slot(), CrawlRunId::new("run-1")).expect("claim slot");
            pending::<()>().await;
        });

        tokio::task::yield_now().await;
        handle.abort();
        let _ = handle.await;

        let guard = claim_active_run(active_run_slot(), CrawlRunId::new("run-2"))
            .expect("cancellation should release slot");
        drop(guard);
    }

    #[derive(Clone)]
    struct StaticNodeProcessor {
        visit: NodeVisit,
    }

    impl NodeProcessor for StaticNodeProcessor {
        fn process(
            &self,
            _endpoint: CrawlEndpoint,
            _config: CrawlerConfig,
        ) -> Result<NodeVisit, NodeVisitFailure> {
            Ok(self.visit.clone())
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

    struct SlowNodeProcessor {
        visit: NodeVisit,
        delay: Duration,
    }

    impl NodeProcessor for SlowNodeProcessor {
        fn process(
            &self,
            _endpoint: CrawlEndpoint,
            _config: CrawlerConfig,
        ) -> Result<NodeVisit, NodeVisitFailure> {
            std::thread::sleep(self.delay);
            Ok(self.visit.clone())
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

        fn count_nodes_by_asn<'a>(
            &'a self,
        ) -> RepositoryFuture<'a, Result<Vec<CountNodesByAsnRow>, CrawlerRepositoryError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn run_with_request_returns_error_when_periodic_checkpointing_fails() {
        let _test_guard = active_run_test_lock().lock().await;
        clear_active_run_slot(active_run_slot());

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
                max_runtime: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(1),
                lifecycle_tick: Duration::from_millis(5),
                connect_timeout: Duration::from_millis(50),
                io_timeout: Duration::from_millis(50),
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
    async fn cancelling_run_aborts_periodic_checkpoint_task_before_slot_reopens() {
        let _test_guard = active_run_test_lock().lock().await;
        clear_active_run_slot(active_run_slot());

        let repository = Arc::new(BlockingPeriodicCheckpointRepository::new());
        let crawler = Arc::new(Crawler::with_adapters(
            CrawlerConfig {
                max_concurrency: 1,
                max_runtime: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(1),
                lifecycle_tick: Duration::from_millis(5),
                connect_timeout: Duration::from_millis(50),
                io_timeout: Duration::from_millis(50),
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

        let guard = claim_active_run(active_run_slot(), CrawlRunId::new("run-2"))
            .expect("slot should reopen only after cancellation cleanup");
        drop(guard);
    }
}
