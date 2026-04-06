use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::domain::{
    CrawlEndpoint, CrawlPhase, CrawlRunCheckpoint, CrawlRunId, CrawlRunMetrics,
    CrawlRunRecoveryPoint, RecoveryPayloadEncoding,
};
use super::ports::{CrawlerRepository, CrawlerRepositoryError};
use super::types::{CrawlState, CrawlerStats};

const PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) struct CheckpointEmitterContext {
    pub(crate) repository: Arc<dyn CrawlerRepository>,
    pub(crate) run_id: CrawlRunId,
    pub(crate) phase: Arc<Mutex<CrawlPhase>>,
    pub(crate) state: Arc<Mutex<CrawlState>>,
    pub(crate) stats: Arc<CrawlerStats>,
    pub(crate) checkpoint_sequence: Arc<AtomicU64>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) checkpoint_interval: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct SnapshotCapture {
    pub(crate) checkpointed_at: DateTime<Utc>,
    pub(crate) checkpoint_sequence: u64,
    pub(crate) metrics: CrawlRunMetrics,
    pub(crate) frontier_payload: Vec<u8>,
    pub(crate) frontier_size: usize,
}

/// Periodically evaluates stop conditions that are independent of any single
/// worker.
///
/// This task is the crawler's coordinator-side policy loop. It does not visit
/// nodes or persist data. Instead it watches shared state and flips the shared
/// `stop` flag when the crawl has exceeded its maximum runtime or has gone idle
/// for too long without discovering a new node.
pub(crate) async fn run_lifecycle(
    state: Arc<Mutex<CrawlState>>,
    stop: Arc<AtomicBool>,
    started_at: Instant,
    max_runtime: Duration,
    idle_timeout: Duration,
    tick_every: Duration,
) {
    let mut ticker = tokio::time::interval(tick_every);

    loop {
        ticker.tick().await;

        if stop.load(Ordering::Relaxed) {
            return;
        }

        if started_at.elapsed() >= max_runtime {
            info!("[lifecycle] max runtime reached ({max_runtime:?}), stopping");
            stop.store(true, Ordering::Relaxed);
            return;
        }

        let idle_for = {
            let guard = state.lock().await;
            guard.last_new_node_at.elapsed()
        };

        if idle_for >= idle_timeout {
            info!("[lifecycle] idle timeout reached ({idle_for:?}), stopping");
            stop.store(true, Ordering::Relaxed);
            return;
        }
    }
}

/// Periodically snapshots crawler progress and durable recovery state.
///
/// This task is separate from the final phase-transition checkpoints written by
/// the coordinator in `mod.rs`. Its job is to emit background progress
/// checkpoints and recovery points while the crawl is still active. If either
/// persistence path fails, it requests global shutdown by setting `stop` and
/// returns the repository error.
pub(crate) async fn run_checkpoint_emitter(
    context: CheckpointEmitterContext,
) -> Result<(), CrawlerRepositoryError> {
    let CheckpointEmitterContext {
        repository,
        run_id,
        phase,
        state,
        stats,
        checkpoint_sequence,
        stop,
        started_at,
        checkpoint_interval,
    } = context;
    let mut ticker = tokio::time::interval(checkpoint_interval);
    let mut last_progress_log_at = None;

    loop {
        ticker.tick().await;

        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        let phase = *phase.lock().await;
        let capture = capture_snapshot(&state, &stats, &checkpoint_sequence).await?;
        let checkpoint = checkpoint_from_capture(run_id.clone(), phase, started_at, &capture);
        if should_log_progress(last_progress_log_at, PROGRESS_LOG_INTERVAL) {
            log_progress_summary(&checkpoint);
            last_progress_log_at = Some(Instant::now());
        }
        let recovery_point =
            recovery_point_from_capture(run_id.clone(), phase, started_at, &capture);
        if let Err(err) = repository.insert_run_recovery_point(recovery_point).await {
            warn!("[crawler] failed to write recovery point: {err}");
            stop.store(true, Ordering::Relaxed);
            return Err(err);
        }
        if let Err(err) = repository.insert_run_checkpoint(checkpoint).await {
            warn!("[crawler] failed to write checkpoint: {err}");
            stop.store(true, Ordering::Relaxed);
            return Err(err);
        }
    }
}

pub(crate) async fn capture_snapshot(
    state: &Arc<Mutex<CrawlState>>,
    stats: &Arc<CrawlerStats>,
    checkpoint_sequence: &Arc<AtomicU64>,
) -> Result<SnapshotCapture, CrawlerRepositoryError> {
    let guard = state.lock().await;
    let frontier = guard.recovery_frontier();

    Ok(SnapshotCapture {
        checkpointed_at: Utc::now(),
        checkpoint_sequence: next_checkpoint_sequence(checkpoint_sequence),
        metrics: CrawlRunMetrics {
            frontier_size: guard.pending_nodes.len(),
            in_flight_work: stats.in_flight.load(Ordering::Relaxed),
            scheduled_tasks: stats.scheduled.load(Ordering::Relaxed),
            successful_handshakes: stats.success.load(Ordering::Relaxed),
            failed_tasks: stats.failed.load(Ordering::Relaxed),
            queued_nodes_total: stats.queued_total.load(Ordering::Relaxed),
            unique_nodes: guard.seen_nodes.len(),
            discovered_node_states: stats.discovered_node_states.load(Ordering::Relaxed),
            persisted_observation_rows: stats.persisted_rows.load(Ordering::Relaxed),
            writer_backlog: stats.writer_backlog.load(Ordering::Relaxed),
        },
        frontier_payload: serialize_recovery_frontier(&frontier)?,
        frontier_size: frontier.len(),
    })
}

pub(crate) fn checkpoint_from_capture(
    run_id: CrawlRunId,
    phase: CrawlPhase,
    started_at: DateTime<Utc>,
    capture: &SnapshotCapture,
) -> CrawlRunCheckpoint {
    CrawlRunCheckpoint {
        run_id,
        phase,
        checkpointed_at: capture.checkpointed_at,
        checkpoint_sequence: capture.checkpoint_sequence,
        started_at,
        stop_reason: None,
        failure_reason: None,
        metrics: capture.metrics.clone(),
        caller: None,
    }
}

pub(crate) fn recovery_point_from_capture(
    run_id: CrawlRunId,
    phase: CrawlPhase,
    started_at: DateTime<Utc>,
    capture: &SnapshotCapture,
) -> CrawlRunRecoveryPoint {
    CrawlRunRecoveryPoint {
        run_id,
        phase,
        checkpointed_at: capture.checkpointed_at,
        checkpoint_sequence: capture.checkpoint_sequence,
        started_at,
        stop_reason: None,
        failure_reason: None,
        metrics: capture.metrics.clone(),
        payload_encoding: RecoveryPayloadEncoding::ZstdJsonV1,
        frontier_payload: capture.frontier_payload.clone(),
        frontier_size: capture.frontier_size,
        caller: None,
    }
}

pub(crate) fn serialize_recovery_frontier(
    frontier: &[CrawlEndpoint],
) -> Result<Vec<u8>, CrawlerRepositoryError> {
    let payload = serde_json::to_vec(frontier).map_err(|err| {
        CrawlerRepositoryError::new(format!("serialize recovery frontier: {err}"))
    })?;
    zstd::stream::encode_all(payload.as_slice(), 0)
        .map_err(|err| CrawlerRepositoryError::new(format!("compress recovery frontier: {err}")))
}

pub(crate) fn deserialize_recovery_frontier(
    payload_encoding: RecoveryPayloadEncoding,
    frontier_payload: &[u8],
) -> Result<Vec<CrawlEndpoint>, String> {
    match payload_encoding {
        RecoveryPayloadEncoding::ZstdJsonV1 => {
            let decoded = zstd::stream::decode_all(frontier_payload)
                .map_err(|err| format!("decompress recovery frontier: {err}"))?;
            serde_json::from_slice(&decoded)
                .map_err(|err| format!("decode recovery frontier JSON: {err}"))
        }
    }
}

fn next_checkpoint_sequence(checkpoint_sequence: &AtomicU64) -> u64 {
    checkpoint_sequence.fetch_add(1, Ordering::Relaxed) + 1
}

fn should_log_progress(last_logged_at: Option<Instant>, interval: Duration) -> bool {
    match last_logged_at {
        None => true,
        Some(last_logged_at) => last_logged_at.elapsed() >= interval,
    }
}

fn log_progress_summary(checkpoint: &CrawlRunCheckpoint) {
    let metrics = &checkpoint.metrics;
    let success_pct = if metrics.scheduled_tasks == 0 {
        0.0
    } else {
        (metrics.successful_handshakes as f64 / metrics.scheduled_tasks as f64) * 100.0
    };

    info!(
        run_id = %checkpoint.run_id.as_str(),
        phase = ?checkpoint.phase,
        scheduled_tasks = metrics.scheduled_tasks,
        successful_handshakes = metrics.successful_handshakes,
        failed_tasks = metrics.failed_tasks,
        frontier_size = metrics.frontier_size,
        in_flight_work = metrics.in_flight_work,
        unique_nodes = metrics.unique_nodes,
        persisted_observation_rows = metrics.persisted_observation_rows,
        writer_backlog = metrics.writer_backlog,
        success_pct = success_pct,
        "[crawler] progress summary"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::{CrawlEndpoint, CrawlNetwork, CrawlerRepository, CrawlerRepositoryError};
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Mutex as StdMutex;

    #[tokio::test]
    async fn lifecycle_stops_on_max_runtime() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stop = Arc::new(AtomicBool::new(false));

        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Instant::now(),
            Duration::from_millis(20),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await;

        assert!(stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn lifecycle_stops_on_idle_timeout() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        {
            let mut guard = state.lock().await;
            guard.last_new_node_at = Instant::now() - Duration::from_millis(50);
        }

        let stop = Arc::new(AtomicBool::new(false));
        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Instant::now(),
            Duration::from_secs(10),
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
        .await;

        assert!(stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn lifecycle_exits_immediately_when_already_stopped() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stop = Arc::new(AtomicBool::new(true));
        let before = Instant::now();

        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Instant::now(),
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await;

        assert!(before.elapsed() < Duration::from_millis(100));
        assert!(stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn lifecycle_uses_original_started_at_for_max_runtime() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stop = Arc::new(AtomicBool::new(false));

        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Instant::now() - Duration::from_millis(50),
            Duration::from_millis(20),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await;

        assert!(stop.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn snapshot_checkpoint_reports_frontier_and_writer_metrics() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        {
            let mut guard = state.lock().await;
            let endpoint = CrawlEndpoint::new(
                "1.1.1.7",
                8333,
                CrawlNetwork::Ipv4,
                Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 7))),
            );
            guard.seen_nodes.insert(endpoint.clone());
            guard.pending_nodes.insert(endpoint);
        }
        let stats = Arc::new(CrawlerStats::default());
        stats.queued_total.store(1, Ordering::Relaxed);
        stats.in_flight.store(2, Ordering::Relaxed);
        stats.discovered_node_states.store(1, Ordering::Relaxed);
        stats.persisted_rows.store(3, Ordering::Relaxed);
        stats.writer_backlog.store(4, Ordering::Relaxed);

        let capture = capture_snapshot(&state, &stats, &Arc::new(AtomicU64::new(0)))
            .await
            .expect("snapshot capture");

        assert_eq!(capture.metrics.frontier_size, 1);
        assert_eq!(capture.metrics.in_flight_work, 2);
        assert_eq!(capture.metrics.persisted_observation_rows, 3);
        assert_eq!(capture.metrics.writer_backlog, 4);
        assert_eq!(capture.checkpoint_sequence, 1);
        let frontier = deserialize_recovery_frontier(
            RecoveryPayloadEncoding::ZstdJsonV1,
            capture.frontier_payload.as_slice(),
        )
        .expect("recovery frontier should deserialize");
        assert_eq!(frontier.len(), 1);
    }

    #[tokio::test]
    async fn snapshot_checkpoint_increments_sequence_monotonically() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let checkpoint_sequence = Arc::new(AtomicU64::new(0));

        let first = capture_snapshot(&state, &stats, &checkpoint_sequence)
            .await
            .expect("first capture");
        let second = capture_snapshot(&state, &stats, &checkpoint_sequence)
            .await
            .expect("second capture");

        assert_eq!(first.checkpoint_sequence, 1);
        assert_eq!(second.checkpoint_sequence, 2);
    }

    #[derive(Default)]
    struct RecordingRepository {
        checkpoints: StdMutex<Vec<CrawlRunCheckpoint>>,
        recovery_points: StdMutex<Vec<CrawlRunRecoveryPoint>>,
    }

    impl CrawlerRepository for RecordingRepository {
        fn insert_observation<'a>(
            &'a self,
            _observation: crate::crawler::PersistedNodeObservation,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn insert_observations_stream<'a>(
            &'a self,
            _observations: Vec<crate::crawler::PersistedNodeObservation>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn insert_run_checkpoint<'a>(
            &'a self,
            checkpoint: CrawlRunCheckpoint,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async move {
                self.checkpoints
                    .lock()
                    .expect("checkpoints lock")
                    .push(checkpoint);
                Ok(())
            })
        }

        fn insert_run_recovery_point<'a>(
            &'a self,
            recovery_point: CrawlRunRecoveryPoint,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async move {
                self.recovery_points
                    .lock()
                    .expect("recovery points lock")
                    .push(recovery_point);
                Ok(())
            })
        }

        fn get_run_checkpoint<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(None) })
        }

        fn list_runs<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(self.checkpoints.lock().expect("checkpoints lock").clone()) })
        }

        fn get_latest_active_run_checkpoint<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(None) })
        }

        fn get_latest_active_run_recovery_point<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Option<CrawlRunRecoveryPoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(None) })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            Vec<crate::crawler::CountNodesByAsnRow>,
                            CrawlerRepositoryError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_observed_endpoints_for_run<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Vec<CrawlEndpoint>, CrawlerRepositoryError>> + Send + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn checkpoint_emitter_writes_periodic_snapshots() {
        let repository = Arc::new(RecordingRepository::default());
        let repository_trait: Arc<dyn CrawlerRepository> = repository.clone();
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let phase = Arc::new(Mutex::new(CrawlPhase::Crawling));
        let stop = Arc::new(AtomicBool::new(false));

        let handle = tokio::spawn(run_checkpoint_emitter(CheckpointEmitterContext {
            repository: repository_trait,
            run_id: CrawlRunId::new("run-1"),
            phase: Arc::clone(&phase),
            state: Arc::clone(&state),
            stats: Arc::clone(&stats),
            checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            stop: Arc::clone(&stop),
            started_at: Utc::now(),
            checkpoint_interval: Duration::from_millis(5),
        }));

        tokio::time::sleep(Duration::from_millis(15)).await;
        stop.store(true, Ordering::Relaxed);
        handle
            .await
            .expect("checkpoint emitter join")
            .expect("checkpoint emitter should succeed");

        let runs = repository.list_runs().await.expect("list runs");
        assert!(!runs.is_empty());
        assert!(
            runs.iter()
                .all(|checkpoint| checkpoint.phase == CrawlPhase::Crawling)
        );
        assert!(
            !repository
                .recovery_points
                .lock()
                .expect("recovery points lock")
                .is_empty()
        );
    }

    #[derive(Default)]
    struct FailingCheckpointRepository;

    impl CrawlerRepository for FailingCheckpointRepository {
        fn insert_observation<'a>(
            &'a self,
            _observation: crate::crawler::PersistedNodeObservation,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn insert_observations_stream<'a>(
            &'a self,
            _observations: Vec<crate::crawler::PersistedNodeObservation>,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn insert_run_checkpoint<'a>(
            &'a self,
            _checkpoint: CrawlRunCheckpoint,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async { Err(CrawlerRepositoryError::new("checkpoint write failed")) })
        }

        fn insert_run_recovery_point<'a>(
            &'a self,
            _recovery_point: CrawlRunRecoveryPoint,
        ) -> Pin<Box<dyn Future<Output = Result<(), CrawlerRepositoryError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn get_run_checkpoint<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(None) })
        }

        fn list_runs<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Vec<CrawlRunCheckpoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn get_latest_active_run_checkpoint<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Option<CrawlRunCheckpoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(None) })
        }

        fn get_latest_active_run_recovery_point<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Option<CrawlRunRecoveryPoint>, CrawlerRepositoryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(None) })
        }

        fn count_nodes_by_asn<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            Vec<crate::crawler::CountNodesByAsnRow>,
                            CrawlerRepositoryError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_observed_endpoints_for_run<'a>(
            &'a self,
            _run_id: &'a CrawlRunId,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Vec<CrawlEndpoint>, CrawlerRepositoryError>> + Send + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn checkpoint_emitter_returns_error_when_checkpoint_write_fails() {
        let repository: Arc<dyn CrawlerRepository> = Arc::new(FailingCheckpointRepository);
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let phase = Arc::new(Mutex::new(CrawlPhase::Crawling));
        let stop = Arc::new(AtomicBool::new(false));

        let err = run_checkpoint_emitter(CheckpointEmitterContext {
            repository,
            run_id: CrawlRunId::new("run-1"),
            phase,
            state,
            stats,
            checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            stop: Arc::clone(&stop),
            started_at: Utc::now(),
            checkpoint_interval: Duration::from_millis(5),
        })
        .await
        .expect_err("checkpoint emitter should return repository errors");

        assert_eq!(err.to_string(), "checkpoint write failed");
        assert!(stop.load(Ordering::Relaxed));
    }
}
