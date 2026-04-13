use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use super::domain::{CrawlPhase, CrawlRunCheckpoint, CrawlRunId, CrawlRunMetrics};
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
    pub(crate) connect_limiter: Option<Arc<Semaphore>>,
    pub(crate) connect_limit: Option<usize>,
}

pub(crate) type SharedStopReason = Arc<StdMutex<Option<String>>>;

#[derive(Debug, Clone)]
pub(crate) struct SnapshotCapture {
    pub(crate) checkpointed_at: DateTime<Utc>,
    pub(crate) checkpoint_sequence: u64,
    pub(crate) metrics: CrawlRunMetrics,
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
    stop_reason: SharedStopReason,
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
            let reason = format!("max runtime reached ({max_runtime:?})");
            info!("[lifecycle] {reason}, stopping");
            record_stop_reason(&stop_reason, reason);
            stop.store(true, Ordering::Relaxed);
            return;
        }

        let idle_for = {
            let guard = state.lock().await;
            guard.last_new_node_at.elapsed()
        };

        if idle_for >= idle_timeout {
            let reason = format!("idle timeout reached ({idle_for:?})");
            info!("[lifecycle] {reason}, stopping");
            record_stop_reason(&stop_reason, reason);
            stop.store(true, Ordering::Relaxed);
            return;
        }
    }
}

/// Periodically snapshots crawler progress.
///
/// This task is separate from the final phase-transition checkpoints written by
/// the coordinator in `mod.rs`. Its job is to emit background progress
/// checkpoints while the crawl is still active. If the persistence path fails,
/// it requests global shutdown by setting `stop` and returns the repository
/// error.
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
        connect_limiter,
        connect_limit,
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
            log_progress_summary(
                &checkpoint,
                repository.as_ref(),
                connect_limiter.as_ref(),
                connect_limit,
                stats.as_ref(),
            );
            last_progress_log_at = Some(Instant::now());
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

    Ok(SnapshotCapture {
        checkpointed_at: Utc::now(),
        checkpoint_sequence: next_checkpoint_sequence(checkpoint_sequence),
        metrics: CrawlRunMetrics {
            frontier_size: guard.pending_nodes.len(),
            in_flight_work: stats.in_flight.load(Ordering::Relaxed),
            scheduled_tasks: stats.scheduled.load(Ordering::Relaxed),
            successful_handshakes: stats.success.load(Ordering::Relaxed),
            failed_tasks: stats.failed.load(Ordering::Relaxed),
            unique_nodes: guard.seen_nodes.len(),
            persisted_observation_rows: stats.persisted_rows.load(Ordering::Relaxed),
            writer_backlog: stats.writer_backlog.load(Ordering::Relaxed),
        },
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
    }
}

pub(crate) fn record_stop_reason(stop_reason: &SharedStopReason, reason: String) {
    let mut guard = stop_reason.lock().expect("stop reason lock");
    if guard.is_none() {
        *guard = Some(reason);
    }
}

pub(crate) fn load_stop_reason(stop_reason: &SharedStopReason) -> Option<String> {
    stop_reason.lock().expect("stop reason lock").clone()
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

fn log_progress_summary(
    checkpoint: &CrawlRunCheckpoint,
    repository: &dyn CrawlerRepository,
    connect_limiter: Option<&Arc<Semaphore>>,
    connect_limit: Option<usize>,
    stats: &CrawlerStats,
) {
    let metrics = &checkpoint.metrics;
    let success_pct = if metrics.scheduled_tasks == 0 {
        0.0
    } else {
        (metrics.successful_handshakes as f64 / metrics.scheduled_tasks as f64) * 100.0
    };
    let process_metrics = ProcessRuntimeMetrics::collect();
    let repository_metrics = repository.runtime_metrics();
    let connect_slots_in_use = connect_limiter
        .map(|limiter| compute_connect_slots_in_use(connect_limit, limiter.available_permits()));

    info!(
        run_id = %checkpoint.run_id,
        phase = ?checkpoint.phase,
        scheduled_tasks = metrics.scheduled_tasks,
        successful_handshakes = metrics.successful_handshakes,
        failed_tasks = metrics.failed_tasks,
        frontier_size = metrics.frontier_size,
        in_flight_work = metrics.in_flight_work,
        unique_nodes = metrics.unique_nodes,
        persisted_observation_rows = metrics.persisted_observation_rows,
        writer_backlog = metrics.writer_backlog,
        open_fd_count = process_metrics.open_fd_count,
        tcp_established = process_metrics.tcp_established,
        tcp_syn_sent = process_metrics.tcp_syn_sent,
        tcp_time_wait = process_metrics.tcp_time_wait,
        connect_slots_in_use = connect_slots_in_use,
        connectable_tasks_started = stats.connectable_tasks_started.load(Ordering::Relaxed),
        connect_retries_started = stats.connect_retries_started.load(Ordering::Relaxed),
        delayed_retry_backlog = stats.delayed_retry_backlog.load(Ordering::Relaxed),
        connect_timeout_failures = stats.connect_timeout_failures.load(Ordering::Relaxed),
        connect_refused_failures = stats.connect_refused_failures.load(Ordering::Relaxed),
        connect_unreachable_failures = stats.connect_unreachable_failures.load(Ordering::Relaxed),
        connect_other_failures = stats.connect_other_failures.load(Ordering::Relaxed),
        postgres_pool_max_connections = repository_metrics.pool_max_connections,
        postgres_pool_size = repository_metrics.pool_size,
        postgres_pool_idle = repository_metrics.pool_idle,
        postgres_pool_acquired = repository_metrics.pool_acquired,
        success_pct = success_pct,
        "[crawler] progress summary"
    );
}

fn compute_connect_slots_in_use(connect_limit: Option<usize>, available_permits: usize) -> usize {
    connect_limit
        .unwrap_or_default()
        .saturating_sub(available_permits)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProcessRuntimeMetrics {
    open_fd_count: Option<usize>,
    tcp_established: Option<usize>,
    tcp_syn_sent: Option<usize>,
    tcp_time_wait: Option<usize>,
}

impl ProcessRuntimeMetrics {
    fn collect() -> Self {
        Self {
            open_fd_count: read_open_fd_count(),
            tcp_established: read_tcp_socket_state_count(TcpSocketState::Established),
            tcp_syn_sent: read_tcp_socket_state_count(TcpSocketState::SynSent),
            tcp_time_wait: read_tcp_socket_state_count(TcpSocketState::TimeWait),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpSocketState {
    Established,
    SynSent,
    TimeWait,
}

impl TcpSocketState {
    fn linux_code(self) -> &'static str {
        match self {
            Self::Established => "01",
            Self::SynSent => "02",
            Self::TimeWait => "06",
        }
    }
}

#[cfg(target_os = "linux")]
fn read_open_fd_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count())
}

#[cfg(not(target_os = "linux"))]
fn read_open_fd_count() -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
fn read_tcp_socket_state_count(state: TcpSocketState) -> Option<usize> {
    let mut total = 0usize;
    for path in ["/proc/self/net/tcp", "/proc/self/net/tcp6"] {
        total += count_tcp_socket_state_in_file(path, state).ok()?;
    }
    Some(total)
}

#[cfg(not(target_os = "linux"))]
fn read_tcp_socket_state_count(_state: TcpSocketState) -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
fn count_tcp_socket_state_in_file(
    path: &str,
    state: TcpSocketState,
) -> Result<usize, std::io::Error> {
    let contents = std::fs::read_to_string(path)?;
    Ok(count_tcp_socket_state_in_contents(&contents, state))
}

fn count_tcp_socket_state_in_contents(contents: &str, state: TcpSocketState) -> usize {
    contents
        .lines()
        .skip(1)
        .filter(|line| parse_tcp_state_code(line).is_some_and(|code| code == state.linux_code()))
        .count()
}

fn parse_tcp_state_code(line: &str) -> Option<&str> {
    line.split_whitespace().nth(3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::{
        CrawlEndpoint, CrawlNetwork, CrawlerRepository, CrawlerRepositoryError,
        RepositoryRuntimeMetrics,
    };
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Mutex as StdMutex;

    #[tokio::test]
    async fn lifecycle_stops_on_max_runtime() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_reason = Arc::new(StdMutex::new(None));

        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Arc::clone(&stop_reason),
            Instant::now(),
            Duration::from_millis(20),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await;

        assert!(stop.load(Ordering::Relaxed));
        assert!(
            load_stop_reason(&stop_reason)
                .is_some_and(|reason| reason.contains("max runtime reached"))
        );
    }

    #[tokio::test]
    async fn lifecycle_stops_on_idle_timeout() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        {
            let mut guard = state.lock().await;
            guard.last_new_node_at = Instant::now() - Duration::from_millis(50);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_reason = Arc::new(StdMutex::new(None));
        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Arc::clone(&stop_reason),
            Instant::now(),
            Duration::from_secs(10),
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
        .await;

        assert!(stop.load(Ordering::Relaxed));
        assert!(
            load_stop_reason(&stop_reason)
                .is_some_and(|reason| reason.contains("idle timeout reached"))
        );
    }

    #[tokio::test]
    async fn lifecycle_exits_immediately_when_already_stopped() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stop = Arc::new(AtomicBool::new(true));
        let stop_reason = Arc::new(StdMutex::new(None));
        let before = Instant::now();

        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Arc::clone(&stop_reason),
            Instant::now(),
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await;

        assert!(before.elapsed() < Duration::from_millis(100));
        assert!(stop.load(Ordering::Relaxed));
        assert_eq!(load_stop_reason(&stop_reason), None);
    }

    #[tokio::test]
    async fn lifecycle_uses_original_started_at_for_max_runtime() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_reason = Arc::new(StdMutex::new(None));

        run_lifecycle(
            Arc::clone(&state),
            Arc::clone(&stop),
            Arc::clone(&stop_reason),
            Instant::now() - Duration::from_millis(50),
            Duration::from_millis(20),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await;

        assert!(stop.load(Ordering::Relaxed));
        assert!(
            load_stop_reason(&stop_reason)
                .is_some_and(|reason| reason.contains("max runtime reached"))
        );
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
        stats.in_flight.store(2, Ordering::Relaxed);
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

        fn runtime_metrics(&self) -> RepositoryRuntimeMetrics {
            RepositoryRuntimeMetrics {
                pool_max_connections: Some(16),
                pool_size: Some(2),
                pool_idle: Some(1),
                pool_acquired: Some(1),
            }
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
            run_id: CrawlRunId::from_u128(1),
            phase: Arc::clone(&phase),
            state: Arc::clone(&state),
            stats: Arc::clone(&stats),
            checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            stop: Arc::clone(&stop),
            started_at: Utc::now(),
            checkpoint_interval: Duration::from_millis(5),
            connect_limiter: None,
            connect_limit: None,
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
            run_id: CrawlRunId::from_u128(1),
            phase,
            state,
            stats,
            checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            stop: Arc::clone(&stop),
            started_at: Utc::now(),
            checkpoint_interval: Duration::from_millis(5),
            connect_limiter: None,
            connect_limit: None,
        })
        .await
        .expect_err("checkpoint emitter should return repository errors");

        assert_eq!(err.to_string(), "checkpoint write failed");
        assert!(stop.load(Ordering::Relaxed));
    }

    #[test]
    fn count_tcp_socket_state_in_contents_counts_target_state() {
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:208D 0100007F:CF3A 01 00000000:00000000 00:00000000 00000000  1000        0 1
   1: 0100007F:208D 0100007F:CF3B 02 00000000:00000000 00:00000000 00000000  1000        0 2
   2: 0100007F:208D 0100007F:CF3C 06 00000000:00000000 00:00000000 00000000  1000        0 3
   3: 0100007F:208D 0100007F:CF3D 01 00000000:00000000 00:00000000 00000000  1000        0 4
";

        assert_eq!(
            count_tcp_socket_state_in_contents(sample, TcpSocketState::Established),
            2
        );
        assert_eq!(
            count_tcp_socket_state_in_contents(sample, TcpSocketState::SynSent),
            1
        );
        assert_eq!(
            count_tcp_socket_state_in_contents(sample, TcpSocketState::TimeWait),
            1
        );
    }

    #[test]
    fn compute_connect_slots_in_use_saturates_at_zero() {
        assert_eq!(compute_connect_slots_in_use(Some(8), 3), 5);
        assert_eq!(compute_connect_slots_in_use(Some(8), 8), 0);
        assert_eq!(compute_connect_slots_in_use(Some(8), 12), 0);
        assert_eq!(compute_connect_slots_in_use(None, 3), 0);
    }
}
