use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::domain::{CrawlPhase, CrawlRunCheckpoint, CrawlRunId, CrawlRunMetrics};
use super::ports::{CrawlerRepository, CrawlerRepositoryError};
use super::types::{CrawlState, CrawlerStats};

pub(crate) struct CheckpointEmitterContext {
    pub(crate) repository: Arc<dyn CrawlerRepository>,
    pub(crate) run_id: CrawlRunId,
    pub(crate) phase: Arc<Mutex<CrawlPhase>>,
    pub(crate) state: Arc<Mutex<CrawlState>>,
    pub(crate) stats: Arc<CrawlerStats>,
    pub(crate) checkpoint_sequence: Arc<AtomicU64>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) tick_every: Duration,
}

pub(crate) async fn run_lifecycle(
    state: Arc<Mutex<CrawlState>>,
    stop: Arc<AtomicBool>,
    max_runtime: Duration,
    idle_timeout: Duration,
    tick_every: Duration,
) {
    let started_at = Instant::now();
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
        tick_every,
    } = context;
    let mut ticker = tokio::time::interval(tick_every);

    loop {
        ticker.tick().await;

        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        let phase = *phase.lock().await;
        let checkpoint = snapshot_checkpoint(
            run_id.clone(),
            phase,
            &state,
            &stats,
            &checkpoint_sequence,
            started_at,
        )
        .await;
        if let Err(err) = repository.insert_run_checkpoint(checkpoint).await {
            warn!("[crawler] failed to write checkpoint: {err}");
            stop.store(true, Ordering::Relaxed);
            return Err(err);
        }
    }
}

pub(crate) async fn snapshot_checkpoint(
    run_id: CrawlRunId,
    phase: CrawlPhase,
    state: &Arc<Mutex<CrawlState>>,
    stats: &Arc<CrawlerStats>,
    checkpoint_sequence: &Arc<AtomicU64>,
    started_at: DateTime<Utc>,
) -> CrawlRunCheckpoint {
    let guard = state.lock().await;

    CrawlRunCheckpoint {
        run_id,
        phase,
        checkpointed_at: Utc::now(),
        checkpoint_sequence: next_checkpoint_sequence(checkpoint_sequence),
        started_at,
        stop_reason: None,
        failure_reason: None,
        metrics: CrawlRunMetrics {
            frontier_size: guard.pending_nodes.len(),
            in_flight_work: stats.in_flight.load(Ordering::Relaxed),
            scheduled_tasks: stats.scheduled.load(Ordering::Relaxed),
            successful_handshakes: stats.success.load(Ordering::Relaxed),
            failed_tasks: stats.failed.load(Ordering::Relaxed),
            queued_nodes_total: stats.queued_total.load(Ordering::Relaxed),
            unique_nodes: guard.seen_nodes.len(),
            discovered_node_states: guard.node_states.len(),
            persisted_observation_rows: stats.persisted_rows.load(Ordering::Relaxed),
            writer_backlog: stats.writer_backlog.load(Ordering::Relaxed),
        },
        resume_state: None,
        caller: None,
    }
}

fn next_checkpoint_sequence(checkpoint_sequence: &AtomicU64) -> u64 {
    checkpoint_sequence.fetch_add(1, Ordering::Relaxed) + 1
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
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .await;

        assert!(before.elapsed() < Duration::from_millis(100));
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
        stats.persisted_rows.store(3, Ordering::Relaxed);
        stats.writer_backlog.store(4, Ordering::Relaxed);

        let checkpoint = snapshot_checkpoint(
            CrawlRunId::new("run-1"),
            CrawlPhase::Crawling,
            &state,
            &stats,
            &Arc::new(AtomicU64::new(0)),
            Utc::now(),
        )
        .await;

        assert_eq!(checkpoint.metrics.frontier_size, 1);
        assert_eq!(checkpoint.metrics.in_flight_work, 2);
        assert_eq!(checkpoint.metrics.persisted_observation_rows, 3);
        assert_eq!(checkpoint.metrics.writer_backlog, 4);
        assert_eq!(checkpoint.checkpoint_sequence, 1);
    }

    #[tokio::test]
    async fn snapshot_checkpoint_increments_sequence_monotonically() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stats = Arc::new(CrawlerStats::default());
        let checkpoint_sequence = Arc::new(AtomicU64::new(0));

        let first = snapshot_checkpoint(
            CrawlRunId::new("run-1"),
            CrawlPhase::Bootstrap,
            &state,
            &stats,
            &checkpoint_sequence,
            Utc::now(),
        )
        .await;
        let second = snapshot_checkpoint(
            CrawlRunId::new("run-1"),
            CrawlPhase::Crawling,
            &state,
            &stats,
            &checkpoint_sequence,
            Utc::now(),
        )
        .await;

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
            tick_every: Duration::from_millis(5),
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
            run_id: CrawlRunId::new("run-1"),
            phase,
            state,
            stats,
            checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            stop: Arc::clone(&stop),
            started_at: Utc::now(),
            tick_every: Duration::from_millis(5),
        })
        .await
        .expect_err("checkpoint emitter should return repository errors");

        assert_eq!(err.to_string(), "checkpoint write failed");
        assert!(stop.load(Ordering::Relaxed));
    }
}
