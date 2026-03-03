use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use super::types::CrawlState;

pub(crate) async fn run_janitor(
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
            println!("[janitor] max runtime reached ({max_runtime:?}), stopping");
            stop.store(true, Ordering::Relaxed);
            return;
        }

        let idle_for = {
            let guard = state.lock().await;
            guard.last_new_node_at.elapsed()
        };

        if idle_for >= idle_timeout {
            println!("[janitor] idle timeout reached ({idle_for:?}), stopping");
            stop.store(true, Ordering::Relaxed);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crawler::types::CrawlState;

    #[tokio::test]
    async fn janitor_stops_on_max_runtime() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        let stop = Arc::new(AtomicBool::new(false));

        run_janitor(
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
    async fn janitor_stops_on_idle_timeout() {
        let state = Arc::new(Mutex::new(CrawlState::new()));
        {
            let mut guard = state.lock().await;
            guard.last_new_node_at = Instant::now() - Duration::from_millis(50);
        }

        let stop = Arc::new(AtomicBool::new(false));
        run_janitor(
            Arc::clone(&state),
            Arc::clone(&stop),
            Duration::from_secs(10),
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
        .await;

        assert!(stop.load(Ordering::Relaxed));
    }
}
