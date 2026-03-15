use std::sync::Once;

use tracing_subscriber::EnvFilter;

static TRACING_INIT: Once = Once::new();

/// Initializes process-wide tracing with JSON output.
///
/// The log level is controlled by `RUST_LOG` and defaults to `info`.
/// Repeated calls are ignored after the first successful initialization.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_ansi(false)
            .json()
            .flatten_event(false)
            .with_current_span(true)
            .with_span_list(false)
            .try_init();
    });
}
