use tracing_subscriber::EnvFilter;

/// Initializes tracing for binaries in this crate.
pub fn init_tracing() {
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
}
