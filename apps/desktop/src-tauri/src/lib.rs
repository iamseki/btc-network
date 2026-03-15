mod commands;
mod error;
mod models;
mod validation;

/// Boots the desktop shell and exposes the narrow Tauri command surface used by the UI.
pub fn run() {
    btc_network_observability::init_tracing();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::handshake,
            commands::ping,
            commands::get_last_block_height,
            commands::get_peer_addresses,
            commands::get_block_summary,
            commands::download_block
        ])
        .run(tauri::generate_context!())
        .expect("error while running btc-network desktop");
}
