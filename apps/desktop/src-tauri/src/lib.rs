mod commands;

/// Boots the desktop shell and exposes the narrow Tauri command surface used by the UI.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::handshake,
            commands::ping
        ])
        .run(tauri::generate_context!())
        .expect("error while running btc-network desktop");
}
