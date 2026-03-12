mod commands;

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::handshake,
            commands::ping
        ])
        .run(tauri::generate_context!())
        .expect("error while running btc-network desktop");
}
