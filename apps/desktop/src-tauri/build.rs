fn main() {
    let attributes = tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "handshake",
            "ping",
            "get_last_block_height",
            "get_peer_addresses",
            "get_block_summary",
            "download_block",
        ]),
    );

    tauri_build::try_build(attributes).expect("failed to run tauri build script");
}
