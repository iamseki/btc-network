use btc_network::client::peer;
use serde::{Deserialize, Serialize};

/// Minimal desktop request for single-peer actions.
#[derive(Debug, Deserialize)]
pub struct ConnectionRequest {
    pub node: String,
}

/// Desktop-facing handshake payload exposed to the web UI through Tauri.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeResponse {
    pub node: String,
    pub protocol_version: i32,
    pub services: String,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: Option<bool>,
}

/// Desktop-facing ping result with hex-encoded nonces for direct display.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PingResponse {
    pub node: String,
    pub nonce: String,
    pub echoed_nonce: String,
}

#[tauri::command]
pub async fn handshake(request: ConnectionRequest) -> Result<HandshakeResponse, String> {
    let summary = tauri::async_runtime::spawn_blocking(move || {
        peer::handshake_node(&request.node).map_err(|err| err.to_string())
    })
    .await
    .map_err(|err| err.to_string())??;

    Ok(HandshakeResponse {
        node: summary.node,
        protocol_version: summary.protocol_version,
        services: summary.services,
        user_agent: summary.user_agent,
        start_height: summary.start_height,
        relay: summary.relay,
    })
}

/// Runs the shared Rust ping workflow through the desktop command boundary.
#[tauri::command]
pub async fn ping(request: ConnectionRequest) -> Result<PingResponse, String> {
    let summary = tauri::async_runtime::spawn_blocking(move || {
        peer::ping_node(&request.node).map_err(|err| err.to_string())
    })
    .await
    .map_err(|err| err.to_string())??;

    Ok(PingResponse {
        node: summary.node,
        nonce: format!("{:#018x}", summary.nonce),
        echoed_nonce: format!("{:#018x}", summary.echoed_nonce),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_network::wire::{Command, build_version_payload, read_message, send_message};
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::thread;
    fn bind_listener_or_skip() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping desktop command socket test: {err}");
                None
            }
            Err(err) => panic!("bind listener failed: {err}"),
        }
    }

    #[test]
    fn handshake_command_maps_shared_result() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version =
                build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0x08)
                    .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");
        });

        let result = tauri::async_runtime::block_on(handshake(ConnectionRequest {
            node: addr.to_string(),
        }))
        .expect("handshake command");

        assert_eq!(result.node, addr.to_string());
        assert_eq!(
            result.protocol_version,
            btc_network::wire::constants::PROTOCOL_VERSION
        );
        assert_eq!(result.services, "0x0000000000000008");

        server.join().expect("join");
    }

    #[test]
    fn ping_command_returns_hex_nonce_fields() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let version = build_version_payload(btc_network::wire::constants::PROTOCOL_VERSION, 0)
                .expect("version");
            send_message(&mut peer, Command::Version, &version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let ping = read_message(&mut peer).expect("read ping");
            assert_eq!(ping.command, Command::Ping);
            send_message(&mut peer, Command::Pong, &ping.payload).expect("send pong");
        });

        let result = tauri::async_runtime::block_on(ping(ConnectionRequest {
            node: addr.to_string(),
        }))
        .expect("ping command");

        assert_eq!(result.node, addr.to_string());
        assert!(result.nonce.starts_with("0x"));
        assert_eq!(result.nonce, result.echoed_nonce);

        server.join().expect("join");
    }
}
