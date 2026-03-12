use rand::Rng;
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::session::Session;
use crate::wire::message::VersionMessage;
use crate::wire::{Command, Message};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeSummary {
    pub node: String,
    pub protocol_version: i32,
    pub services: String,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingSummary {
    pub node: String,
    pub nonce: u64,
    pub echoed_nonce: u64,
}

pub fn handshake_node(node: &str) -> Result<HandshakeSummary, Box<dyn Error>> {
    let mut session = connect(node, Duration::from_secs(30))?;
    handshake_session(node, &mut session)
}

pub fn ping_node(node: &str) -> Result<PingSummary, Box<dyn Error>> {
    let mut session = connect(node, Duration::from_secs(30))?;
    let _ = handshake_session(node, &mut session)?;
    ping_session(node, &mut session)
}

pub fn handshake_session(
    node: &str,
    session: &mut Session,
) -> Result<HandshakeSummary, Box<dyn Error>> {
    let version = session.handshake()?;
    Ok(map_handshake(node, version))
}

pub fn ping_session(node: &str, session: &mut Session) -> Result<PingSummary, Box<dyn Error>> {
    let nonce: u64 = rand::thread_rng().r#gen();
    ping_session_with_nonce(node, session, nonce)
}

fn connect(node: &str, timeout: Duration) -> Result<Session, Box<dyn Error>> {
    let addr = node
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve address")?;

    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    Ok(Session::new(stream))
}

fn map_handshake(node: &str, version: VersionMessage) -> HandshakeSummary {
    HandshakeSummary {
        node: node.to_owned(),
        protocol_version: version.version,
        services: format!("{:#018x}", version.services.bits()),
        user_agent: version.user_agent,
        start_height: version.start_height,
        relay: version.relay,
    }
}

fn ping_session_with_nonce(
    node: &str,
    session: &mut Session,
    nonce: u64,
) -> Result<PingSummary, Box<dyn Error>> {
    session.send(Command::Ping, &nonce.to_le_bytes())?;

    recv_until(session, |msg| match msg {
        Message::Pong(payload) => {
            let returned = u64::from_le_bytes(payload[..8].try_into()?);
            Ok(Some(PingSummary {
                node: node.to_owned(),
                nonce,
                echoed_nonce: returned,
            }))
        }
        _ => Ok(None),
    })
}

fn recv_until<F>(
    session: &mut Session,
    mut handler: F,
) -> Result<PingSummary, Box<dyn std::error::Error>>
where
    F: FnMut(Message) -> Result<Option<PingSummary>, Box<dyn std::error::Error>>,
{
    loop {
        let msg = session.recv()?;

        if let Message::Ping(payload) = &msg {
            session.send(Command::Pong, payload)?;
            continue;
        }

        if let Some(result) = handler(msg)? {
            return Ok(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{build_version_payload, read_message, send_message};
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::thread;
    use tracing::error;

    fn bind_listener_or_skip() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                error!("skipping peer app socket test: {err}");
                None
            }
            Err(err) => panic!("bind listener failed: {err}"),
        }
    }

    #[test]
    fn handshake_session_maps_peer_version_into_summary() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let peer_version =
                build_version_payload(crate::wire::constants::PROTOCOL_VERSION, 0x08)
                    .expect("build version");
            send_message(&mut peer, Command::Version, &peer_version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);

            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);

            send_message(&mut peer, Command::Verack, &[]).expect("send verack");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let summary =
            handshake_session(&addr.to_string(), &mut session).expect("handshake session");

        assert_eq!(summary.node, addr.to_string());
        assert_eq!(summary.protocol_version, crate::wire::constants::PROTOCOL_VERSION);
        assert_eq!(summary.services, "0x0000000000000008");

        server.join().expect("join");
    }

    #[test]
    fn ping_session_returns_echoed_nonce() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");

            let first = read_message(&mut peer).expect("read version");
            assert_eq!(first.command, Command::Version);

            let peer_version =
                build_version_payload(crate::wire::constants::PROTOCOL_VERSION, 0)
                    .expect("build version");
            send_message(&mut peer, Command::Version, &peer_version).expect("send version");

            let second = read_message(&mut peer).expect("read sendaddrv2");
            assert_eq!(second.command, Command::SendAddrV2);

            let third = read_message(&mut peer).expect("read verack");
            assert_eq!(third.command, Command::Verack);

            send_message(&mut peer, Command::Verack, &[]).expect("send verack");

            let ping = read_message(&mut peer).expect("read ping");
            assert_eq!(ping.command, Command::Ping);
            send_message(&mut peer, Command::Pong, &ping.payload).expect("send pong");
        });

        let mut session = Session::new(TcpStream::connect(addr).expect("connect"));
        let _ = handshake_session(&addr.to_string(), &mut session).expect("handshake");
        let summary =
            ping_session_with_nonce(&addr.to_string(), &mut session, 0xAABBCCDDEEFF0011)
                .expect("ping");

        assert_eq!(summary.node, addr.to_string());
        assert_eq!(summary.nonce, 0xAABBCCDDEEFF0011);
        assert_eq!(summary.echoed_nonce, 0xAABBCCDDEEFF0011);

        server.join().expect("join");
    }
}
