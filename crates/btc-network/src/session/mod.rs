//! Stateful peer interaction over an established transport connection.
//!
//! The session layer owns Bitcoin P2P sequencing once a `TcpStream` already exists.
//! It sits above the wire layer and below application-facing clients.
//!
//! Responsibilities:
//! - Enforce handshake ordering
//! - Preserve ping/pong liveness while other operations are in flight
//! - Expose typed send/receive helpers over a connected peer session
//! - Coordinate request/response message flow without embedding CLI or UI concerns
//!
//! Non-responsibilities:
//! - DNS resolution or TCP connection establishment
//! - Byte-level parsing or envelope framing
//! - Mapping protocol data into app-specific DTOs

use std::error::Error;
use std::io;
use std::net::TcpStream;
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::wire::message::VersionMessage;
use crate::wire::{
    self, Command, Message, RawMessage, build_version_payload, read_message, read_message_async,
    send_message, send_message_async,
};

pub struct Session {
    stream: TcpStream,
}

impl Session {
    pub fn new(stream: TcpStream) -> Self {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set_read_timeout");

        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("set_write_timeout");

        Self { stream }
    }

    pub fn handshake(&mut self) -> Result<VersionMessage, Box<dyn Error>> {
        let payload = build_version_payload(wire::constants::PROTOCOL_VERSION, 0)?;
        send_message(&mut self.stream, Command::Version, &payload)?;

        let mut version_msg: Option<VersionMessage> = None;
        let mut got_verack = false;

        while !(version_msg.is_some() && got_verack) {
            let raw = read_message(&mut self.stream)?;
            let msg = Message::try_from(raw)?;

            match msg {
                Message::Version(v) => {
                    if version_msg.is_none() {
                        debug!("[handshake] got version msg: {:?}", v);
                        // 2️⃣ Always signal BIP155 support
                        send_message(&mut self.stream, Command::SendAddrV2, &[])?;

                        // 3️⃣ Send verack
                        send_message(&mut self.stream, Command::Verack, &[])?;
                        version_msg = Some(v);
                    }
                }
                Message::Verack => {
                    got_verack = true;
                }
                Message::Ping(payload) => {
                    send_message(&mut self.stream, Command::Pong, &payload)?;
                }
                _ => {}
            }
        }

        version_msg.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "peer did not send version").into()
        })
    }

    /// Sends a ping and waits for the matching pong while keeping the session alive.
    pub fn ping(&mut self, nonce: u64) -> Result<u64, Box<dyn Error>> {
        self.send(Command::Ping, &nonce.to_le_bytes())?;

        self.recv_until(|msg, session| match msg {
            Message::Pong(payload) => {
                if payload.len() != 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pong payload must be exactly 8 bytes",
                    )
                    .into());
                }
                let returned = u64::from_le_bytes(payload[..8].try_into()?);
                Ok(Some(returned))
            }
            Message::Ping(payload) => {
                session.send(Command::Pong, &payload)?;
                Ok(None)
            }
            _ => Ok(None),
        })
    }

    pub fn send(&mut self, command: Command, payload: &[u8]) -> Result<(), Box<dyn Error>> {
        send_message(&mut self.stream, command, payload)?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Message, Box<dyn Error>> {
        let raw = read_message(&mut self.stream)?;
        Ok(Message::try_from(raw)?)
    }

    pub fn recv_raw(&mut self) -> Result<RawMessage, Box<dyn Error>> {
        Ok(read_message(&mut self.stream)?)
    }

    pub fn recv_until<T, F>(&mut self, mut handler: F) -> Result<T, Box<dyn Error>>
    where
        F: FnMut(Message, &mut Session) -> Result<Option<T>, Box<dyn Error>>,
    {
        loop {
            let msg = self.recv()?;
            if let Some(result) = handler(msg, self)? {
                return Ok(result);
            }
        }
    }
}

/// Async crawler-facing peer session over a Tokio TCP stream.
pub struct AsyncSession {
    stream: AsyncTcpStream,
    io_timeout: Duration,
}

impl AsyncSession {
    pub fn new(stream: AsyncTcpStream, io_timeout: Duration) -> Self {
        Self { stream, io_timeout }
    }

    pub async fn handshake(&mut self) -> Result<VersionMessage, Box<dyn Error>> {
        let payload = build_version_payload(wire::constants::PROTOCOL_VERSION, 0)?;
        self.send(Command::Version, &payload).await?;

        let mut version_msg: Option<VersionMessage> = None;
        let mut got_verack = false;

        while !(version_msg.is_some() && got_verack) {
            let raw = self.recv_raw().await?;
            let msg = Message::try_from(raw)?;

            match msg {
                Message::Version(v) => {
                    if version_msg.is_none() {
                        debug!("[handshake] got version msg: {:?}", v);
                        self.send(Command::SendAddrV2, &[]).await?;
                        self.send(Command::Verack, &[]).await?;
                        version_msg = Some(v);
                    }
                }
                Message::Verack => {
                    got_verack = true;
                }
                Message::Ping(payload) => {
                    self.send(Command::Pong, &payload).await?;
                }
                _ => {}
            }
        }

        version_msg.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "peer did not send version").into()
        })
    }

    pub async fn send(&mut self, command: Command, payload: &[u8]) -> Result<(), Box<dyn Error>> {
        with_io_timeout(
            self.io_timeout,
            "write",
            send_message_async(&mut self.stream, command, payload),
        )
        .await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Message, Box<dyn Error>> {
        let raw = self.recv_raw().await?;
        Ok(Message::try_from(raw)?)
    }

    pub async fn recv_raw(&mut self) -> Result<RawMessage, Box<dyn Error>> {
        let raw = with_io_timeout(
            self.io_timeout,
            "read",
            read_message_async(&mut self.stream),
        )
        .await?;
        Ok(raw)
    }
}

async fn with_io_timeout<T, F>(
    io_timeout: Duration,
    operation: &str,
    future: F,
) -> Result<T, io::Error>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    timeout(io_timeout, future).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{operation} timed out after {io_timeout:?}"),
        )
    })?
}

#[cfg(test)]
mod tests {
    use tracing::error;

    use super::*;
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::thread;
    use tokio::net::TcpListener as AsyncTcpListener;

    fn bind_listener_or_skip() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => Some(l),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                error!("skipping session socket test: {e}");
                None
            }
            Err(e) => panic!("bind listener failed: {e}"),
        }
    }

    #[test]
    fn handshake_returns_peer_version_and_enforces_order() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");
            peer.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set peer read timeout");

            let first = read_message(&mut peer).expect("read first message");
            assert_eq!(first.command, Command::Version);

            let peer_version =
                build_version_payload(wire::constants::PROTOCOL_VERSION, 0x08).expect("version");
            send_message(&mut peer, Command::Version, &peer_version).expect("send version");

            let second = read_message(&mut peer).expect("read second message");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message(&mut peer).expect("read third message");
            assert_eq!(third.command, Command::Verack);

            send_message(&mut peer, Command::Verack, &[]).expect("send verack");
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut session = Session::new(stream);
        let version = session.handshake().expect("handshake success");

        assert_eq!(version.version, wire::constants::PROTOCOL_VERSION);
        server.join().expect("join server");
    }

    #[test]
    fn handshake_replies_pong_when_ping_received() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");
            peer.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set peer read timeout");

            let first = read_message(&mut peer).expect("read first");
            assert_eq!(first.command, Command::Version);

            let peer_version =
                build_version_payload(wire::constants::PROTOCOL_VERSION, 0).expect("version");
            send_message(&mut peer, Command::Version, &peer_version).expect("send version");

            let ping_nonce = 0x1122334455667788u64.to_le_bytes();
            send_message(&mut peer, Command::Ping, &ping_nonce).expect("send ping");

            let second = read_message(&mut peer).expect("read second");
            assert_eq!(second.command, Command::SendAddrV2);

            let third = read_message(&mut peer).expect("read third");
            assert_eq!(third.command, Command::Verack);

            let fourth = read_message(&mut peer).expect("read fourth");
            assert_eq!(fourth.command, Command::Pong);
            assert_eq!(fourth.payload, ping_nonce);

            send_message(&mut peer, Command::Verack, &[]).expect("send verack");
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut session = Session::new(stream);
        session.handshake().expect("handshake success");

        server.join().expect("join server");
    }

    #[test]
    fn send_and_recv_wrappers_work() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");
            peer.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set peer read timeout");

            let sent = read_message(&mut peer).expect("read sent ping");
            assert_eq!(sent.command, Command::Ping);
            assert_eq!(sent.payload, 0xAABBCCDDEEFF0011u64.to_le_bytes());

            let pong_nonce = 0xAABBCCDDEEFF0011u64.to_le_bytes();
            send_message(&mut peer, Command::Pong, &pong_nonce).expect("send pong");
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut session = Session::new(stream);
        let nonce = 0xAABBCCDDEEFF0011u64.to_le_bytes();
        session.send(Command::Ping, &nonce).expect("send ping");

        let msg = session.recv().expect("recv pong");
        match msg {
            Message::Pong(payload) => assert_eq!(payload, nonce),
            other => panic!("expected pong, got {:?}", other),
        }

        server.join().expect("join server");
    }

    #[test]
    fn ping_returns_matching_nonce_and_replies_to_inbound_ping() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");
            peer.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set peer read timeout");

            let ping = read_message(&mut peer).expect("read ping");
            assert_eq!(ping.command, Command::Ping);
            assert_eq!(ping.payload, 0xAABBCCDDEEFF0011u64.to_le_bytes());

            let inbound_ping_nonce = 0x1122334455667788u64.to_le_bytes();
            send_message(&mut peer, Command::Ping, &inbound_ping_nonce).expect("send ping");

            let pong = read_message(&mut peer).expect("read pong");
            assert_eq!(pong.command, Command::Pong);
            assert_eq!(pong.payload, inbound_ping_nonce);

            send_message(&mut peer, Command::Pong, &ping.payload).expect("send pong");
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut session = Session::new(stream);
        let echoed = session.ping(0xAABBCCDDEEFF0011).expect("ping success");

        assert_eq!(echoed, 0xAABBCCDDEEFF0011);
        server.join().expect("join server");
    }

    #[test]
    fn recv_raw_returns_raw_message() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");
            send_message(&mut peer, Command::Verack, &[]).expect("send verack");
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut session = Session::new(stream);
        let raw = session.recv_raw().expect("recv raw");
        assert_eq!(raw.command, Command::Verack);
        assert!(raw.payload.is_empty());

        server.join().expect("join server");
    }

    #[test]
    fn ping_rejects_short_pong_payload() {
        let Some(listener) = bind_listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept client");
            peer.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set peer read timeout");

            let ping = read_message(&mut peer).expect("read ping");
            assert_eq!(ping.command, Command::Ping);

            send_message(&mut peer, Command::Pong, &[0u8; 4]).expect("send short pong");
        });

        let stream = TcpStream::connect(addr).expect("connect");
        let mut session = Session::new(stream);
        let err = session
            .ping(0xAABBCCDDEEFF0011)
            .expect_err("short pong should fail");

        assert!(
            err.to_string()
                .contains("pong payload must be exactly 8 bytes"),
            "unexpected error: {err}"
        );
        server.join().expect("join server");
    }

    #[tokio::test]
    async fn async_handshake_returns_peer_version_and_enforces_order() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.expect("accept client");

            let first = read_message_async(&mut peer)
                .await
                .expect("read first message");
            assert_eq!(first.command, Command::Version);

            let peer_version =
                build_version_payload(wire::constants::PROTOCOL_VERSION, 0x08).expect("version");
            send_message_async(&mut peer, Command::Version, &peer_version)
                .await
                .expect("send version");

            let second = read_message_async(&mut peer)
                .await
                .expect("read second message");
            assert_eq!(second.command, Command::SendAddrV2);
            let third = read_message_async(&mut peer)
                .await
                .expect("read third message");
            assert_eq!(third.command, Command::Verack);

            send_message_async(&mut peer, Command::Verack, &[])
                .await
                .expect("send verack");
        });

        let stream = AsyncTcpStream::connect(addr).await.expect("connect");
        let mut session = AsyncSession::new(stream, Duration::from_secs(2));
        let version = session.handshake().await.expect("handshake success");

        assert_eq!(version.version, wire::constants::PROTOCOL_VERSION);
        server.await.expect("join server");
    }
}
