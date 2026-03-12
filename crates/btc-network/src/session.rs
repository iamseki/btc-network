use std::error::Error;
use std::io;
use std::net::TcpStream;
use std::time::Duration;
use tracing::debug;

use crate::wire::message::VersionMessage;
use crate::wire::{
    self, Command, Message, RawMessage, build_version_payload, read_message, send_message,
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
}

#[cfg(test)]
mod tests {
    use tracing::error;

    use super::*;
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::thread;

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
}
