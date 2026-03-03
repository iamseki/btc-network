use std::error::Error;
use std::io;
use std::net::TcpStream;
use std::time::Duration;

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
                        println!("[handshake] - got version msg: {:?}", v);
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
