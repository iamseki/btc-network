use std::error::Error;
use std::net::TcpStream;
use std::time::Duration;

use crate::wire::{self, Command, Message, build_version_payload, read_message, send_message};

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

    pub fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        let payload = build_version_payload(wire::constants::PROTOCOL_VERSION, 0)?;
        send_message(&mut self.stream, Command::Version, &payload)?;

        let mut got_version = false;
        let mut got_verack = false;

        while !(got_version && got_verack) {
            let raw = read_message(&mut self.stream)?;
            let msg = Message::try_from(raw)?;

            match msg {
                Message::Version(_) => {
                    got_version = true;

                    // 2️⃣ Always signal BIP155 support
                    send_message(&mut self.stream, Command::SendAddrV2, &[])?;

                    // 3️⃣ Send verack
                    send_message(&mut self.stream, Command::Verack, &[])?;
                }
                Message::Verack => {
                    got_verack = true;
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub fn send(&mut self, command: Command, payload: &[u8]) -> Result<(), Box<dyn Error>> {
        send_message(&mut self.stream, command, payload)?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Message, Box<dyn Error>> {
        let raw = read_message(&mut self.stream)?;
        Ok(Message::try_from(raw)?)
    }
}
