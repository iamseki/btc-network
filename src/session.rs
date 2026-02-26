use std::error::Error;
use std::net::TcpStream;
use std::time::Duration;

use crate::wire::{self, Command, Message};

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
        let payload = wire::build_version_payload(70016, 0)?;
        wire::send_message(&mut self.stream, Command::Version, &payload)?;

        let mut got_version = false;
        let mut got_verack = false;

        while !(got_version && got_verack) {
            let raw = wire::read_message(&mut self.stream)?;
            let msg = Message::try_from(raw)?;

            match msg {
                Message::Version(_) => {
                    got_version = true;

                    // 2️⃣ Always signal BIP155 support
                    wire::send_message(&mut self.stream, Command::SendAddrV2, &[])?;

                    // 3️⃣ Send verack
                    wire::send_message(&mut self.stream, Command::Verack, &[])?;
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
        wire::send_message(&mut self.stream, command, payload)?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Message, Box<dyn Error>> {
        let raw = wire::read_message(&mut self.stream)?;
        Ok(Message::try_from(raw)?)
    }
}
