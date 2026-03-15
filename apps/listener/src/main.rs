use btc_network::wire;
use btc_network_observability as observability;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use tracing::{info, warn};

fn handshake(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    // Send version
    let version_payload = wire::build_version_payload(wire::constants::PROTOCOL_VERSION, 0)?;
    wire::send_message(stream, wire::Command::Version, &version_payload)?;

    // Receive peer version
    let msg = wire::Message::try_from(wire::read_message(stream)?)?;
    info!("Received: {:?}", msg);

    // Signal addrv2 support (must be before verack)
    wire::send_message(stream, wire::Command::SendAddrV2, &[])?;

    // Send verack
    wire::send_message(stream, wire::Command::Verack, &[])?;

    // Receive verack
    let msg = wire::Message::try_from(wire::read_message(stream)?)?;
    info!("Received: {:?}", msg);

    Ok(())
}

fn listen(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match wire::read_message(stream) {
            Ok(raw) => {
                info!(
                    "Received Command: {:?}, payload_len: {}",
                    raw.command,
                    raw.payload.len()
                );

                // Respond to ping to keep connection alive
                if raw.command == wire::Command::Ping {
                    wire::send_message(stream, wire::Command::Pong, &raw.payload)?;
                    info!("Sent Pong");
                }
            }

            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("Peer closed connection.");
                break;
            }

            Err(e) => {
                warn!("Read error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    observability::init_tracing();
    let node = "seed.bitcoin.sipa.be:8333";
    info!("Connecting to: {node}");

    let addr = node.to_socket_addrs()?.next().expect("to get socket addrs");

    let timeout = Duration::from_secs(30);

    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;

    handshake(&mut stream)?;

    // Now just listen forever
    // Nothings happen because bitcoin network is "PULL BASED"
    listen(&mut stream)?;

    Ok(())
}
