use btc_network::wire;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn handshake(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    // Send version
    let version_payload = wire::build_version_payload(wire::constants::PROTOCOL_VERSION, 0)?;
    wire::send_message(stream, wire::Command::Version, &version_payload)?;

    // Receive peer version
    let msg = wire::Message::try_from(wire::read_message(stream)?)?;
    println!("Received: {:?}", msg);

    // Signal addrv2 support (must be before verack)
    wire::send_message(stream, wire::Command::SendAddrV2, &[])?;

    // Send verack
    wire::send_message(stream, wire::Command::Verack, &[])?;

    // Receive verack
    let msg = wire::Message::try_from(wire::read_message(stream)?)?;
    println!("Received: {:?}", msg);

    Ok(())
}

fn listen(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match wire::read_message(stream) {
            Ok(raw) => {
                println!(
                    "Received Command: {:?}, payload_len: {}",
                    raw.command,
                    raw.payload.len()
                );

                // Respond to ping to keep connection alive
                if raw.command == wire::Command::Ping {
                    wire::send_message(stream, wire::Command::Pong, &raw.payload)?;
                    println!("→ Sent Pong");
                }
            }

            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                println!("Peer closed connection.");
                break;
            }

            Err(e) => {
                println!("Read error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node = "seed.bitcoin.sipa.be:8333";
    println!("Connecting to: {node}");

    let addr = node.to_socket_addrs()?.next().expect("to get socket addrs");

    let timeout = Duration::from_secs(30);

    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;

    handshake(&mut stream)?;

    // Now just listen forever
    // Nothings happen because bitcoin network is "PULL BASED"
    listen(&mut stream)?;

    Ok(())
}
