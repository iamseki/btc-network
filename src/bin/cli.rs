use clap::{Parser, Subcommand};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use btc_network::session::Session;
use btc_network::wire::{Command, Message};

use rand::Rng;

#[derive(Parser)]
#[command(name = "btc-cli")]
struct Cli {
    #[arg(long)]
    node: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Ping,
    GetAddr,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    println!("Connecting to {}", cli.node);

    let addr = cli
        .node
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve address")?;

    let timeout = Duration::from_secs(30);
    let stream = TcpStream::connect_timeout(&addr, timeout)?;

    let mut session = Session::new(stream);

    session.handshake()?;

    match cli.command {
        Commands::Ping => ping(&mut session)?,
        Commands::GetAddr => get_addresses(&mut session)?,
    }

    Ok(())
}

fn ping(session: &mut Session) -> Result<(), Box<dyn Error>> {
    let nonce: u64 = rand::thread_rng().r#gen();

    println!("Sending ping");

    session.send(Command::Ping, &nonce.to_le_bytes())?;

    loop {
        let msg = session.recv()?;

        match msg {
            Message::Pong(payload) => {
                let returned = u64::from_le_bytes(payload[..8].try_into()?);

                if returned == nonce {
                    println!("Received matching pong");
                    break;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn get_addresses(session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting peer addresses...");

    // 1️⃣ Send getaddr
    session.send(Command::GetAddr, &[])?;

    // 2️⃣ Wait for addr or addrv2
    loop {
        let msg = session.recv()?;

        match msg {
            Message::AddrV2(entries) => {
                println!("Received {} peers (addrv2)", entries.len());

                for entry in entries {
                    println!("  {:?}:{:?}", entry.addr, entry.port);
                }

                break;
            }

            Message::Addr(entries) => {
                println!("Received {} peers (legacy addr)", entries.len());

                for entry in entries {
                    println!("  {}:{}", entry.addr.ip, entry.addr.port);
                }

                break;
            }

            Message::Ping(payload) => {
                session.send(Command::Pong, &payload)?;
            }

            other => {
                println!("Other command received from get addresses: {:?}", other);
            }
        }
    }

    Ok(())
}
