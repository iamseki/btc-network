use clap::{Parser, Subcommand};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use btc_network::session::Session;
use btc_network::wire::{self, Command, Message};

use std::time::Instant;

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
    GetHeaders,
    LastBlockHeader,
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
        Commands::GetHeaders => get_headers(&mut session)?,
        Commands::LastBlockHeader => last_block_header(&mut session)?,
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

fn get_headers(session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting headers from genesis...");

    let payload = wire::build_getheaders_payload(&[wire::constants::GENESIS_BLOCK_HASH_MAINNET]);

    session.send(Command::GetHeaders, &payload)?;

    loop {
        match session.recv()? {
            Message::Headers(headers) => {
                println!("Received {} headers", headers.len());

                if let Some(last) = headers.last() {
                    let mut hash = last.hash();
                    hash.reverse(); // display big-endian

                    println!("Last header hash: {}", hex::encode(hash));
                }

                break;
            }

            Message::Ping(payload) => {
                session.send(Command::Pong, &payload)?;
            }

            other => {
                println!("Received: {:?}", other);
            }
        }
    }

    Ok(())
}

/// The `headers` message returns block headers in strictly
/// chronological (forward) order along the peer's active chain.
///
/// Semantics:
/// - The peer finds the first locator hash it recognizes.
/// - It then returns headers *after* that block.
/// - Headers are ordered from oldest → newest.
/// - At most 2000 headers are returned per message.
///
/// This ordering allows the client to validate linkage linearly:
///
///     header[i].prev_blockhash == header[i-1].hash()
///
/// Even though block headers only contain a backward pointer
/// (`prev_blockhash`), peers maintain a forward index internally
/// and iterate forward when constructing the response.
///
/// Reference:
/// https://developer.bitcoin.org/reference/p2p_networking.html#getheaders
///
/// This forward ordering is relied upon by header-first sync
/// and is required for deterministic chain construction.
fn last_block_header(session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting header sync from genesis...");

    let start = Instant::now();
    let mut round = 0usize;
    let mut total_headers = 0usize;
    let mut current_locator = wire::constants::GENESIS_BLOCK_HASH_MAINNET;

    loop {
        round += 1;

        println!(
            "[round {}] requesting headers (total so far: {})",
            round, total_headers
        );

        let payload = wire::build_getheaders_payload(&[current_locator]);
        session.send(Command::GetHeaders, &payload)?;

        let headers = loop {
            match session.recv()? {
                Message::Headers(h) => break h,
                Message::Ping(p) => {
                    session.send(Command::Pong, &p)?;
                }
                other => {
                    println!("Received: {:?}", other);
                }
            }
        };

        let count = headers.len();
        println!("[round {}] received {} headers", round, count);

        if count == 0 {
            println!("No new headers returned. Already at tip?");
            break;
        }

        total_headers += count;

        let last = headers.last().expect("headers not empty");

        let mut last_hash = last.hash();
        last_hash.reverse(); // big-endian for display

        println!(
            "[round {}] last header hash: {}",
            round,
            hex::encode(last_hash)
        );

        // If less than 2000, we reached peer tip
        if count < 2000 {
            println!();
            println!("Reached peer tip.");
            println!("Total headers fetched: {}", total_headers);
            println!("Rounds: {}", round);
            println!("Elapsed: {:.2?}", start.elapsed());
            println!("Most recent block: {}", hex::encode(last_hash));
            break;
        }

        current_locator = last.hash();
    }

    Ok(())
}
