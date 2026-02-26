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
    GetBlock {
        #[arg(long)]
        hash: String,
    },
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
        Commands::GetBlock { hash } => get_block(&mut session, hash)?,
    }

    Ok(())
}

/// Receives the next decoded Bitcoin P2P message from the peer.
///
/// It automatically handle Ping
///
/// The name `recv` "receive" follows conventional socket APIs (`recv()` in
/// POSIX/BSD sockets) and indicates a blocking receive operation.
fn recv_until<F>(session: &mut Session, mut handler: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(Message) -> Result<bool, Box<dyn std::error::Error>>,
{
    loop {
        let msg = session.recv()?;

        if let Message::Ping(payload) = &msg {
            session.send(Command::Pong, payload)?;
            continue;
        }

        if handler(msg)? {
            break;
        }
    }

    Ok(())
}

fn ping(session: &mut Session) -> Result<(), Box<dyn Error>> {
    let nonce: u64 = rand::thread_rng().r#gen();

    println!("Sending ping");
    session.send(Command::Ping, &nonce.to_le_bytes())?;

    recv_until(session, |msg| match msg {
        Message::Pong(payload) => {
            let returned = u64::from_le_bytes(payload[..8].try_into()?);
            println!(
                "Received matching pong. ping nounce: {}, pong nonce: {}",
                nonce, returned
            );
            Ok(true)
        }
        other => {
            println!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
}

fn get_addresses(session: &mut Session) -> Result<(), Box<dyn Error>> {
    println!("Requesting peer addresses...");
    session.send(Command::GetAddr, &[])?;

    recv_until(session, |msg| match msg {
        Message::AddrV2(entries) => {
            println!("Received {} peers (addrv2)", entries.len());
            for e in entries {
                println!("  {:?}:{:?}", e.addr, e.port);
            }
            Ok(true)
        }
        Message::Addr(entries) => {
            println!("Received {} peers (legacy addr)", entries.len());
            for e in entries {
                println!("  {}:{}", e.addr.ip, e.addr.port);
            }
            Ok(true)
        }
        other => {
            println!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
}

fn get_headers(session: &mut Session) -> Result<(), Box<dyn Error>> {
    println!("Requesting headers from genesis...");

    let payload = wire::build_getheaders_payload(&[wire::constants::GENESIS_BLOCK_HASH_MAINNET]);

    session.send(Command::GetHeaders, &payload)?;

    recv_until(session, |msg| match msg {
        Message::Headers(headers) => {
            println!("Received {} headers", headers.len());

            if let Some(last) = headers.last() {
                let mut hash = last.hash();
                hash.reverse();
                println!("Last header hash: {}", hex::encode(hash));
            }

            Ok(true)
        }
        other => {
            println!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
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

        let mut received_headers = None;

        recv_until(session, |msg| match msg {
            Message::Headers(h) => {
                received_headers = Some(h);
                Ok(true)
            }
            other => {
                println!("Received: {:?}", other);
                Ok(false)
            }
        })?;

        let headers = received_headers.expect("headers expected");

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

fn get_block(session: &mut Session, hash_hex: String) -> Result<(), Box<dyn Error>> {
    let mut hash = hex::decode(hash_hex)?;
    hash.reverse();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);

    let payload = wire::build_getdata_block_payload(arr);
    session.send(Command::GetData, &payload)?;

    recv_until(session, |msg| match msg {
        Message::Block(block) => {
            let mb = block.serialized_size as f64 / (1024.0 * 1024.0);

            println!("Block hash: {}", hex::encode(block.header.hash()));
            println!("Tx count: {}", block.tx_count);
            println!("Size: {:.2} MB", mb);

            if block.tx_count > 0 {
                let tx = block
                    .transactions
                    .first()
                    .ok_or("block has no transactions")?;

                println!("tx.is_coinbase => {}, tx: {:?}", tx.is_coinbase(), tx);
            }

            Ok(true)
        }
        other => {
            println!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
}
