use clap::{Parser, Subcommand};
use std::error::Error;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use btc_network_observability as observability;
use btc_network::client::peer as peer_client;
use btc_network::session::Session;
use btc_network::wire::{self, Command, Message};
use tracing::{debug, info};

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
    DownloadBlock {
        #[arg(long)]
        hash: String,
        #[arg(long)]
        out: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    observability::init_tracing();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Ping => {
            let result = peer_client::ping_node(&cli.node)?;
            info!(
                "Received matching pong. ping nonce: {}, pong nonce: {}",
                result.nonce, result.echoed_nonce
            );
            return Ok(());
        }
        Commands::GetAddr => {
            let result = peer_client::get_peer_addresses_node(&cli.node)?;
            info!("Received {} peers", result.addresses.len());
            for entry in result.addresses {
                info!("  [{}] {}:{}", entry.network, entry.address, entry.port);
            }
            return Ok(());
        }
        Commands::LastBlockHeader => {
            let result = peer_client::get_last_block_height_node(&cli.node)?;
            info!("Reached peer tip.");
            info!("Total headers fetched: {}", result.height);
            info!("Rounds: {}", result.rounds);
            info!("Elapsed: {:.2?}", Duration::from_millis(result.elapsed_ms));
            info!(
                "Most recent block: {}",
                result.best_block_hash.as_deref().unwrap_or("n/a")
            );
            return Ok(());
        }
        Commands::GetBlock { hash } => {
            let result = peer_client::get_block_summary_node(&cli.node, hash)?;
            let mb = result.serialized_size as f64 / (1024.0 * 1024.0);
            info!("Block hash: {}", result.hash);
            info!("Tx count: {}", result.tx_count);
            info!("Size: {:.2} MB", mb);
            info!("Coinbase detected => {}", result.coinbase_tx_detected);
            return Ok(());
        }
        Commands::DownloadBlock { hash, out } => {
            let result = peer_client::download_block_node(&cli.node, hash, out.as_deref())?;
            info!(
                "Saved block to {} (raw block: {} bytes, blk record: {} bytes)",
                result.output_path,
                result.raw_bytes,
                result.raw_bytes + 8
            );
            return Ok(());
        }
        Commands::GetHeaders => {}
    }

    info!("Connecting to {}", cli.node);

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
        Commands::GetHeaders => get_headers(&mut session)?,
        Commands::Ping
        | Commands::GetAddr
        | Commands::LastBlockHeader
        | Commands::GetBlock { .. }
        | Commands::DownloadBlock { .. } => unreachable!("handled before session setup"),
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

fn get_headers(session: &mut Session) -> Result<(), Box<dyn Error>> {
    info!("Requesting headers from genesis...");

    let payload = wire::build_getheaders_payload(&[wire::constants::GENESIS_BLOCK_HASH_MAINNET]);

    session.send(Command::GetHeaders, &payload)?;

    recv_until(session, |msg| match msg {
        Message::Headers(headers) => {
            info!("Received {} headers", headers.len());

            if let Some(last) = headers.last() {
                let mut hash = last.hash();
                hash.reverse();
                info!("Last header hash: {}", hex::encode(hash));
            }

            Ok(true)
        }
        other => {
            debug!("Received (ignored): {:?}", other);
            Ok(false)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_get_headers_command() {
        let cli = Cli::try_parse_from(["btc-cli", "--node", "seed.bitcoin.sipa.be:8333", "get-headers"])
            .expect("parse get-headers");

        assert!(matches!(cli.command, Commands::GetHeaders));
        assert_eq!(cli.node, "seed.bitcoin.sipa.be:8333");
    }

    #[test]
    fn cli_parses_download_block_command_with_output() {
        let cli = Cli::try_parse_from([
            "btc-cli",
            "--node",
            "seed.bitcoin.sipa.be:8333",
            "download-block",
            "--hash",
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "--out",
            "blk.dat",
        ])
        .expect("parse download-block");

        let Commands::DownloadBlock { hash, out } = cli.command else {
            panic!("expected download-block");
        };

        assert_eq!(
            hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(out.as_deref(), Some("blk.dat"));
    }
}
