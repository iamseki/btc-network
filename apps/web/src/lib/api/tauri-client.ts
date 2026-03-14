import type { BtcAppClient } from "./client";
import type {
  AddrResult,
  BlockDownloadResult,
  BlockSummary,
  ConnectionRequest,
  HandshakeResult,
  LastBlockHeightResult,
  PingResult,
  UiLogEvent,
} from "./types";

async function invoke<T>(
  command: string,
  payload: Record<string, unknown>,
): Promise<T> {
  const mod = await import("@tauri-apps/api/core");
  return mod.invoke<T>(command, payload);
}

export const tauriClient: BtcAppClient = {
  handshake(request: ConnectionRequest): Promise<HandshakeResult> {
    return invoke<HandshakeResult>("handshake", { request });
  },
  ping(node: string): Promise<PingResult> {
    return invoke<PingResult>("ping", { request: { node } });
  },
  getAddr(node: string): Promise<AddrResult> {
    return invoke<AddrResult>("get_peer_addresses", { request: { node } });
  },
  getLastBlockHeight(node: string): Promise<LastBlockHeightResult> {
    return invoke<LastBlockHeightResult>("get_last_block_height", { request: { node } });
  },
  getBlock(node: string, hash: string): Promise<BlockSummary> {
    return invoke<BlockSummary>("get_block_summary", { request: { node, hash } });
  },
  downloadBlock(node: string, hash: string): Promise<BlockDownloadResult> {
    return invoke<BlockDownloadResult>("download_block", { request: { node, hash } });
  },
  getRecentEvents(): Promise<UiLogEvent[]> {
    return Promise.resolve([]);
  },
};
