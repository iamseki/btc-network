import type { BtcAppClient } from "./client";
import type {
  AddrResult,
  BlockDownloadResult,
  BlockSummary,
  ConnectionRequest,
  HandshakeResult,
  LastBlockHeightProgress,
  LastBlockHeightResult,
  PingResult,
  UiLogEvent,
} from "./types";

const CHAIN_HEIGHT_PROGRESS_EVENT = "chain-height-progress";

function nextOperationId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `chain-height-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

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
  async getLastBlockHeight(
    node: string,
    onProgress?: (progress: LastBlockHeightProgress) => void,
  ): Promise<LastBlockHeightResult> {
    const operationId = nextOperationId();
    const eventMod = await import("@tauri-apps/api/event");
    const unlisten = await eventMod.listen<LastBlockHeightProgress>(
      CHAIN_HEIGHT_PROGRESS_EVENT,
      (event) => {
        if (event.payload.operationId !== operationId) {
          return;
        }

        onProgress?.(event.payload);
      },
    );

    try {
      return await invoke<LastBlockHeightResult>("get_last_block_height", {
        request: { node, operationId },
      });
    } finally {
      unlisten();
    }
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
