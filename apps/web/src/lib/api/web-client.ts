import type { BtcAppClient } from "./client";
import type {
  AddrResult,
  BlockDownloadRequest,
  BlockDownloadResult,
  BlockSummary,
  ConnectionRequest,
  HandshakeResult,
  LastBlockHeightProgress,
  LastBlockHeightResult,
  PingResult,
  UiLogEvent,
} from "./types";

function nowIso(): string {
  return new Date().toISOString();
}

function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => resolve(value), 120);
  });
}

const events: UiLogEvent[] = [
  {
    at: nowIso(),
    level: "info",
    message: "Web client is running in placeholder mode until the desktop and HTTP adapters are wired.",
  },
];

export const webClient: BtcAppClient = {
  handshake(request: ConnectionRequest): Promise<HandshakeResult> {
    return delay({
      node: request.node,
      protocolVersion: 70016,
      services: "0x0000000000000000",
      serviceNames: ["NONE"],
      userAgent: "/btc-network:ui-placeholder/",
      startHeight: 0,
      relay: null,
    });
  },

  ping(node: string): Promise<PingResult> {
    return delay({
      node,
      nonce: "0xfeedfacecafebeef",
      echoedNonce: "0xfeedfacecafebeef",
    });
  },

  getAddr(node: string): Promise<AddrResult> {
    return delay({
      node,
      addresses: [
        { address: "127.0.0.1", port: 8333, network: "ipv4" },
        { address: "::1", port: 8333, network: "ipv6" },
      ],
    });
  },

  async getLastBlockHeight(
    node: string,
    onProgress?: (progress: LastBlockHeightProgress) => void,
  ): Promise<LastBlockHeightResult> {
    const operationId = "web-placeholder-chain-height";

    onProgress?.({
      operationId,
      node,
      phase: "connecting",
      roundsCompleted: 0,
      headersSeen: 0,
      lastBatchCount: 0,
      bestBlockHash: null,
      elapsedMs: 0,
    });

    await delay(null);

    onProgress?.({
      operationId,
      node,
      phase: "requesting_headers",
      roundsCompleted: 470,
      headersSeen: 938408,
      lastBatchCount: 408,
      bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
      elapsedMs: 545450,
    });

    return {
      node,
      height: 938408,
      rounds: 470,
      elapsedMs: 545450,
      bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
    };
  },

  getBlock(_node: string, hash: string): Promise<BlockSummary> {
    return delay({
      hash,
      txCount: 1,
      serializedSize: 285,
      coinbaseTxDetected: true,
    });
  },

  downloadBlock(request: BlockDownloadRequest): Promise<BlockDownloadResult> {
    const filename = request.outputPath?.trim() || `downloads/blk-${request.hash.slice(0, 8)}-${request.hash.slice(-6)}.dat`;
    return delay({
      hash: request.hash,
      outputPath: filename,
      rawBytes: 285,
    });
  },
  getSuggestedBlockDownloadPath(hash: string): Promise<string> {
    return delay(`downloads/blk-${hash.slice(0, 8)}-${hash.slice(-6)}.dat`);
  },

  getRecentEvents(): Promise<UiLogEvent[]> {
    return delay(events);
  },
};
