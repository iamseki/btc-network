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

  getLastBlockHeight(_node: string): Promise<LastBlockHeightResult> {
    return delay({
      height: 938408,
      rounds: 470,
      elapsedMs: 545450,
      bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
    });
  },

  getBlock(_node: string, hash: string): Promise<BlockSummary> {
    return delay({
      hash,
      txCount: 1,
      serializedSize: 285,
      coinbaseTxDetected: true,
    });
  },

  downloadBlock(_node: string, hash: string): Promise<BlockDownloadResult> {
    return delay({
      hash,
      outputPath: `blk-${hash.slice(0, 8)}-${hash.slice(-6)}.dat`,
      rawBytes: 285,
    });
  },

  getRecentEvents(): Promise<UiLogEvent[]> {
    return delay(events);
  },
};
