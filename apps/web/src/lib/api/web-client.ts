import type { BtcAppClient } from "./client";
import { countNodesByAsn, getCrawlRun, listCrawlRuns } from "./analytics-http";
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

function delay<T>(value: T, ms = 120): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => resolve(value), ms);
  });
}

const INITIAL_EVENTS: UiLogEvent[] = [
  {
    at: nowIso(),
    level: "info",
    message: "Web client is running in placeholder mode until the desktop and HTTP adapters are wired.",
  },
];

const events: UiLogEvent[] = [...INITIAL_EVENTS];

const SAMPLE_HASHES = [
  "00000000000000000000d39ec0b0f62d60f4f0fb2b7a2f3a0f5d7d6c53b1cb62",
  "00000000000000000001ac49584dbb6f5a6d3c8f0d2d3ed7e43a18fc8a9b7f12",
  "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
  "0000000000000000000215f4a2d5cb5b7f36ab6c2cd93f45f9df4a57a9cbe0ab",
] as const;

function pushEvent(level: UiLogEvent["level"], message: string) {
  events.unshift({
    at: nowIso(),
    level,
    message,
  });
}

function seedFromText(value: string): number {
  let hash = 2166136261;

  for (const ch of value) {
    hash ^= ch.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }

  return hash >>> 0;
}

function nonceFromSeed(seed: number): string {
  const upper = (seed ^ 0x9e3779b9).toString(16).padStart(8, "0");
  const lower = Math.imul(seed, 2654435761).toString(16).slice(-8).padStart(8, "0");
  return `0x${upper}${lower}`;
}

function blockHeightFromSeed(seed: number): number {
  return 880000 + (seed % 80000);
}

function bestHashFromSeed(seed: number): string {
  return SAMPLE_HASHES[seed % SAMPLE_HASHES.length]!;
}

function serviceSummaryFromSeed(seed: number): Pick<HandshakeResult, "services" | "serviceNames" | "relay"> {
  const profiles = [
    {
      services: "0x0000000000000409",
      serviceNames: ["NODE_NETWORK", "NODE_WITNESS", "NODE_NETWORK_LIMITED"],
      relay: true,
    },
    {
      services: "0x0000000000000009",
      serviceNames: ["NODE_NETWORK", "NODE_WITNESS"],
      relay: true,
    },
    {
      services: "0x0000000000000401",
      serviceNames: ["NODE_NETWORK", "NODE_NETWORK_LIMITED"],
      relay: false,
    },
  ] as const;

  const profile = profiles[seed % profiles.length]!;
  return {
    services: profile.services,
    serviceNames: [...profile.serviceNames],
    relay: profile.relay,
  };
}

function sanitizeOutputPath(path: string | undefined, hash: string): string {
  const trimmed = path?.trim();

  if (trimmed) {
    return trimmed;
  }

  return `downloads/blk-${hash.slice(0, 8)}-${hash.slice(-6)}.dat`;
}

function makePeerAddresses(node: string): AddrResult["addresses"] {
  const seed = seedFromText(node);
  const octet2 = ((seed >> 8) % 253) + 1;
  const octet3 = ((seed >> 16) % 253) + 1;
  const octet4 = ((seed >> 24) % 253) + 1;
  const ipv6Suffix = (seed & 0xffff).toString(16);

  return [
    { address: `34.${octet2}.${octet3}.${octet4}`, port: 8333, network: "ipv4" },
    { address: `2001:db8::${ipv6Suffix}`, port: 8333, network: "ipv6" },
    { address: "v26qxw6b6h3v6x2n.onion", port: 8333, network: "torv3" },
  ];
}

function makeBlockSummary(hash: string): BlockSummary {
  const seed = seedFromText(hash);

  return {
    hash,
    txCount: 1 + (seed % 2800),
    serializedSize: 285 + (seed % 1_750_000),
    coinbaseTxDetected: true,
  };
}

export const webClient: BtcAppClient = {
  listCrawlRuns(limit) {
    return listCrawlRuns(limit);
  },
  getCrawlRun(runId) {
    return getCrawlRun(runId);
  },
  countNodesByAsn(limit) {
    return countNodesByAsn(limit);
  },
  async handshake(request: ConnectionRequest): Promise<HandshakeResult> {
    const seed = seedFromText(request.node);
    const services = serviceSummaryFromSeed(seed);
    const result = await delay({
      node: request.node,
      protocolVersion: 70016,
      services: services.services,
      serviceNames: [...services.serviceNames],
      userAgent: `/btc-network:web-mock-${(seed % 5) + 1}.0.0/`,
      startHeight: blockHeightFromSeed(seed),
      relay: services.relay,
    });

    pushEvent(
      "info",
      `Mock handshake completed for ${request.node} with ${result.serviceNames.join(", ")}.`,
    );
    return result;
  },

  async ping(node: string): Promise<PingResult> {
    const result = await delay({
      node,
      nonce: nonceFromSeed(seedFromText(`ping:${node}`)),
      echoedNonce: nonceFromSeed(seedFromText(`ping:${node}`)),
    });

    pushEvent("info", `Mock ping round-trip completed for ${node}.`);
    return result;
  },

  async getAddr(node: string): Promise<AddrResult> {
    const result = await delay({
      node,
      addresses: makePeerAddresses(node),
    });

    pushEvent("info", `Mock peer address lookup returned ${result.addresses.length} entries for ${node}.`);
    return result;
  },

  async getLastBlockHeight(
    node: string,
    onProgress?: (progress: LastBlockHeightProgress) => void,
  ): Promise<LastBlockHeightResult> {
    const seed = seedFromText(node);
    const operationId = `web-mock-chain-height-${seed.toString(16)}`;
    const height = blockHeightFromSeed(seed);
    const rounds = 440 + (seed % 40);
    const bestBlockHash = bestHashFromSeed(seed);
    const totalElapsedMs = 480_000 + (seed % 180_000);

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

    await delay(null, 80);

    onProgress?.({
      operationId,
      node,
      phase: "handshaking",
      roundsCompleted: 0,
      headersSeen: 0,
      lastBatchCount: 0,
      bestBlockHash: null,
      elapsedMs: 90,
    });

    await delay(null, 80);

    onProgress?.({
      operationId,
      node,
      phase: "requesting_headers",
      roundsCompleted: rounds,
      headersSeen: height,
      lastBatchCount: Math.max(1, height % 2000),
      bestBlockHash,
      elapsedMs: totalElapsedMs - 200,
    });

    await delay(null, 80);

    onProgress?.({
      operationId,
      node,
      phase: "completed",
      roundsCompleted: rounds,
      headersSeen: height,
      lastBatchCount: Math.max(1, height % 2000),
      bestBlockHash,
      elapsedMs: totalElapsedMs,
    });

    const result = {
      node,
      height,
      rounds,
      elapsedMs: totalElapsedMs,
      bestBlockHash,
    };

    pushEvent("info", `Mock chain height lookup completed for ${node} at height ${height}.`);
    return result;
  },

  async getBlock(node: string, hash: string): Promise<BlockSummary> {
    const result = await delay(makeBlockSummary(hash));
    pushEvent("info", `Mock block summary loaded for ${hash} from ${node}.`);
    return result;
  },

  async downloadBlock(request: BlockDownloadRequest): Promise<BlockDownloadResult> {
    const summary = makeBlockSummary(request.hash);
    const result = await delay({
      hash: request.hash,
      outputPath: sanitizeOutputPath(request.outputPath, request.hash),
      rawBytes: summary.serializedSize,
    });

    pushEvent("info", `Mock block download prepared for ${request.hash} at ${result.outputPath}.`);
    return result;
  },

  getSuggestedBlockDownloadPath(hash: string): Promise<string> {
    const result = sanitizeOutputPath(undefined, hash);
    return delay(result);
  },

  getRecentEvents(): Promise<UiLogEvent[]> {
    return delay([...events]);
  },
};
