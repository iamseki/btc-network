import type { BtcAppClient } from "./client";
import { countNodesByAsn, getCrawlRun, listCrawlRuns } from "./analytics-http";
import type {
  AddrResult,
  AsnNodeCountItem,
  BlockDownloadRequest,
  BlockDownloadResult,
  BlockSummary,
  ConnectionRequest,
  CrawlRunDetail,
  CrawlRunListItem,
  HandshakeResult,
  LastBlockHeightProgress,
  LastBlockHeightResult,
  PingResult,
  UiLogEvent,
} from "./types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

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
    message: isDemoModeEnabled()
      ? "Web client is running in demo mode with deterministic mock data."
      : "Web client is running in browser mode. Peer tools use deterministic mock data until browser-safe backends are wired.",
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

const DEMO_RUNS: CrawlRunListItem[] = [
  {
    runId: "crawl-demo-2026-03-31-1800",
    phase: "completed",
    startedAt: "2026-03-31T18:00:00Z",
    lastCheckpointedAt: "2026-03-31T18:22:00Z",
    stopReason: "idle timeout",
    failureReason: null,
    scheduledTasks: 180,
    successfulHandshakes: 74,
    failedTasks: 106,
    uniqueNodes: 241,
    persistedObservationRows: 180,
    successPct: 41.11,
    scheduledPct: 74.69,
    unscheduledGap: 61,
  },
  {
    runId: "crawl-demo-2026-03-30-1200",
    phase: "completed",
    startedAt: "2026-03-30T12:00:00Z",
    lastCheckpointedAt: "2026-03-30T12:18:00Z",
    stopReason: "frontier drained",
    failureReason: null,
    scheduledTasks: 152,
    successfulHandshakes: 58,
    failedTasks: 94,
    uniqueNodes: 204,
    persistedObservationRows: 152,
    successPct: 38.16,
    scheduledPct: 74.51,
    unscheduledGap: 52,
  },
  {
    runId: "crawl-demo-2026-03-29-0915",
    phase: "failed",
    startedAt: "2026-03-29T09:15:00Z",
    lastCheckpointedAt: "2026-03-29T09:41:00Z",
    stopReason: null,
    failureReason: "shutdown grace period elapsed",
    scheduledTasks: 96,
    successfulHandshakes: 21,
    failedTasks: 75,
    uniqueNodes: 173,
    persistedObservationRows: 96,
    successPct: 21.88,
    scheduledPct: 55.49,
    unscheduledGap: 77,
  },
];

const DEMO_RUN_DETAILS: Record<string, CrawlRunDetail> = {
  "crawl-demo-2026-03-31-1800": {
    run: DEMO_RUNS[0]!,
    checkpoints: [
      {
        phase: "bootstrapping",
        checkpointedAt: "2026-03-31T18:06:00Z",
        checkpointSequence: 1,
        stopReason: null,
        failureReason: null,
        frontierSize: 182,
        inFlightWork: 24,
        scheduledTasks: 48,
        successfulHandshakes: 19,
        failedTasks: 29,
        uniqueNodes: 122,
        persistedObservationRows: 48,
        writerBacklog: 3,
      },
      {
        phase: "steady_state",
        checkpointedAt: "2026-03-31T18:14:00Z",
        checkpointSequence: 2,
        stopReason: null,
        failureReason: null,
        frontierSize: 98,
        inFlightWork: 11,
        scheduledTasks: 129,
        successfulHandshakes: 53,
        failedTasks: 76,
        uniqueNodes: 214,
        persistedObservationRows: 129,
        writerBacklog: 1,
      },
      {
        phase: "completed",
        checkpointedAt: "2026-03-31T18:22:00Z",
        checkpointSequence: 3,
        stopReason: "idle timeout",
        failureReason: null,
        frontierSize: 61,
        inFlightWork: 0,
        scheduledTasks: 180,
        successfulHandshakes: 74,
        failedTasks: 106,
        uniqueNodes: 241,
        persistedObservationRows: 180,
        writerBacklog: 0,
      },
    ],
    failureCounts: [
      { classification: "connect", observations: 47 },
      { classification: "handshake", observations: 29 },
      { classification: "timeout", observations: 18 },
      { classification: "peer-discovery", observations: 12 },
    ],
    networkOutcomes: [
      {
        networkType: "ipv4",
        observations: 132,
        verifiedNodes: 58,
        failedNodes: 74,
        verifiedPct: 43.94,
      },
      {
        networkType: "ipv6",
        observations: 28,
        verifiedNodes: 10,
        failedNodes: 18,
        verifiedPct: 35.71,
      },
      {
        networkType: "torv3",
        observations: 14,
        verifiedNodes: 5,
        failedNodes: 9,
        verifiedPct: 35.71,
      },
      {
        networkType: "cjdns",
        observations: 6,
        verifiedNodes: 1,
        failedNodes: 5,
        verifiedPct: 16.67,
      },
    ],
  },
  "crawl-demo-2026-03-30-1200": {
    run: DEMO_RUNS[1]!,
    checkpoints: [
      {
        phase: "bootstrapping",
        checkpointedAt: "2026-03-30T12:05:00Z",
        checkpointSequence: 1,
        stopReason: null,
        failureReason: null,
        frontierSize: 151,
        inFlightWork: 17,
        scheduledTasks: 45,
        successfulHandshakes: 18,
        failedTasks: 27,
        uniqueNodes: 108,
        persistedObservationRows: 45,
        writerBacklog: 4,
      },
      {
        phase: "steady_state",
        checkpointedAt: "2026-03-30T12:11:00Z",
        checkpointSequence: 2,
        stopReason: null,
        failureReason: null,
        frontierSize: 88,
        inFlightWork: 8,
        scheduledTasks: 103,
        successfulHandshakes: 40,
        failedTasks: 63,
        uniqueNodes: 176,
        persistedObservationRows: 103,
        writerBacklog: 2,
      },
      {
        phase: "completed",
        checkpointedAt: "2026-03-30T12:18:00Z",
        checkpointSequence: 3,
        stopReason: "frontier drained",
        failureReason: null,
        frontierSize: 52,
        inFlightWork: 0,
        scheduledTasks: 152,
        successfulHandshakes: 58,
        failedTasks: 94,
        uniqueNodes: 204,
        persistedObservationRows: 152,
        writerBacklog: 0,
      },
    ],
    failureCounts: [
      { classification: "connect", observations: 36 },
      { classification: "handshake", observations: 24 },
      { classification: "timeout", observations: 22 },
      { classification: "protocol", observations: 12 },
    ],
    networkOutcomes: [
      {
        networkType: "ipv4",
        observations: 111,
        verifiedNodes: 45,
        failedNodes: 66,
        verifiedPct: 40.54,
      },
      {
        networkType: "ipv6",
        observations: 25,
        verifiedNodes: 8,
        failedNodes: 17,
        verifiedPct: 32.0,
      },
      {
        networkType: "torv3",
        observations: 12,
        verifiedNodes: 4,
        failedNodes: 8,
        verifiedPct: 33.33,
      },
      {
        networkType: "i2p",
        observations: 4,
        verifiedNodes: 1,
        failedNodes: 3,
        verifiedPct: 25.0,
      },
    ],
  },
  "crawl-demo-2026-03-29-0915": {
    run: DEMO_RUNS[2]!,
    checkpoints: [
      {
        phase: "bootstrapping",
        checkpointedAt: "2026-03-29T09:22:00Z",
        checkpointSequence: 1,
        stopReason: null,
        failureReason: null,
        frontierSize: 139,
        inFlightWork: 19,
        scheduledTasks: 33,
        successfulHandshakes: 10,
        failedTasks: 23,
        uniqueNodes: 96,
        persistedObservationRows: 33,
        writerBacklog: 6,
      },
      {
        phase: "steady_state",
        checkpointedAt: "2026-03-29T09:33:00Z",
        checkpointSequence: 2,
        stopReason: null,
        failureReason: null,
        frontierSize: 109,
        inFlightWork: 13,
        scheduledTasks: 77,
        successfulHandshakes: 18,
        failedTasks: 59,
        uniqueNodes: 151,
        persistedObservationRows: 77,
        writerBacklog: 5,
      },
      {
        phase: "failed",
        checkpointedAt: "2026-03-29T09:41:00Z",
        checkpointSequence: 3,
        stopReason: null,
        failureReason: "shutdown grace period elapsed",
        frontierSize: 77,
        inFlightWork: 0,
        scheduledTasks: 96,
        successfulHandshakes: 21,
        failedTasks: 75,
        uniqueNodes: 173,
        persistedObservationRows: 96,
        writerBacklog: 0,
      },
    ],
    failureCounts: [
      { classification: "connect", observations: 31 },
      { classification: "timeout", observations: 20 },
      { classification: "handshake", observations: 16 },
      { classification: "dns", observations: 8 },
    ],
    networkOutcomes: [
      {
        networkType: "ipv4",
        observations: 65,
        verifiedNodes: 16,
        failedNodes: 49,
        verifiedPct: 24.62,
      },
      {
        networkType: "ipv6",
        observations: 19,
        verifiedNodes: 3,
        failedNodes: 16,
        verifiedPct: 15.79,
      },
      {
        networkType: "torv3",
        observations: 8,
        verifiedNodes: 2,
        failedNodes: 6,
        verifiedPct: 25.0,
      },
      {
        networkType: "cjdns",
        observations: 4,
        verifiedNodes: 0,
        failedNodes: 4,
        verifiedPct: 0,
      },
    ],
  },
};

const DEMO_ASN_ROWS: AsnNodeCountItem[] = [
  { asn: 7922, asnOrganization: "Comcast Cable Communications, LLC", verifiedNodes: 12 },
  { asn: 16509, asnOrganization: "Amazon.com, Inc.", verifiedNodes: 10 },
  { asn: 24940, asnOrganization: "Hetzner Online GmbH", verifiedNodes: 9 },
  { asn: 14061, asnOrganization: "DigitalOcean, LLC", verifiedNodes: 8 },
  { asn: 63949, asnOrganization: "Linode, LLC", verifiedNodes: 7 },
  { asn: 8075, asnOrganization: "Microsoft Corporation", verifiedNodes: 6 },
  { asn: 13335, asnOrganization: "Cloudflare, Inc.", verifiedNodes: 5 },
  { asn: 3320, asnOrganization: "Deutsche Telekom AG", verifiedNodes: 5 },
  { asn: 12876, asnOrganization: "scaleup technologies GmbH & Co. KG", verifiedNodes: 4 },
  { asn: 9009, asnOrganization: "M247 Europe SRL", verifiedNodes: 4 },
];

function cloneRun(run: CrawlRunListItem): CrawlRunListItem {
  return { ...run };
}

function cloneRunDetail(detail: CrawlRunDetail): CrawlRunDetail {
  return {
    run: cloneRun(detail.run),
    checkpoints: detail.checkpoints.map((checkpoint) => ({ ...checkpoint })),
    failureCounts: detail.failureCounts.map((entry) => ({ ...entry })),
    networkOutcomes: detail.networkOutcomes.map((entry) => ({ ...entry })),
  };
}

async function listDemoRuns(limit = 10): Promise<CrawlRunListItem[]> {
  const result = DEMO_RUNS.slice(0, limit).map(cloneRun);
  pushEvent("info", `Demo mode served ${result.length} crawler run summaries from the embedded dataset.`);
  return delay(result);
}

async function getDemoRunDetail(runId: string): Promise<CrawlRunDetail> {
  const detail = DEMO_RUN_DETAILS[runId];

  if (!detail) {
    throw new Error(`No demo crawl run exists for ${runId}`);
  }

  pushEvent("info", `Demo mode loaded crawler run detail for ${runId}.`);
  return delay(cloneRunDetail(detail));
}

async function countDemoNodesByAsn(limit = 10): Promise<AsnNodeCountItem[]> {
  const result = DEMO_ASN_ROWS.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} ASN rows from the embedded dataset.`);
  return delay(result);
}

export const webClient: BtcAppClient = {
  listCrawlRuns(limit) {
    if (isDemoModeEnabled()) {
      return listDemoRuns(limit);
    }

    return listCrawlRuns(limit);
  },
  getCrawlRun(runId) {
    if (isDemoModeEnabled()) {
      return getDemoRunDetail(runId);
    }

    return getCrawlRun(runId);
  },
  countNodesByAsn(limit) {
    if (isDemoModeEnabled()) {
      return countDemoNodesByAsn(limit);
    }

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
