import type { BtcAppClient } from "./client";
import {
  countNodesByAsn,
  getCrawlRun,
  listCrawlRuns,
  listLastRunAsnOrganizations,
  listLastRunAsns,
  listLastRunCountries,
  listLastRunNetworkTypes,
  listLastRunNodes,
  listLastRunProtocolVersions,
  listLastRunServices,
  listLastRunStartHeights,
  listLastRunUserAgents,
} from "./analytics-http";
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
  LastRunAsnCountItem,
  LastRunAsnOrganizationCountItem,
  LastRunCountryCountItem,
  LastRunNetworkTypeCountItem,
  LastRunNodeSummaryItem,
  LastRunProtocolVersionCountItem,
  LastRunServicesCountItem,
  LastRunStartHeightCountItem,
  LastRunUserAgentCountItem,
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
    lastCheckpointedAt: "2026-03-31T18:04:58Z",
    stopReason: "idle timeout",
    failureReason: null,
    scheduledTasks: 23642,
    successfulHandshakes: 9847,
    failedTasks: 13795,
    uniqueNodes: 24816,
    persistedObservationRows: 23642,
    successPct: 41.65,
    scheduledPct: 95.27,
    unscheduledGap: 1174,
  },
  {
    runId: "crawl-demo-2026-03-30-1200",
    phase: "completed",
    startedAt: "2026-03-30T12:00:00Z",
    lastCheckpointedAt: "2026-03-30T12:04:57Z",
    stopReason: "frontier drained",
    failureReason: null,
    scheduledTasks: 20891,
    successfulHandshakes: 8614,
    failedTasks: 12277,
    uniqueNodes: 22108,
    persistedObservationRows: 20891,
    successPct: 41.23,
    scheduledPct: 94.49,
    unscheduledGap: 1217,
  },
  {
    runId: "crawl-demo-2026-03-29-0915",
    phase: "failed",
    startedAt: "2026-03-29T09:15:00Z",
    lastCheckpointedAt: "2026-03-29T09:19:56Z",
    stopReason: null,
    failureReason: "shutdown grace period elapsed",
    scheduledTasks: 16190,
    successfulHandshakes: 5342,
    failedTasks: 10848,
    uniqueNodes: 19462,
    persistedObservationRows: 16190,
    successPct: 32.99,
    scheduledPct: 83.19,
    unscheduledGap: 3272,
  },
];

const DEMO_RUN_DETAILS: Record<string, CrawlRunDetail> = {
  "crawl-demo-2026-03-31-1800": {
    run: DEMO_RUNS[0]!,
    checkpoints: [
      {
        phase: "bootstrapping",
        checkpointedAt: "2026-03-31T18:01:28Z",
        checkpointSequence: 1,
        stopReason: null,
        failureReason: null,
        frontierSize: 17576,
        inFlightWork: 812,
        scheduledTasks: 6482,
        successfulHandshakes: 2714,
        failedTasks: 3768,
        uniqueNodes: 11240,
        persistedObservationRows: 6482,
        writerBacklog: 94,
      },
      {
        phase: "steady_state",
        checkpointedAt: "2026-03-31T18:03:12Z",
        checkpointSequence: 2,
        stopReason: null,
        failureReason: null,
        frontierSize: 6330,
        inFlightWork: 286,
        scheduledTasks: 17308,
        successfulHandshakes: 7261,
        failedTasks: 10047,
        uniqueNodes: 21264,
        persistedObservationRows: 17308,
        writerBacklog: 33,
      },
      {
        phase: "completed",
        checkpointedAt: "2026-03-31T18:04:58Z",
        checkpointSequence: 3,
        stopReason: "idle timeout",
        failureReason: null,
        frontierSize: 1174,
        inFlightWork: 0,
        scheduledTasks: 23642,
        successfulHandshakes: 9847,
        failedTasks: 13795,
        uniqueNodes: 24816,
        persistedObservationRows: 23642,
        writerBacklog: 0,
      },
    ],
    failureCounts: [
      { classification: "connect", observations: 5230 },
      { classification: "handshake", observations: 3411 },
      { classification: "timeout", observations: 2847 },
      { classification: "peer-discovery", observations: 1628 },
      { classification: "protocol", observations: 679 },
    ],
    networkOutcomes: [
      {
        networkType: "ipv4",
        observations: 18420,
        verifiedNodes: 7821,
        failedNodes: 10599,
        verifiedPct: 42.46,
      },
      {
        networkType: "ipv6",
        observations: 3128,
        verifiedNodes: 1215,
        failedNodes: 1913,
        verifiedPct: 38.84,
      },
      {
        networkType: "torv3",
        observations: 1784,
        verifiedNodes: 694,
        failedNodes: 1090,
        verifiedPct: 38.9,
      },
      {
        networkType: "i2p",
        observations: 206,
        verifiedNodes: 73,
        failedNodes: 133,
        verifiedPct: 35.44,
      },
      {
        networkType: "cjdns",
        observations: 104,
        verifiedNodes: 44,
        failedNodes: 60,
        verifiedPct: 42.31,
      },
    ],
  },
  "crawl-demo-2026-03-30-1200": {
    run: DEMO_RUNS[1]!,
    checkpoints: [
      {
        phase: "bootstrapping",
        checkpointedAt: "2026-03-30T12:01:33Z",
        checkpointSequence: 1,
        stopReason: null,
        failureReason: null,
        frontierSize: 16186,
        inFlightWork: 754,
        scheduledTasks: 5922,
        successfulHandshakes: 2468,
        failedTasks: 3454,
        uniqueNodes: 10124,
        persistedObservationRows: 5922,
        writerBacklog: 86,
      },
      {
        phase: "steady_state",
        checkpointedAt: "2026-03-30T12:03:20Z",
        checkpointSequence: 2,
        stopReason: null,
        failureReason: null,
        frontierSize: 7000,
        inFlightWork: 244,
        scheduledTasks: 15108,
        successfulHandshakes: 6229,
        failedTasks: 8879,
        uniqueNodes: 19182,
        persistedObservationRows: 15108,
        writerBacklog: 29,
      },
      {
        phase: "completed",
        checkpointedAt: "2026-03-30T12:04:57Z",
        checkpointSequence: 3,
        stopReason: "frontier drained",
        failureReason: null,
        frontierSize: 1217,
        inFlightWork: 0,
        scheduledTasks: 20891,
        successfulHandshakes: 8614,
        failedTasks: 12277,
        uniqueNodes: 22108,
        persistedObservationRows: 20891,
        writerBacklog: 0,
      },
    ],
    failureCounts: [
      { classification: "connect", observations: 4495 },
      { classification: "handshake", observations: 3062 },
      { classification: "timeout", observations: 2448 },
      { classification: "peer-discovery", observations: 1352 },
      { classification: "protocol", observations: 920 },
    ],
    networkOutcomes: [
      {
        networkType: "ipv4",
        observations: 16422,
        verifiedNodes: 6880,
        failedNodes: 9542,
        verifiedPct: 41.89,
      },
      {
        networkType: "ipv6",
        observations: 2750,
        verifiedNodes: 1079,
        failedNodes: 1671,
        verifiedPct: 39.24,
      },
      {
        networkType: "torv3",
        observations: 1450,
        verifiedNodes: 566,
        failedNodes: 884,
        verifiedPct: 39.03,
      },
      {
        networkType: "i2p",
        observations: 173,
        verifiedNodes: 64,
        failedNodes: 109,
        verifiedPct: 36.99,
      },
      {
        networkType: "cjdns",
        observations: 96,
        verifiedNodes: 25,
        failedNodes: 71,
        verifiedPct: 26.04,
      },
    ],
  },
  "crawl-demo-2026-03-29-0915": {
    run: DEMO_RUNS[2]!,
    checkpoints: [
      {
        phase: "bootstrapping",
        checkpointedAt: "2026-03-29T09:16:31Z",
        checkpointSequence: 1,
        stopReason: null,
        failureReason: null,
        frontierSize: 14582,
        inFlightWork: 691,
        scheduledTasks: 4880,
        successfulHandshakes: 1624,
        failedTasks: 3256,
        uniqueNodes: 9548,
        persistedObservationRows: 4880,
        writerBacklog: 121,
      },
      {
        phase: "steady_state",
        checkpointedAt: "2026-03-29T09:18:14Z",
        checkpointSequence: 2,
        stopReason: null,
        failureReason: null,
        frontierSize: 8418,
        inFlightWork: 378,
        scheduledTasks: 11044,
        successfulHandshakes: 3785,
        failedTasks: 7259,
        uniqueNodes: 15402,
        persistedObservationRows: 11044,
        writerBacklog: 58,
      },
      {
        phase: "failed",
        checkpointedAt: "2026-03-29T09:19:56Z",
        checkpointSequence: 3,
        stopReason: null,
        failureReason: "shutdown grace period elapsed",
        frontierSize: 3272,
        inFlightWork: 0,
        scheduledTasks: 16190,
        successfulHandshakes: 5342,
        failedTasks: 10848,
        uniqueNodes: 19462,
        persistedObservationRows: 16190,
        writerBacklog: 0,
      },
    ],
    failureCounts: [
      { classification: "connect", observations: 4024 },
      { classification: "timeout", observations: 2647 },
      { classification: "handshake", observations: 2198 },
      { classification: "peer-discovery", observations: 1289 },
      { classification: "dns", observations: 690 },
    ],
    networkOutcomes: [
      {
        networkType: "ipv4",
        observations: 11890,
        verifiedNodes: 4037,
        failedNodes: 7853,
        verifiedPct: 33.95,
      },
      {
        networkType: "ipv6",
        observations: 2338,
        verifiedNodes: 748,
        failedNodes: 1590,
        verifiedPct: 31.99,
      },
      {
        networkType: "torv3",
        observations: 1561,
        verifiedNodes: 473,
        failedNodes: 1088,
        verifiedPct: 30.3,
      },
      {
        networkType: "i2p",
        observations: 241,
        verifiedNodes: 62,
        failedNodes: 179,
        verifiedPct: 25.73,
      },
      {
        networkType: "cjdns",
        observations: 160,
        verifiedNodes: 22,
        failedNodes: 138,
        verifiedPct: 13.75,
      },
    ],
  },
};

const DEMO_ASN_ROWS: AsnNodeCountItem[] = [
  { asn: 7922, asnOrganization: "Comcast Cable Communications, LLC", verifiedNodes: 1482 },
  { asn: 16509, asnOrganization: "Amazon.com, Inc.", verifiedNodes: 1326 },
  { asn: 24940, asnOrganization: "Hetzner Online GmbH", verifiedNodes: 1194 },
  { asn: 14061, asnOrganization: "DigitalOcean, LLC", verifiedNodes: 982 },
  { asn: 63949, asnOrganization: "Linode, LLC", verifiedNodes: 904 },
  { asn: 8075, asnOrganization: "Microsoft Corporation", verifiedNodes: 866 },
  { asn: 13335, asnOrganization: "Cloudflare, Inc.", verifiedNodes: 812 },
  { asn: 3320, asnOrganization: "Deutsche Telekom AG", verifiedNodes: 774 },
  { asn: 12876, asnOrganization: "scaleup technologies GmbH & Co. KG", verifiedNodes: 688 },
  { asn: 9009, asnOrganization: "M247 Europe SRL", verifiedNodes: 624 },
];

const DEMO_LAST_RUN_SERVICES: LastRunServicesCountItem[] = [
  { services: "1", nodeCount: 3520 },
  { services: "1033", nodeCount: 2894 },
  { services: "9", nodeCount: 2142 },
  { services: "1025", nodeCount: 711 },
];

const DEMO_LAST_RUN_PROTOCOL_VERSIONS: LastRunProtocolVersionCountItem[] = [
  { protocolVersion: 70016, nodeCount: 7624 },
  { protocolVersion: 70015, nodeCount: 1488 },
  { protocolVersion: 70014, nodeCount: 526 },
  { protocolVersion: 70013, nodeCount: 209 },
];

const DEMO_LAST_RUN_USER_AGENTS: LastRunUserAgentCountItem[] = [
  { userAgent: "/Satoshi:27.0.0/", nodeCount: 2396 },
  { userAgent: "/Satoshi:26.1.0/", nodeCount: 1842 },
  { userAgent: "/Satoshi:25.1.0/", nodeCount: 1204 },
  { userAgent: "/Knots:27.1.knots20250305/", nodeCount: 746 },
  { userAgent: "/btcd:0.24.2/", nodeCount: 392 },
  { userAgent: "/libbitcoin:4.0.0/", nodeCount: 188 },
];

const DEMO_LAST_RUN_NETWORK_TYPES: LastRunNetworkTypeCountItem[] = [
  { networkType: "ipv4", nodeCount: 7821 },
  { networkType: "ipv6", nodeCount: 1215 },
  { networkType: "torv3", nodeCount: 694 },
  { networkType: "i2p", nodeCount: 73 },
  { networkType: "cjdns", nodeCount: 44 },
];

const DEMO_LAST_RUN_COUNTRIES: LastRunCountryCountItem[] = [
  { country: "US", nodeCount: 2116 },
  { country: "DE", nodeCount: 1268 },
  { country: "FR", nodeCount: 740 },
  { country: "NL", nodeCount: 688 },
  { country: "CA", nodeCount: 612 },
  { country: "GB", nodeCount: 578 },
  { country: "FI", nodeCount: 431 },
  { country: "JP", nodeCount: 412 },
  { country: "SG", nodeCount: 341 },
  { country: "AU", nodeCount: 305 },
];

const DEMO_LAST_RUN_ASNS: LastRunAsnCountItem[] = DEMO_ASN_ROWS.map((row) => ({
  asn: row.asn ?? 0,
  asnOrganization: row.asnOrganization,
  nodeCount: row.verifiedNodes,
})).filter((row) => row.asn > 0);

const DEMO_LAST_RUN_START_HEIGHTS: LastRunStartHeightCountItem[] = [
  { startHeight: 900000, nodeCount: 3288 },
  { startHeight: 899999, nodeCount: 2466 },
  { startHeight: 900001, nodeCount: 1914 },
  { startHeight: 899998, nodeCount: 1180 },
  { startHeight: 900002, nodeCount: 999 },
];

const DEMO_LAST_RUN_ASN_ORGANIZATIONS: LastRunAsnOrganizationCountItem[] = DEMO_LAST_RUN_ASNS.map(
  (row) => ({
    asnOrganization: row.asnOrganization ?? `AS${row.asn}`,
    nodeCount: row.nodeCount,
  }),
);

const DEMO_LAST_RUN_NODES: LastRunNodeSummaryItem[] = [
  {
    endpoint: "1.1.1.7:8333",
    networkType: "ipv4",
    protocolVersion: 70016,
    userAgent: "/Satoshi:27.0.0/",
    services: "1033",
    startHeight: 900000,
    country: "US",
    asn: 13335,
    asnOrganization: "Cloudflare, Inc.",
  },
  {
    endpoint: "8.8.8.8:8333",
    networkType: "ipv4",
    protocolVersion: 70016,
    userAgent: "/Satoshi:26.1.0/",
    services: "9",
    startHeight: 900001,
    country: "US",
    asn: 15169,
    asnOrganization: "Google LLC",
  },
  {
    endpoint: "45.76.12.44:8333",
    networkType: "ipv4",
    protocolVersion: 70015,
    userAgent: "/Knots:27.1.knots20250305/",
    services: "1033",
    startHeight: 899999,
    country: "DE",
    asn: 24940,
    asnOrganization: "Hetzner Online GmbH",
  },
  {
    endpoint: "[2604:a880:cad:d0::19d:5001]:8333",
    networkType: "ipv6",
    protocolVersion: 70016,
    userAgent: "/Satoshi:27.0.0/",
    services: "1",
    startHeight: 900000,
    country: "NL",
    asn: 14061,
    asnOrganization: "DigitalOcean, LLC",
  },
  {
    endpoint: "q3tqu3sxuo5x6w3y.onion:8333",
    networkType: "torv3",
    protocolVersion: 70016,
    userAgent: "/btcd:0.24.2/",
    services: "1025",
    startHeight: 899998,
    country: null,
    asn: null,
    asnOrganization: null,
  },
  {
    endpoint: "139.162.12.90:8333",
    networkType: "ipv4",
    protocolVersion: 70014,
    userAgent: "/libbitcoin:4.0.0/",
    services: "1",
    startHeight: 900002,
    country: "SG",
    asn: 63949,
    asnOrganization: "Linode, LLC",
  },
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

async function listDemoLastRunServices(limit = 100): Promise<LastRunServicesCountItem[]> {
  const result = DEMO_LAST_RUN_SERVICES.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run services buckets.`);
  return delay(result);
}

async function listDemoLastRunProtocolVersions(
  limit = 100,
): Promise<LastRunProtocolVersionCountItem[]> {
  const result = DEMO_LAST_RUN_PROTOCOL_VERSIONS.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run protocol version buckets.`);
  return delay(result);
}

async function listDemoLastRunUserAgents(limit = 100): Promise<LastRunUserAgentCountItem[]> {
  const result = DEMO_LAST_RUN_USER_AGENTS.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run user agent buckets.`);
  return delay(result);
}

async function listDemoLastRunNetworkTypes(
  limit = 100,
): Promise<LastRunNetworkTypeCountItem[]> {
  const result = DEMO_LAST_RUN_NETWORK_TYPES.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run network type buckets.`);
  return delay(result);
}

async function listDemoLastRunCountries(limit = 100): Promise<LastRunCountryCountItem[]> {
  const result = DEMO_LAST_RUN_COUNTRIES.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run country buckets.`);
  return delay(result);
}

async function listDemoLastRunAsns(limit = 100): Promise<LastRunAsnCountItem[]> {
  const result = DEMO_LAST_RUN_ASNS.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run ASN buckets.`);
  return delay(result);
}

async function listDemoLastRunStartHeights(
  limit = 100,
): Promise<LastRunStartHeightCountItem[]> {
  const result = DEMO_LAST_RUN_START_HEIGHTS.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run start-height buckets.`);
  return delay(result);
}

async function listDemoLastRunAsnOrganizations(
  limit = 100,
): Promise<LastRunAsnOrganizationCountItem[]> {
  const result = DEMO_LAST_RUN_ASN_ORGANIZATIONS.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run ASN organization buckets.`);
  return delay(result);
}

async function listDemoLastRunNodes(limit = 500): Promise<LastRunNodeSummaryItem[]> {
  const result = DEMO_LAST_RUN_NODES.slice(0, limit).map((row) => ({ ...row }));
  pushEvent("info", `Demo mode served ${result.length} last-run node rows.`);
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
  listLastRunServices(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunServices(limit);
    }

    return listLastRunServices(limit);
  },
  listLastRunProtocolVersions(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunProtocolVersions(limit);
    }

    return listLastRunProtocolVersions(limit);
  },
  listLastRunUserAgents(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunUserAgents(limit);
    }

    return listLastRunUserAgents(limit);
  },
  listLastRunNetworkTypes(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunNetworkTypes(limit);
    }

    return listLastRunNetworkTypes(limit);
  },
  listLastRunCountries(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunCountries(limit);
    }

    return listLastRunCountries(limit);
  },
  listLastRunAsns(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunAsns(limit);
    }

    return listLastRunAsns(limit);
  },
  listLastRunStartHeights(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunStartHeights(limit);
    }

    return listLastRunStartHeights(limit);
  },
  listLastRunAsnOrganizations(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunAsnOrganizations(limit);
    }

    return listLastRunAsnOrganizations(limit);
  },
  listLastRunNodes(limit) {
    if (isDemoModeEnabled()) {
      return listDemoLastRunNodes(limit);
    }

    return listLastRunNodes(limit);
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
