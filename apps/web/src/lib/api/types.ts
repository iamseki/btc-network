export type ConnectionRequest = {
  node: string;
};

export type HandshakeResult = {
  node: string;
  protocolVersion: number;
  services: string;
  serviceNames: string[];
  userAgent: string;
  startHeight: number;
  relay: boolean | null;
};

export type PingResult = {
  node: string;
  nonce: string;
  echoedNonce: string;
};

export type PeerAddress = {
  address: string;
  port: number;
  network: "ipv4" | "ipv6" | "torv2" | "torv3" | "i2p" | "cjdns" | "unknown";
};

export type AddrResult = {
  node: string;
  addresses: PeerAddress[];
};

export type LastBlockHeightResult = {
  node?: string;
  height: number;
  rounds: number;
  elapsedMs: number;
  bestBlockHash: string | null;
};

export type LastBlockHeightProgressPhase =
  | "connecting"
  | "handshaking"
  | "requesting_headers"
  | "completed";

export type LastBlockHeightProgress = {
  operationId: string;
  node: string;
  phase: LastBlockHeightProgressPhase;
  roundsCompleted: number;
  headersSeen: number;
  lastBatchCount: number;
  bestBlockHash: string | null;
  elapsedMs: number;
};

export type BlockSummary = {
  hash: string;
  txCount: number;
  serializedSize: number;
  coinbaseTxDetected: boolean;
};

export type BlockDownloadResult = {
  hash: string;
  outputPath: string;
  rawBytes: number;
};

export type BlockDownloadRequest = {
  node: string;
  hash: string;
  outputPath?: string;
};

export type UiLogEvent = {
  at: string;
  level: "info" | "warn" | "error";
  message: string;
};

export type CrawlRunListItem = {
  runId: string;
  phase: string;
  startedAt: string;
  lastCheckpointedAt: string;
  stopReason: string | null;
  failureReason: string | null;
  scheduledTasks: number;
  successfulHandshakes: number;
  failedTasks: number;
  uniqueNodes: number;
  persistedObservationRows: number;
  successPct: number;
  scheduledPct: number;
  unscheduledGap: number;
};

export type CrawlRunCheckpointItem = {
  phase: string;
  checkpointedAt: string;
  checkpointSequence: number;
  stopReason: string | null;
  failureReason: string | null;
  frontierSize: number;
  inFlightWork: number;
  scheduledTasks: number;
  successfulHandshakes: number;
  failedTasks: number;
  uniqueNodes: number;
  persistedObservationRows: number;
  writerBacklog: number;
};

export type FailureClassificationCount = {
  classification: string;
  observations: number;
};

export type NetworkOutcomeCount = {
  networkType: string;
  observations: number;
  verifiedNodes: number;
  failedNodes: number;
  verifiedPct: number;
};

export type AsnNodeCountItem = {
  asn: number | null;
  asnOrganization: string | null;
  verifiedNodes: number;
};

export type CrawlRunDetail = {
  run: CrawlRunListItem;
  checkpoints: CrawlRunCheckpointItem[];
  failureCounts: FailureClassificationCount[];
  networkOutcomes: NetworkOutcomeCount[];
};
