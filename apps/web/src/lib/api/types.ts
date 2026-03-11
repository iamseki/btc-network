export type ConnectionRequest = {
  node: string;
};

export type HandshakeResult = {
  node: string;
  protocolVersion: number;
  services: string;
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

export type HeaderFetchResult = {
  count: number;
  lastHeaderHash: string | null;
};

export type HeaderSyncResult = {
  totalHeaders: number;
  rounds: number;
  elapsedMs: number;
  mostRecentBlock: string | null;
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

export type UiLogEvent = {
  at: string;
  level: "info" | "warn" | "error";
  message: string;
};
