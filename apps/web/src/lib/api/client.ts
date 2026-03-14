import type {
  AddrResult,
  BlockDownloadResult,
  BlockSummary,
  ConnectionRequest,
  HandshakeResult,
  HeaderFetchResult,
  LastBlockHeightResult,
  PingResult,
  UiLogEvent,
} from "./types";

export interface BtcAppClient {
  handshake(request: ConnectionRequest): Promise<HandshakeResult>;
  ping(node: string): Promise<PingResult>;
  getAddr(node: string): Promise<AddrResult>;
  getHeaders(node: string): Promise<HeaderFetchResult>;
  getLastBlockHeight(node: string): Promise<LastBlockHeightResult>;
  getBlock(node: string, hash: string): Promise<BlockSummary>;
  downloadBlock(node: string, hash: string): Promise<BlockDownloadResult>;
  getRecentEvents(): Promise<UiLogEvent[]>;
}
