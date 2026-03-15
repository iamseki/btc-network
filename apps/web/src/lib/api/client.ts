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

export type LastBlockHeightProgressListener = (progress: LastBlockHeightProgress) => void;

export interface BtcAppClient {
  handshake(request: ConnectionRequest): Promise<HandshakeResult>;
  ping(node: string): Promise<PingResult>;
  getAddr(node: string): Promise<AddrResult>;
  getLastBlockHeight(
    node: string,
    onProgress?: LastBlockHeightProgressListener,
  ): Promise<LastBlockHeightResult>;
  getBlock(node: string, hash: string): Promise<BlockSummary>;
  downloadBlock(request: BlockDownloadRequest): Promise<BlockDownloadResult>;
  getSuggestedBlockDownloadPath(hash: string): Promise<string>;
  getRecentEvents(): Promise<UiLogEvent[]>;
}
