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
  LastRunAsnCountItem,
  LastRunAsnOrganizationCountItem,
  LastBlockHeightProgress,
  LastBlockHeightResult,
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

export type LastBlockHeightProgressListener = (progress: LastBlockHeightProgress) => void;

export interface BtcAppClient {
  listCrawlRuns(limit?: number): Promise<CrawlRunListItem[]>;
  getCrawlRun(runId: string): Promise<CrawlRunDetail>;
  countNodesByAsn(limit?: number): Promise<AsnNodeCountItem[]>;
  listLastRunServices(limit?: number): Promise<LastRunServicesCountItem[]>;
  listLastRunProtocolVersions(limit?: number): Promise<LastRunProtocolVersionCountItem[]>;
  listLastRunUserAgents(limit?: number): Promise<LastRunUserAgentCountItem[]>;
  listLastRunNetworkTypes(limit?: number): Promise<LastRunNetworkTypeCountItem[]>;
  listLastRunCountries(limit?: number): Promise<LastRunCountryCountItem[]>;
  listLastRunAsns(limit?: number): Promise<LastRunAsnCountItem[]>;
  listLastRunStartHeights(limit?: number): Promise<LastRunStartHeightCountItem[]>;
  listLastRunAsnOrganizations(limit?: number): Promise<LastRunAsnOrganizationCountItem[]>;
  listLastRunNodes(limit?: number): Promise<LastRunNodeSummaryItem[]>;
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
