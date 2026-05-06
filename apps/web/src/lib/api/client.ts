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
  HistoricalWindow,
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
  NodeStatusItem,
  PageResponse,
  PingResult,
  UiLogEvent,
} from "./types";

export type LastBlockHeightProgressListener = (progress: LastBlockHeightProgress) => void;
export type CrawlRunPhaseFilter = "any" | "bootstrap" | "crawling" | "draining" | "finished";
export type CrawlRunPhaseFilterOptions = {
  phase?: CrawlRunPhaseFilter | CrawlRunPhaseFilter[];
};

export interface BtcAppClient {
  listCrawlRuns(limit?: number): Promise<CrawlRunListItem[]>;
  getCrawlRun(runId: string): Promise<CrawlRunDetail>;
  countNodesByAsn(limit?: number, window?: HistoricalWindow): Promise<AsnNodeCountItem[]>;
  listLastRunServices(limit?: number, options?: CrawlRunPhaseFilterOptions): Promise<LastRunServicesCountItem[]>;
  listLastRunProtocolVersions(
    limit?: number,
    options?: CrawlRunPhaseFilterOptions,
  ): Promise<LastRunProtocolVersionCountItem[]>;
  listLastRunUserAgents(limit?: number, options?: CrawlRunPhaseFilterOptions): Promise<LastRunUserAgentCountItem[]>;
  listLastRunNetworkTypes(
    limit?: number,
    options?: CrawlRunPhaseFilterOptions,
  ): Promise<LastRunNetworkTypeCountItem[]>;
  listLastRunCountries(limit?: number, options?: CrawlRunPhaseFilterOptions): Promise<LastRunCountryCountItem[]>;
  listLastRunAsns(limit?: number, options?: CrawlRunPhaseFilterOptions): Promise<LastRunAsnCountItem[]>;
  listLastRunStartHeights(limit?: number, options?: CrawlRunPhaseFilterOptions): Promise<LastRunStartHeightCountItem[]>;
  listLastRunAsnOrganizations(
    limit?: number,
    options?: CrawlRunPhaseFilterOptions,
  ): Promise<LastRunAsnOrganizationCountItem[]>;
  listLastRunNodes(limit?: number, pageToken?: string): Promise<PageResponse<LastRunNodeSummaryItem>>;
  listNodeStatus(): Promise<NodeStatusItem[]>;
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
