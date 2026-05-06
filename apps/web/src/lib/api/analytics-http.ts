import type {
  AsnNodeCountItem,
  CrawlRunDetail,
  CrawlRunListItem,
  HistoricalWindow,
  LastRunAsnCountItem,
  LastRunAsnOrganizationCountItem,
  LastRunCountryCountItem,
  LastRunNetworkTypeCountItem,
  LastRunNodeSummaryItem,
  LastRunProtocolVersionCountItem,
  LastRunServicesCountItem,
  LastRunStartHeightCountItem,
  LastRunUserAgentCountItem,
  NodeStatusItem,
  PageResponse,
} from "./types";
import { fetchJson } from "./http";
import type { CrawlRunPhaseFilterOptions } from "./client";

type CrawlRunsResponse = {
  runs: CrawlRunListItem[];
};

type RowsResponse<T> = {
  rows: T[];
};

function defaultHistoricalWindow(): HistoricalWindow {
  const end = new Date();
  const start = new Date(end);
  start.setUTCDate(start.getUTCDate() - 31);

  return {
    start: start.toISOString(),
    end: end.toISOString(),
  };
}

export async function listCrawlRuns(limit = 10): Promise<CrawlRunListItem[]> {
  const response = await fetchJson<CrawlRunsResponse>(
    `/api/v1/network/historical/runs?limit=${encodeURIComponent(String(limit))}`,
  );

  return response.runs;
}

export async function getCrawlRun(runId: string): Promise<CrawlRunDetail> {
  return fetchJson<CrawlRunDetail>(`/api/v1/network/historical/runs/${encodeURIComponent(runId)}`);
}

export async function countNodesByAsn(
  limit = 10,
  window: HistoricalWindow = defaultHistoricalWindow(),
): Promise<AsnNodeCountItem[]> {
  return fetchRows<AsnNodeCountItem>(
    `/api/v1/network/historical/asns?start=${encodeURIComponent(window.start)}&end=${encodeURIComponent(window.end)}&limit=${encodeURIComponent(String(limit))}`,
  );
}

async function fetchRows<T>(path: string): Promise<T[]> {
  const response = await fetchJson<RowsResponse<T>>(path);
  return response.rows;
}

function lastRunDistributionPath(path: string, limit: number, options: CrawlRunPhaseFilterOptions): string {
  const params = new URLSearchParams({ limit: String(limit) });

  if (options.phase) {
    params.set("phase", Array.isArray(options.phase) ? options.phase.join(",") : options.phase);
  }

  return `/api/v1/network/last-run/${path}?${params.toString()}`;
}

export async function listLastRunServices(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunServicesCountItem[]> {
  return fetchRows<LastRunServicesCountItem>(lastRunDistributionPath("services", limit, options));
}

export async function listLastRunProtocolVersions(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunProtocolVersionCountItem[]> {
  return fetchRows<LastRunProtocolVersionCountItem>(
    lastRunDistributionPath("protocol-versions", limit, options),
  );
}

export async function listLastRunUserAgents(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunUserAgentCountItem[]> {
  return fetchRows<LastRunUserAgentCountItem>(lastRunDistributionPath("user-agents", limit, options));
}

export async function listLastRunNetworkTypes(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunNetworkTypeCountItem[]> {
  return fetchRows<LastRunNetworkTypeCountItem>(
    lastRunDistributionPath("network-types", limit, options),
  );
}

export async function listLastRunCountries(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunCountryCountItem[]> {
  return fetchRows<LastRunCountryCountItem>(lastRunDistributionPath("countries", limit, options));
}

export async function listLastRunAsns(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunAsnCountItem[]> {
  return fetchRows<LastRunAsnCountItem>(lastRunDistributionPath("asns", limit, options));
}

export async function listLastRunStartHeights(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunStartHeightCountItem[]> {
  return fetchRows<LastRunStartHeightCountItem>(
    lastRunDistributionPath("start-heights", limit, options),
  );
}

export async function listLastRunAsnOrganizations(
  limit = 100,
  options: CrawlRunPhaseFilterOptions = {},
): Promise<LastRunAsnOrganizationCountItem[]> {
  return fetchRows<LastRunAsnOrganizationCountItem>(
    lastRunDistributionPath("asn-organizations", limit, options),
  );
}

export async function listLastRunNodes(
  limit = 500,
  pageToken?: string,
): Promise<PageResponse<LastRunNodeSummaryItem>> {
  const params = new URLSearchParams({ limit: String(limit) });

  if (pageToken) {
    params.set("pageToken", pageToken);
  }

  return fetchJson<PageResponse<LastRunNodeSummaryItem>>(
    `/api/v1/network/last-run/nodes?${params.toString()}`,
  );
}

export async function listNodeStatus(): Promise<NodeStatusItem[]> {
  return fetchJson<NodeStatusItem[]>("/api/nodes/status");
}
