import type {
  AsnNodeCountItem,
  CrawlRunDetail,
  CrawlRunListItem,
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
} from "./types";
import { fetchJson } from "./http";

type CrawlRunsResponse = {
  runs: CrawlRunListItem[];
};

type RowsResponse<T> = {
  rows: T[];
};

export async function listCrawlRuns(limit = 10): Promise<CrawlRunListItem[]> {
  const response = await fetchJson<CrawlRunsResponse>(
    `/api/v1/network/historical/runs?limit=${encodeURIComponent(String(limit))}`,
  );

  return response.runs;
}

export async function getCrawlRun(runId: string): Promise<CrawlRunDetail> {
  return fetchJson<CrawlRunDetail>(`/api/v1/network/historical/runs/${encodeURIComponent(runId)}`);
}

export async function countNodesByAsn(limit = 10): Promise<AsnNodeCountItem[]> {
  return fetchRows<AsnNodeCountItem>(`/api/v1/network/historical/asns?limit=${encodeURIComponent(String(limit))}`);
}

async function fetchRows<T>(path: string): Promise<T[]> {
  const response = await fetchJson<RowsResponse<T>>(path);
  return response.rows;
}

export async function listLastRunServices(limit = 100): Promise<LastRunServicesCountItem[]> {
  return fetchRows<LastRunServicesCountItem>(
    `/api/v1/network/last-run/services?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunProtocolVersions(
  limit = 100,
): Promise<LastRunProtocolVersionCountItem[]> {
  return fetchRows<LastRunProtocolVersionCountItem>(
    `/api/v1/network/last-run/protocol-versions?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunUserAgents(limit = 100): Promise<LastRunUserAgentCountItem[]> {
  return fetchRows<LastRunUserAgentCountItem>(
    `/api/v1/network/last-run/user-agents?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunNetworkTypes(
  limit = 100,
): Promise<LastRunNetworkTypeCountItem[]> {
  return fetchRows<LastRunNetworkTypeCountItem>(
    `/api/v1/network/last-run/network-types?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunCountries(limit = 100): Promise<LastRunCountryCountItem[]> {
  return fetchRows<LastRunCountryCountItem>(
    `/api/v1/network/last-run/countries?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunAsns(limit = 100): Promise<LastRunAsnCountItem[]> {
  return fetchRows<LastRunAsnCountItem>(
    `/api/v1/network/last-run/asns?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunStartHeights(
  limit = 100,
): Promise<LastRunStartHeightCountItem[]> {
  return fetchRows<LastRunStartHeightCountItem>(
    `/api/v1/network/last-run/start-heights?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunAsnOrganizations(
  limit = 100,
): Promise<LastRunAsnOrganizationCountItem[]> {
  return fetchRows<LastRunAsnOrganizationCountItem>(
    `/api/v1/network/last-run/asn-organizations?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunNodes(limit = 500): Promise<LastRunNodeSummaryItem[]> {
  return fetchRows<LastRunNodeSummaryItem>(
    `/api/v1/network/last-run/nodes?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listNodeStatus(): Promise<NodeStatusItem[]> {
  return fetchJson<NodeStatusItem[]>("/api/nodes/status");
}
