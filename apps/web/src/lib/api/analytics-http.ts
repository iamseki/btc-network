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
} from "./types";

type CrawlRunsResponse = {
  runs: CrawlRunListItem[];
};

type RowsResponse<T> = {
  rows: T[];
};

function resolveApiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL?.trim();

  if (configured) {
    return configured.replace(/\/+$/, "");
  }

  if (import.meta.env.DEV) {
    return "http://127.0.0.1:8080";
  }

  return "https://api.btcnetwork.info";
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${resolveApiBaseUrl()}${path}`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    let message = `Request failed with ${response.status}`;

    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) {
        message = body.error;
      }
    } catch {
      // Use the default status-based message when the body is not valid JSON.
    }

    throw new Error(message);
  }

  return (await response.json()) as T;
}

export async function listCrawlRuns(limit = 10): Promise<CrawlRunListItem[]> {
  const response = await fetchJson<CrawlRunsResponse>(
    `/api/v1/crawler/runs?limit=${encodeURIComponent(String(limit))}`,
  );

  return response.runs;
}

export async function getCrawlRun(runId: string): Promise<CrawlRunDetail> {
  return fetchJson<CrawlRunDetail>(`/api/v1/crawler/runs/${encodeURIComponent(runId)}`);
}

export async function countNodesByAsn(limit = 10): Promise<AsnNodeCountItem[]> {
  return fetchRows<AsnNodeCountItem>(`/api/v1/crawler/asn?limit=${encodeURIComponent(String(limit))}`);
}

async function fetchRows<T>(path: string): Promise<T[]> {
  const response = await fetchJson<RowsResponse<T>>(path);
  return response.rows;
}

export async function listLastRunServices(limit = 100): Promise<LastRunServicesCountItem[]> {
  return fetchRows<LastRunServicesCountItem>(
    `/api/v1/crawler/last-run/services?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunProtocolVersions(
  limit = 100,
): Promise<LastRunProtocolVersionCountItem[]> {
  return fetchRows<LastRunProtocolVersionCountItem>(
    `/api/v1/crawler/last-run/protocol-versions?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunUserAgents(limit = 100): Promise<LastRunUserAgentCountItem[]> {
  return fetchRows<LastRunUserAgentCountItem>(
    `/api/v1/crawler/last-run/user-agents?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunNetworkTypes(
  limit = 100,
): Promise<LastRunNetworkTypeCountItem[]> {
  return fetchRows<LastRunNetworkTypeCountItem>(
    `/api/v1/crawler/last-run/network-types?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunCountries(limit = 100): Promise<LastRunCountryCountItem[]> {
  return fetchRows<LastRunCountryCountItem>(
    `/api/v1/crawler/last-run/countries?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunAsns(limit = 100): Promise<LastRunAsnCountItem[]> {
  return fetchRows<LastRunAsnCountItem>(
    `/api/v1/crawler/last-run/asns?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunStartHeights(
  limit = 100,
): Promise<LastRunStartHeightCountItem[]> {
  return fetchRows<LastRunStartHeightCountItem>(
    `/api/v1/crawler/last-run/start-heights?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunAsnOrganizations(
  limit = 100,
): Promise<LastRunAsnOrganizationCountItem[]> {
  return fetchRows<LastRunAsnOrganizationCountItem>(
    `/api/v1/crawler/last-run/asn-organizations?limit=${encodeURIComponent(String(limit))}`,
  );
}

export async function listLastRunNodes(limit = 500): Promise<LastRunNodeSummaryItem[]> {
  return fetchRows<LastRunNodeSummaryItem>(
    `/api/v1/crawler/last-run/nodes?limit=${encodeURIComponent(String(limit))}`,
  );
}
