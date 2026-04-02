import type { AsnNodeCountItem, CrawlRunDetail, CrawlRunListItem } from "./types";

type CrawlRunsResponse = {
  runs: CrawlRunListItem[];
};

type AsnCountsResponse = {
  rows: AsnNodeCountItem[];
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
  const response = await fetchJson<AsnCountsResponse>(
    `/api/v1/crawler/asn?limit=${encodeURIComponent(String(limit))}`,
  );

  return response.rows;
}
