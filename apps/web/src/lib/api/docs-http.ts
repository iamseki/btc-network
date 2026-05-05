import demoAgentsGuideMarkdown from "./api-agents.md?raw";

import { apiBaseUrl, fetchJson } from "./http";
import type { DocsUiConfig } from "./types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

export async function getDocsUiConfig(): Promise<DocsUiConfig> {
  const docsUiConfig = await fetchJson<DocsUiConfig>("/api/docs/config.json");

  return {
    ...docsUiConfig,
    openapiUrl: resolveApiAssetUrl(docsUiConfig.openapiUrl),
    scalarPath: resolveApiAssetUrl(docsUiConfig.scalarPath),
    baseServerUrl: docsUiConfig.baseServerUrl ?? apiBaseUrl(),
  };
}

export async function getOpenApiDocument(path = "/api/openapi.json"): Promise<Record<string, unknown>> {
  return fetchJson<Record<string, unknown>>(path);
}

export function getAgentsGuideUrl(path = "/agents.md"): string {
  if (isDemoModeEnabled()) {
    return `data:text/markdown;charset=utf-8,${encodeURIComponent(demoAgentsGuideMarkdown)}`;
  }

  return resolveApiAssetUrl(path);
}

export async function getAgentsGuideMarkdown(path = "/agents.md"): Promise<string> {
  if (isDemoModeEnabled()) {
    // `./api-agents.md` is a symlink to the API-owned guide so demo builds do not maintain a second copy.
    return demoAgentsGuideMarkdown;
  }

  const response = await fetch(getAgentsGuideUrl(path), {
    method: "GET",
    headers: {
      Accept: "text/markdown, text/plain;q=0.9",
    },
  });

  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }

  return response.text();
}

function resolveApiAssetUrl(pathOrUrl: string): string {
  return new URL(pathOrUrl, `${apiBaseUrl()}/`).toString();
}
