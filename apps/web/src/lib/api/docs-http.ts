import { apiBaseUrl, fetchJson } from "./http";
import type { DocsUiConfig } from "./types";

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

function resolveApiAssetUrl(pathOrUrl: string): string {
  return new URL(pathOrUrl, `${apiBaseUrl()}/`).toString();
}
