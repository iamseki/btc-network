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

function resolveApiAssetUrl(pathOrUrl: string): string {
  return new URL(pathOrUrl, `${apiBaseUrl()}/`).toString();
}
