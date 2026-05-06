import demoAgentsGuideMarkdown from "./api-agents.md?raw";

import { apiBaseUrl, fetchJson } from "./http";
import type { DocsUiConfig } from "./types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

type OpenApiDocument = Record<string, unknown> & {
  servers?: unknown;
};

export async function getDocsUiConfig(): Promise<DocsUiConfig> {
  const docsUiConfig = await fetchJson<DocsUiConfig>("/api/docs/config.json");

  return {
    ...docsUiConfig,
    openapiUrl: resolveApiAssetUrl(docsUiConfig.openapiUrl),
    scalarPath: resolveApiAssetUrl(docsUiConfig.scalarPath),
    baseServerUrl: docsUiConfig.baseServerUrl ?? apiBaseUrl(),
  };
}

export async function getOpenApiDocument(
  pathOrUrl = "/api/openapi.json",
  options: { baseServerUrl?: string | null } = {},
): Promise<Record<string, unknown>> {
  const document = await fetchJson<OpenApiDocument>(pathOrUrl);

  return withConfiguredServer(document, options.baseServerUrl);
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

function withConfiguredServer(
  document: OpenApiDocument,
  baseServerUrl: string | null | undefined,
): OpenApiDocument {
  const normalizedBaseServerUrl = normalizeBaseServerUrl(baseServerUrl);

  if (!normalizedBaseServerUrl) {
    return document;
  }

  const existingServers = Array.isArray(document.servers) ? document.servers : [];
  const serverUrls = new Set<string>();
  const servers = [{ url: normalizedBaseServerUrl }];
  serverUrls.add(normalizedBaseServerUrl);

  for (const server of existingServers) {
    if (!isOpenApiServer(server) || serverUrls.has(server.url)) {
      continue;
    }

    serverUrls.add(server.url);
    servers.push(server);
  }

  return {
    ...document,
    servers,
  };
}

function normalizeBaseServerUrl(baseServerUrl: string | null | undefined): string | null {
  const trimmed = baseServerUrl?.trim();

  if (!trimmed) {
    return null;
  }

  try {
    return new URL(trimmed).toString().replace(/\/+$/, "");
  } catch {
    return null;
  }
}

function isOpenApiServer(server: unknown): server is { url: string } {
  return (
    typeof server === "object" &&
    server !== null &&
    "url" in server &&
    typeof server.url === "string"
  );
}
