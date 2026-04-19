import { fetchJson } from "./http";
import type { DocsUiConfig } from "./types";

export async function getDocsUiConfig(): Promise<DocsUiConfig> {
  return fetchJson<DocsUiConfig>("/api/docs/config.json");
}
