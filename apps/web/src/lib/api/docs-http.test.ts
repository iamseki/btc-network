import { describe, expect, it, vi } from "vitest";

import { getDocsUiConfig } from "./docs-http";
import { apiBaseUrl, fetchJson } from "./http";

vi.mock("./http", () => ({
  apiBaseUrl: vi.fn(() => "http://127.0.0.1:8080"),
  fetchJson: vi.fn(),
}));

describe("getDocsUiConfig", () => {
  it("normalizes spec and docs URLs against the API host", async () => {
    vi.mocked(fetchJson).mockResolvedValueOnce({
      title: "btc-network API",
      version: "0.1.0",
      description: "Generated docs",
      introduction: "Start with runs.",
      openapiUrl: "/api/openapi.json",
      openapiPath: "/api/openapi.json",
      scalarPath: "/docs",
      baseServerUrl: null,
    });

    const docsUiConfig = await getDocsUiConfig();

    expect(fetchJson).toHaveBeenCalledWith("/api/docs/config.json");
    expect(apiBaseUrl).toHaveBeenCalled();
    expect(docsUiConfig.openapiUrl).toBe("http://127.0.0.1:8080/api/openapi.json");
    expect(docsUiConfig.scalarPath).toBe("http://127.0.0.1:8080/docs");
    expect(docsUiConfig.baseServerUrl).toBe("http://127.0.0.1:8080");
  });
});
