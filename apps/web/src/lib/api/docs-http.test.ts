import { afterEach, describe, expect, it, vi } from "vitest";

import {
  getAgentsGuideMarkdown,
  getAgentsGuideUrl,
  getDocsUiConfig,
  getOpenApiDocument,
} from "./docs-http";
import { apiBaseUrl, fetchJson } from "./http";

vi.mock("./http", () => ({
  apiBaseUrl: vi.fn(() => "http://127.0.0.1:8080"),
  fetchJson: vi.fn(),
}));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

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

describe("getOpenApiDocument", () => {
  it("fetches the generated OpenAPI document and injects the configured server", async () => {
    vi.mocked(fetchJson).mockResolvedValueOnce({
      openapi: "3.1.0",
      info: { title: "btc-network API", version: "0.1.0" },
      paths: {},
    });

    const document = await getOpenApiDocument("http://127.0.0.1:8080/api/openapi.json", {
      baseServerUrl: "http://127.0.0.1:8080",
    });

    expect(fetchJson).toHaveBeenCalledWith("http://127.0.0.1:8080/api/openapi.json");
    expect(document).toMatchObject({
      openapi: "3.1.0",
      servers: [{ url: "http://127.0.0.1:8080" }],
    });
  });

  it("keeps existing OpenAPI servers after the configured web API server", async () => {
    vi.mocked(fetchJson).mockResolvedValueOnce({
      openapi: "3.1.0",
      info: { title: "btc-network API", version: "0.1.0" },
      servers: [{ url: "https://api.btcnetwork.info" }],
      paths: {},
    });

    const document = await getOpenApiDocument("/api/openapi.json", {
      baseServerUrl: "http://127.0.0.1:8080/",
    });

    expect(document.servers).toEqual([
      { url: "http://127.0.0.1:8080" },
      { url: "https://api.btcnetwork.info" },
    ]);
  });
});

describe("getAgentsGuideUrl", () => {
  it("resolves the agent guide URL against the API host", () => {
    expect(getAgentsGuideUrl()).toBe("http://127.0.0.1:8080/agents.md");
  });

  it("uses a bundled data URL in demo mode", () => {
    vi.stubEnv("VITE_DEMO_MODE", "true");

    const url = getAgentsGuideUrl();
    expect(url.startsWith("data:text/markdown;charset=utf-8,")).toBe(true);
    expect(decodeURIComponent(url)).toContain("btc-network Agent Guide");
  });
});

describe("getAgentsGuideMarkdown", () => {
  it("fetches markdown from the resolved guide URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => "# guide",
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(getAgentsGuideMarkdown()).resolves.toBe("# guide");
    expect(fetchMock).toHaveBeenCalledWith("http://127.0.0.1:8080/agents.md", {
      method: "GET",
      headers: {
        Accept: "text/markdown, text/plain;q=0.9",
      },
    });
  });

  it("returns bundled markdown without fetching in demo mode", async () => {
    const fetchMock = vi.fn();
    vi.stubEnv("VITE_DEMO_MODE", "true");
    vi.stubGlobal("fetch", fetchMock);

    const markdown = await getAgentsGuideMarkdown();

    expect(markdown).toContain("btc-network Agent Guide");
    expect(markdown).toContain("OpenAPI");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
