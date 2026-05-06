// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchJson } from "./http";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchJson", () => {
  it("resolves relative API paths against the configured API base URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchJson("/api/docs/config.json");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/api/docs/config.json",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("uses absolute API URLs without prefixing the configured API base URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchJson("https://api.btcnetwork.info/api/openapi.json");

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.btcnetwork.info/api/openapi.json",
      expect.objectContaining({ method: "GET" }),
    );
  });
});
