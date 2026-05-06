// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  countNodesByAsn,
  getCrawlRun,
  listCrawlRuns,
  listLastRunCountries,
  listLastRunNodes,
  listLastRunNetworkTypes,
} from "./analytics-http";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("analytics-http", () => {
  it("loads crawler runs from the HTTP API envelope", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        runs: [
          {
            runId: "crawl-1",
            phase: "completed",
            startedAt: "2026-03-30T12:00:00Z",
            lastCheckpointedAt: "2026-03-30T12:10:00Z",
            stopReason: "idle timeout",
            failureReason: null,
            scheduledTasks: 100,
            successfulHandshakes: 20,
            failedTasks: 80,
            uniqueNodes: 125,
            persistedObservationRows: 100,
            successPct: 20,
            scheduledPct: 80,
            unscheduledGap: 25,
          },
        ],
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const runs = await listCrawlRuns(5);

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/api/v1/network/historical/runs?limit=5",
      expect.objectContaining({ method: "GET" }),
    );
    expect(runs[0]?.runId).toBe("crawl-1");
  });

  it("loads a crawl run detail document", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          run: {
            runId: "crawl-1",
            phase: "completed",
            startedAt: "2026-03-30T12:00:00Z",
            lastCheckpointedAt: "2026-03-30T12:10:00Z",
            stopReason: "idle timeout",
            failureReason: null,
            scheduledTasks: 100,
            successfulHandshakes: 20,
            failedTasks: 80,
            uniqueNodes: 125,
            persistedObservationRows: 100,
            successPct: 20,
            scheduledPct: 80,
            unscheduledGap: 25,
          },
          checkpoints: [],
          failureCounts: [],
          networkOutcomes: [],
        }),
      }),
    );

    const detail = await getCrawlRun("crawl-1");

    expect(detail.run.runId).toBe("crawl-1");
  });

  it("surfaces API errors without leaking parsing failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        json: async () => ({ error: "crawler analytics backend failed" }),
      }),
    );

    await expect(
      countNodesByAsn(10, {
        start: "2026-04-01T00:00:00.000Z",
        end: "2026-04-30T00:00:00.000Z",
      }),
    ).rejects.toThrow("crawler analytics backend failed");
  });

  it("loads historical ASN rows with an explicit time window", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        rows: [
          {
            asn: 64512,
            asnOrganization: "Example ASN",
            verifiedNodes: 2,
          },
        ],
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const rows = await countNodesByAsn(5, {
      start: "2026-04-01T00:00:00.000Z",
      end: "2026-04-30T00:00:00.000Z",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/api/v1/network/historical/asns?start=2026-04-01T00%3A00%3A00.000Z&end=2026-04-30T00%3A00%3A00.000Z&limit=5",
      expect.objectContaining({ method: "GET" }),
    );
    expect(rows).toEqual([{ asn: 64512, asnOrganization: "Example ASN", verifiedNodes: 2 }]);
  });

  it("loads last-run network type rows from the explicit last-run endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        rows: [
          {
            networkType: "ipv4",
            nodeCount: 42,
          },
        ],
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const rows = await listLastRunNetworkTypes(5);

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/api/v1/network/last-run/network-types?limit=5",
      expect.objectContaining({ method: "GET" }),
    );
    expect(rows).toEqual([{ networkType: "ipv4", nodeCount: 42 }]);
  });

  it("loads country rows with a phase filter for live snapshot views", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        rows: [
          {
            country: "US",
            nodeCount: 42,
          },
        ],
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const rows = await listLastRunCountries(5, { phase: "any" });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/api/v1/network/last-run/countries?limit=5&phase=any",
      expect.objectContaining({ method: "GET" }),
    );
    expect(rows).toEqual([{ country: "US", nodeCount: 42 }]);
  });

  it("loads last-run node pages from the page envelope", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        items: [
          {
            endpoint: "1.1.1.1:8333",
            networkType: "ipv4",
            protocolVersion: 70016,
            userAgent: "/Satoshi:27.0.0/",
            services: "1",
            startHeight: 900000,
            country: "US",
            asn: 64512,
            asnOrganization: "Example ASN",
          },
        ],
        nextPageToken: "next-token",
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const page = await listLastRunNodes(5, "cursor-token");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8080/api/v1/network/last-run/nodes?limit=5&pageToken=cursor-token",
      expect.objectContaining({ method: "GET" }),
    );
    expect(page.nextPageToken).toBe("next-token");
    expect(page.items[0]?.endpoint).toBe("1.1.1.1:8333");
  });
});
