// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  countNodesByAsn,
  getCrawlRun,
  listCrawlRuns,
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
      "http://127.0.0.1:8080/api/v1/crawler/runs?limit=5",
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

    await expect(countNodesByAsn()).rejects.toThrow("crawler analytics backend failed");
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
      "http://127.0.0.1:8080/api/v1/crawler/last-run/network-types?limit=5",
      expect.objectContaining({ method: "GET" }),
    );
    expect(rows).toEqual([{ networkType: "ipv4", nodeCount: 42 }]);
  });
});
