import { afterEach, describe, expect, it, vi } from "vitest";

import { webClient } from "./web-client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("webClient", () => {
  it("loads crawler runs through the shared HTTP analytics helper", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
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
              successfulHandshakes: 25,
              failedTasks: 75,
              uniqueNodes: 120,
              persistedObservationRows: 100,
              successPct: 25,
              scheduledPct: 83.33,
              unscheduledGap: 20,
            },
          ],
        }),
      }),
    );

    const runs = await webClient.listCrawlRuns();

    expect(runs[0]?.runId).toBe("crawl-1");
  });

  it("returns a deterministic mock handshake response for the requested node", async () => {
    const result = await webClient.handshake({ node: "seed.bitnodes.io:8333" });

    expect(result.node).toBe("seed.bitnodes.io:8333");
    expect(result.protocolVersion).toBe(70016);
    expect(result.serviceNames.length).toBeGreaterThan(0);
    expect(result.userAgent).toMatch(/^\/btc-network:web-mock-/);
    expect(result.startHeight).toBeGreaterThan(0);
  });

  it("returns deterministic mock peer addresses", async () => {
    const result = await webClient.getAddr("seed.bitnodes.io:8333");

    expect(result.node).toBe("seed.bitnodes.io:8333");
    expect(result.addresses).toHaveLength(3);
    expect(result.addresses[0]?.network).toBe("ipv4");
    expect(result.addresses[1]?.network).toBe("ipv6");
    expect(result.addresses[2]?.network).toBe("torv3");
  });

  it("emits a realistic progress lifecycle for last block height", async () => {
    const onProgress = vi.fn();
    const result = await webClient.getLastBlockHeight("seed.bitnodes.io:8333", onProgress);

    expect(result.height).toBeGreaterThan(0);
    expect(result.bestBlockHash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.rounds).toBeGreaterThan(0);
    expect(onProgress).toHaveBeenCalledTimes(4);
    expect(onProgress.mock.calls[0]?.[0].phase).toBe("connecting");
    expect(onProgress.mock.calls[1]?.[0].phase).toBe("handshaking");
    expect(onProgress.mock.calls[2]?.[0].phase).toBe("requesting_headers");
    expect(onProgress.mock.calls[3]?.[0].phase).toBe("completed");
    expect(onProgress.mock.calls[3]?.[0].bestBlockHash).toBe(result.bestBlockHash);
  });

  it("returns a deterministic block summary for the requested hash", async () => {
    const hash =
      "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde";
    const result = await webClient.getBlock("seed.bitnodes.io:8333", hash);

    expect(result.hash).toBe(hash);
    expect(result.txCount).toBeGreaterThan(0);
    expect(result.serializedSize).toBeGreaterThan(284);
    expect(result.coinbaseTxDetected).toBe(true);
  });

  it("derives the default output filename for block downloads", async () => {
    const hash =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const result = await webClient.downloadBlock({ node: "node", hash });

    expect(result.outputPath).toBe("downloads/blk-00000000-8ce26f.dat");
    expect(result.rawBytes).toBeGreaterThan(284);
  });

  it("returns a suggested host download path for block downloads", async () => {
    const hash =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    const result = await webClient.getSuggestedBlockDownloadPath(hash);

    expect(result).toBe("downloads/blk-00000000-8ce26f.dat");
  });

  it("records mock API activity in recent events", async () => {
    await webClient.handshake({ node: "seed.bitnodes.io:8333" });
    await webClient.ping("seed.bitnodes.io:8333");

    const events = await webClient.getRecentEvents();

    expect(events[0]?.message).toContain("Mock ping round-trip completed");
    expect(events[1]?.message).toContain("Mock handshake completed");
    expect(events.some((event) => event.message.includes("placeholder mode"))).toBe(true);
  });
});
