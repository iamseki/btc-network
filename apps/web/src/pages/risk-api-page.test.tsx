// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";

import { RiskApiPage } from "./risk-api-page";

afterEach(() => {
  cleanup();
});

function makeClient(overrides: Partial<BtcAppClient> = {}): BtcAppClient {
  return {
    listCrawlRuns: vi.fn().mockResolvedValue([
      {
        runId: "crawl-9",
        phase: "completed",
        startedAt: "2026-03-30T12:00:00Z",
        lastCheckpointedAt: "2026-03-30T12:05:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 100,
        successfulHandshakes: 42,
        failedTasks: 58,
        uniqueNodes: 130,
        persistedObservationRows: 100,
        successPct: 42,
        scheduledPct: 76.92,
        unscheduledGap: 30,
      },
    ]),
    getCrawlRun: vi.fn().mockResolvedValue({
      run: {
        runId: "crawl-9",
        phase: "completed",
        startedAt: "2026-03-30T12:00:00Z",
        lastCheckpointedAt: "2026-03-30T12:05:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 100,
        successfulHandshakes: 42,
        failedTasks: 58,
        uniqueNodes: 130,
        persistedObservationRows: 100,
        successPct: 42,
        scheduledPct: 76.92,
        unscheduledGap: 30,
      },
      checkpoints: [],
      failureCounts: [],
      networkOutcomes: [
        {
          networkType: "ipv4",
          observations: 90,
          verifiedNodes: 42,
          failedNodes: 48,
          verifiedPct: 46.67,
        },
        {
          networkType: "torv3",
          observations: 10,
          verifiedNodes: 1,
          failedNodes: 9,
          verifiedPct: 10,
        },
      ],
    }),
    countNodesByAsn: vi.fn().mockResolvedValue([
      {
        asn: 64512,
        asnOrganization: "Example ASN",
        verifiedNodes: 18,
      },
      {
        asn: 64513,
        asnOrganization: "Second ASN",
        verifiedNodes: 12,
      },
    ]),
    handshake: vi.fn(),
    ping: vi.fn(),
    getAddr: vi.fn(),
    getLastBlockHeight: vi.fn().mockResolvedValue({
      node: "seed.bitnodes.io:8333",
      height: 892345,
      rounds: 2,
      elapsedMs: 184,
      bestBlockHash: "0000000000000000000123456789abcdef0123456789abcdef0123456789abcd",
    }),
    getBlock: vi.fn(),
    downloadBlock: vi.fn(),
    getSuggestedBlockDownloadPath: vi.fn().mockResolvedValue("downloads/block.dat"),
    getRecentEvents: vi.fn().mockResolvedValue([]),
    ...overrides,
  };
}

describe("RiskApiPage", () => {
  it("renders a mocked commercial landing page driven by current analytics inputs", async () => {
    render(<RiskApiPage client={makeClient()} />);

    expect(await screen.findByText("Network Risk API")).toBeTruthy();
    expect(screen.getByText("Sell Bitcoin network visibility as a risk API, not a novelty dashboard.")).toBeTruthy();
    expect(screen.getByText("Preview only")).toBeTruthy();
    expect(screen.getByText("SLA-Ready Read Path")).toBeTruthy();
    expect(screen.getByText("Why teams buy this")).toBeTruthy();
    expect(screen.getByText("Treasury and Custody Risk")).toBeTruthy();
    expect(screen.getByText("Example Snapshot Contract")).toBeTruthy();
    expect(screen.getByText(/\"lead_asn\": 64512/i)).toBeTruthy();
    expect(screen.getByText(/\"chain_height\": 892345/i)).toBeTruthy();
    expect(await screen.findByText(/Example ASN/i)).toBeTruthy();
  });

  it("falls back to commercial framing when live analytics loading fails", async () => {
    const client = makeClient({
      listCrawlRuns: vi.fn().mockRejectedValue(new Error("api unavailable")),
    });

    render(<RiskApiPage client={client} />);

    expect(await screen.findByText("Preview is showing mocked commercial framing only")).toBeTruthy();
    expect(screen.getByText("Sell Bitcoin network visibility as a risk API, not a novelty dashboard.")).toBeTruthy();
    expect(screen.getByText("Mocked browser-only commercial surface")).toBeTruthy();
  });
});
