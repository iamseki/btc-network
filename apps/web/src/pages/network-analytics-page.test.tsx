// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";

import { NetworkAnalyticsPage } from "./network-analytics-page";

afterEach(() => {
  cleanup();
});

function makeClient(overrides: Partial<BtcAppClient> = {}): BtcAppClient {
  return {
    listCrawlRuns: vi.fn().mockResolvedValue([]),
    getCrawlRun: vi.fn().mockResolvedValue({
      run: {
        runId: "crawl-1",
        phase: "completed",
        startedAt: "2026-03-30T12:00:00Z",
        lastCheckpointedAt: "2026-03-30T12:10:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 100,
        successfulHandshakes: 30,
        failedTasks: 70,
        uniqueNodes: 130,
        persistedObservationRows: 100,
        successPct: 30,
        scheduledPct: 76.92,
        unscheduledGap: 30,
      },
      checkpoints: [],
      failureCounts: [],
      networkOutcomes: [],
    }),
    countNodesByAsn: vi.fn().mockResolvedValue([]),
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

describe("NetworkAnalyticsPage", () => {
  it("shows an empty state when no analytics data exists", async () => {
    const client = makeClient();

    render(<NetworkAnalyticsPage client={client} />);

    expect(
      await screen.findByText(/No crawler analytics are available yet\./i),
    ).toBeTruthy();
  });

  it("renders a focused overview first, then loads ASN and verification tables on demand", async () => {
    const client = makeClient({
      listCrawlRuns: vi.fn().mockResolvedValue([
        {
          runId: "crawl-7",
          phase: "completed",
          startedAt: "2026-03-30T12:00:00Z",
          lastCheckpointedAt: "2026-03-30T12:10:00Z",
          stopReason: "idle timeout",
          failureReason: null,
          scheduledTasks: 100,
          successfulHandshakes: 30,
          failedTasks: 70,
          uniqueNodes: 130,
          persistedObservationRows: 100,
          successPct: 30,
          scheduledPct: 76.92,
          unscheduledGap: 30,
        },
      ]),
      countNodesByAsn: vi.fn().mockResolvedValue([
        {
          asn: 64512,
          asnOrganization: "Example ASN",
          verifiedNodes: 18,
        },
      ]),
      getCrawlRun: vi.fn().mockResolvedValue({
        run: {
          runId: "crawl-7",
          phase: "completed",
          startedAt: "2026-03-30T12:00:00Z",
          lastCheckpointedAt: "2026-03-30T12:10:00Z",
          stopReason: "idle timeout",
          failureReason: null,
          scheduledTasks: 100,
          successfulHandshakes: 30,
          failedTasks: 70,
          uniqueNodes: 130,
          persistedObservationRows: 100,
          successPct: 30,
          scheduledPct: 76.92,
          unscheduledGap: 30,
        },
        checkpoints: [],
        failureCounts: [],
        networkOutcomes: [
          {
            networkType: "ipv4",
            observations: 90,
            verifiedNodes: 30,
            failedNodes: 60,
            verifiedPct: 33.33,
          },
        ],
      }),
    });

    render(<NetworkAnalyticsPage client={client} />);

    expect(await screen.findByText("Network Risk Snapshot")).toBeTruthy();
    expect(await screen.findByText("Decentralization Score")).toBeTruthy();
    expect(screen.getByText("Eclipse Exposure (Proxy)")).toBeTruthy();
    expect(screen.getByText("Observation Confidence")).toBeTruthy();
    expect(screen.getByText("Transport Diversity")).toBeTruthy();
    expect(scoreCardValue("Decentralization Score")).toBe("15");
    expect(scoreCardValue("Eclipse Exposure (Proxy)")).toBe("86");
    expect(scoreCardValue("Observation Confidence")).toBe("58");
    expect(scoreCardValue("Transport Diversity")).toBe("0");
    expect(screen.getByRole("button", { name: "Decentralization Score score explanation" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Eclipse Exposure (Proxy) score explanation" })).toBeTruthy();
    expect(screen.getByText("Network Risk Snapshot")).toBeTruthy();
    expect(await screen.findByText("Risk Drivers")).toBeTruthy();
    expect(screen.queryByText("Checkpoint Rail")).toBeNull();
    expect(screen.getByText(/Public risk view from the latest read-only crawler snapshot\./i)).toBeTruthy();
    expect(screen.getByText("Block Height")).toBeTruthy();
    expect(screen.getAllByText("892,345").length).toBeGreaterThan(0);
    expect(screen.getByText("Verification Distribution")).toBeTruthy();
    expect(screen.getByText("Example ASN")).toBeTruthy();
    expect(screen.getAllByText("ipv4").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Top ASNs" }));
    expect(await screen.findByText("Organization")).toBeTruthy();
    expect((await screen.findAllByText("Example ASN")).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Verification" }));
    expect((await screen.findAllByText("Failed")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText("ipv4")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText("33.33%")).length).toBeGreaterThan(0);
  });

  it("shows an error state when analytics loading fails", async () => {
    const client = makeClient({
      listCrawlRuns: vi.fn().mockRejectedValue(new Error("api unavailable")),
    });

    render(<NetworkAnalyticsPage client={client} />);

    expect(
      await screen.findByText("Network analytics failed to load: api unavailable"),
    ).toBeTruthy();
  });
});

function scoreCardValue(label: string): string {
  const labelNode = screen.getByText(label);
  const card = labelNode.closest("div[class*='rounded']");

  if (!(card instanceof HTMLElement)) {
    throw new Error(`Could not find score card for ${label}`);
  }

  const values = within(card).getAllByText(/^\d+$/);
  return values[0]?.textContent ?? "";
}
