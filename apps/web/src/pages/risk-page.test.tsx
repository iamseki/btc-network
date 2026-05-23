// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";

import { RiskPage } from "./risk-page";

afterEach(() => {
  cleanup();
});

function makeClient(overrides: Partial<BtcAppClient> = {}): BtcAppClient {
  return {
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
    countNodesByAsn: vi.fn().mockResolvedValue([]),
    listLastRunServices: vi.fn().mockResolvedValue([]),
    listLastRunProtocolVersions: vi.fn().mockResolvedValue([]),
    listLastRunUserAgents: vi.fn().mockResolvedValue([]),
    listLastRunNetworkTypes: vi.fn().mockResolvedValue([
      { networkType: "ipv4", nodeCount: 24 },
      { networkType: "ipv6", nodeCount: 6 },
    ]),
    listLastRunCountries: vi.fn().mockResolvedValue([]),
    listLastRunAsns: vi.fn().mockResolvedValue([
      { asn: 64512, asnOrganization: "Example ASN", nodeCount: 18 },
    ]),
    listLastRunStartHeights: vi.fn().mockResolvedValue([]),
    listLastRunAsnOrganizations: vi.fn().mockResolvedValue([]),
    listLastRunNodes: vi.fn().mockResolvedValue({ items: [], nextPageToken: null }),
    listNodeStatus: vi.fn().mockResolvedValue([]),
    handshake: vi.fn(),
    ping: vi.fn(),
    getAddr: vi.fn(),
    getLastBlockHeight: vi.fn(),
    getBlock: vi.fn(),
    downloadBlock: vi.fn(),
    getSuggestedBlockDownloadPath: vi.fn().mockResolvedValue("downloads/block.dat"),
    getRecentEvents: vi.fn().mockResolvedValue([]),
    ...overrides,
  };
}

describe("RiskPage", () => {
  it("renders clean risk cards without the old control deck", async () => {
    render(<RiskPage client={makeClient()} />);

    expect(await screen.findByText("Risk Library")).toBeTruthy();
    expect(screen.queryByText("Control Deck")).toBeNull();
    const identityCard = screen.getByRole("button", { name: "Open Identity Concentration Signals" });
    expect(identityCard.className).toContain("cursor-pointer");
    expect(screen.getByText("Identity Concentration Signals")).toBeTruthy();
    expect(screen.getByText("Sybil-oriented evidence")).toBeTruthy();
    expect(screen.getByText("Top ASN share")).toBeTruthy();
    expect(screen.getByText("Mocked details")).toBeTruthy();
    expect(screen.getByText("Decentralization Review")).toBeTruthy();
    expect(screen.queryByText("Sybil attack detected")).toBeNull();
  });

  it("opens a selected risk card into a detail page with a clickable menu", async () => {
    render(<RiskPage client={makeClient()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Open Identity Concentration Signals" }));

    expect(screen.getByRole("navigation", { name: "Identity Concentration Signals detail menu" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Current read" }).getAttribute("href")).toBe("#read");
    expect(screen.getByRole("link", { name: "Mocked data" }).getAttribute("href")).toBe("#mocked-data");
    expect(screen.getByText("Example analyst notes")).toBeTruthy();
    expect(screen.getByText("Prefix cluster A: 14 endpoints, 92% matching service tuple.")).toBeTruthy();
    expect(screen.getByText("Crawler data cannot prove real-world operator identity.")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Cards" }));

    expect(screen.getByText("Risk Library")).toBeTruthy();
  });

  it("shows an error state when risk loading fails", async () => {
    render(
      <RiskPage
        client={makeClient({
          listCrawlRuns: vi.fn().mockRejectedValue(new Error("api unavailable")),
        })}
      />,
    );

    expect(await screen.findByText("Risk metrics failed to load: api unavailable")).toBeTruthy();
  });
});
