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
    expect(screen.getByRole("textbox", { name: "Filter risk topics" })).toBeTruthy();
    const identityCard = screen.getByRole("button", { name: "Open Identity Concentration Signals" });
    expect(identityCard.className).toContain("cursor-pointer");
    expect(screen.getByText("Identity Concentration Signals")).toBeTruthy();
    expect(screen.getByText("Sybil-oriented evidence")).toBeTruthy();
    expect(screen.getByText("Evidence topics")).toBeTruthy();
    expect(screen.getByText("No verdict claims")).toBeTruthy();
    expect(screen.getByText("Draft article")).toBeTruthy();
    expect(screen.getByText("Decentralization Review")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Open Decentralization Review" })).toBeNull();
    expect(screen.getByLabelText("Decentralization Review is not available yet")).toBeTruthy();
    expect(screen.getAllByText("Coming soon").length).toBeGreaterThanOrEqual(3);
    expect(screen.queryByText("Top ASN share")).toBeNull();
    expect(document.body.textContent).not.toMatch(/\b(attacker|malicious)\b/i);
    expect(document.body.textContent).not.toMatch(/shared control|controlled by one entity/i);
  });

  it("filters the risk topic cards from the header", async () => {
    render(<RiskPage client={makeClient()} />);

    expect(await screen.findByText("Risk Library")).toBeTruthy();

    fireEvent.change(screen.getByRole("textbox", { name: "Filter risk topics" }), {
      target: { value: "sybil" },
    });

    expect(screen.getByText("Identity Concentration Signals")).toBeTruthy();
    expect(screen.queryByText("Observation Confidence")).toBeNull();

    fireEvent.change(screen.getByRole("textbox", { name: "Filter risk topics" }), {
      target: { value: "confidence" },
    });

    expect(screen.queryByText("Identity Concentration Signals")).toBeNull();
    expect(screen.getByText("Observation Confidence")).toBeTruthy();

    fireEvent.change(screen.getByRole("textbox", { name: "Filter risk topics" }), {
      target: { value: "not-a-topic" },
    });

    expect(screen.getByText('No risk topics match "not-a-topic".')).toBeTruthy();
  });

  it("opens a selected risk card into a detail page with a clickable menu", async () => {
    const scrollIntoView = vi.fn();
    window.HTMLElement.prototype.scrollIntoView = scrollIntoView;
    render(<RiskPage client={makeClient()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Open Identity Concentration Signals" }));

    expect(screen.getByRole("navigation", { name: "Identity Concentration Signals on this page" })).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Identity Concentration Signals compact section menu" })).toBeTruthy();
    expect(screen.getByText("On this page")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Overview" }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Overview" })[0].getAttribute("aria-current")).toBe("true");
    expect(screen.getAllByRole("button", { name: "Dashboard" }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "References" }).length).toBeGreaterThan(0);
    const sectionsButton = screen.getByRole("button", { name: /Sections/ });
    expect(sectionsButton.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(sectionsButton);
    expect(sectionsButton.getAttribute("aria-expanded")).toBe("true");
    fireEvent.pointerDown(screen.getByText("Top clusters to review"));
    expect(sectionsButton.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(sectionsButton);
    expect(sectionsButton.getAttribute("aria-expanded")).toBe("true");
    const overviewButton = screen.getAllByRole("button", { name: "Overview" })[0];
    expect(overviewButton.className).toContain("cursor-pointer");
    expect(screen.queryByRole("link", { name: "Overview" })).toBeNull();
    expect(screen.getByText("Verified nodes")).toBeTruthy();
    expect(screen.getByText("Top clusters to review")).toBeTruthy();
    expect(screen.getByText("A Sybil problem starts when one real participant can look like many independent participants. In a peer-to-peer network this matters because software often makes decisions from the identities it can see: which peers to connect to, which addresses to learn from, and how diverse the surrounding network appears.")).toBeTruthy();
    expect(screen.getAllByText("Top ASN share").length).toBeGreaterThan(0);
    expect(screen.getByText("ASN AS64512: Example Hosting ASN")).toBeTruthy();
    expect(screen.getByText("The Sybil Attack - John R. Douceur")).toBeTruthy();
    expect(screen.getByText("Bitcoin: A Peer-to-Peer Electronic Cash System")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/\b(attacker|malicious)\b/i);
    expect(document.body.textContent).not.toMatch(/shared control|controlled by one entity/i);

    fireEvent.click(overviewButton);

    expect(window.location.hash).toBe("");
    expect(sectionsButton.getAttribute("aria-expanded")).toBe("false");
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });

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
