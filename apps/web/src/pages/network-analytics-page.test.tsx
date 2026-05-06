// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";
import type { CrawlRunListItem } from "@/lib/api/types";

import {
  NETWORK_ANALYTICS_LIVE_POLL_INTERVAL_MS,
  NetworkAnalyticsPage,
} from "./network-analytics-page";

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
    listLastRunServices: vi.fn().mockResolvedValue([]),
    listLastRunProtocolVersions: vi.fn().mockResolvedValue([]),
    listLastRunUserAgents: vi.fn().mockResolvedValue([]),
    listLastRunNetworkTypes: vi.fn().mockResolvedValue([]),
    listLastRunCountries: vi.fn().mockResolvedValue([]),
    listLastRunAsns: vi.fn().mockResolvedValue([]),
    listLastRunStartHeights: vi.fn().mockResolvedValue([]),
    listLastRunAsnOrganizations: vi.fn().mockResolvedValue([]),
    listLastRunNodes: vi.fn().mockResolvedValue({ items: [], nextPageToken: null }),
    listNodeStatus: vi.fn().mockResolvedValue([]),
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

  it("shows the latest active run on the globe even before a finished snapshot exists", async () => {
    const getCrawlRun = vi.fn().mockResolvedValue({
      run: {
        runId: "crawl-local-active",
        phase: "crawling",
        startedAt: "2026-05-06T00:02:34Z",
        lastCheckpointedAt: "2026-05-06T00:17:34Z",
        stopReason: null,
        failureReason: null,
        scheduledTasks: 34257,
        successfulHandshakes: 1378,
        failedTasks: 22879,
        uniqueNodes: 231684,
        persistedObservationRows: 1481,
        successPct: 4.02,
        scheduledPct: 14.79,
        unscheduledGap: 197427,
      },
      checkpoints: [],
      failureCounts: [],
      networkOutcomes: [],
    });
    const client = makeClient({
      listCrawlRuns: vi.fn().mockResolvedValue([
        {
          runId: "crawl-local-active",
          phase: "crawling",
          startedAt: "2026-05-06T00:02:34Z",
          lastCheckpointedAt: "2026-05-06T00:17:34Z",
          stopReason: null,
          failureReason: null,
          scheduledTasks: 34257,
          successfulHandshakes: 1378,
          failedTasks: 22879,
          uniqueNodes: 231684,
          persistedObservationRows: 1481,
          successPct: 4.02,
          scheduledPct: 14.79,
          unscheduledGap: 197427,
        },
        {
          runId: "crawl-older-finished",
          phase: "finished",
          startedAt: "2026-05-05T00:02:34Z",
          lastCheckpointedAt: "2026-05-05T00:17:34Z",
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
      listLastRunAsns: vi.fn().mockImplementation((_limit, options) => {
        if (options?.phase === "any") {
          return Promise.resolve([
            { asn: 64512, asnOrganization: "Active ASN", nodeCount: 27 },
          ]);
        }

        return Promise.resolve([]);
      }),
      listLastRunCountries: vi.fn().mockImplementation((_limit, options) => {
        if (options?.phase === "any") {
          return Promise.resolve([
            { country: "US", nodeCount: 323 },
            { country: "DE", nodeCount: 115 },
          ]);
        }

        return Promise.resolve([]);
      }),
      getCrawlRun,
    });

    render(<NetworkAnalyticsPage client={client} />);

    expect(await screen.findByRole("img", { name: /Interactive 3D globe/i })).toBeTruthy();
    expect(await screen.findByText("Background sweep active")).toBeTruthy();
    await waitFor(() => expect(getCrawlRun).toHaveBeenCalledWith("crawl-local-active"));
    expect(screen.queryByText("Crawler data warming up")).toBeNull();
    expect(screen.queryByText("Latest Finished Snapshot Not Ready")).toBeNull();
    expect(screen.getByText("Top ASN Distribution")).toBeTruthy();
    expect(screen.getByText("Top Country Distribution")).toBeTruthy();
  });

  it("polls only the latest-run snapshot surface", async () => {
    vi.useFakeTimers();

    try {
      const listCrawlRuns = vi
        .fn()
        .mockResolvedValueOnce([
          makeRunSummary({ runId: "crawl-active-1", scheduledTasks: 10, successfulHandshakes: 2 }),
        ])
        .mockResolvedValueOnce([
          makeRunSummary({ runId: "crawl-active-2", scheduledTasks: 20, successfulHandshakes: 4 }),
        ]);
      const getCrawlRun = vi.fn().mockImplementation((runId: string) =>
        Promise.resolve({
          run: makeRunSummary({ runId }),
          checkpoints: [],
          failureCounts: [],
          networkOutcomes: [],
        }),
      );
      const listLastRunAsns = vi.fn().mockImplementation((_limit, options) => {
        if (options?.phase === "any") {
          return Promise.resolve([
            { asn: 64512, asnOrganization: "Active ASN", nodeCount: 9 },
          ]);
        }

        return Promise.resolve([{ asn: 64513, asnOrganization: "Finished ASN", nodeCount: 4 }]);
      });
      const listLastRunCountries = vi.fn().mockImplementation((limit, options) => {
        if (options?.phase === "any") {
          return Promise.resolve([
            { country: "US", nodeCount: limit === 32 ? 12 : 7 },
            { country: "DE", nodeCount: 5 },
          ]);
        }

        return Promise.resolve([{ country: "GB", nodeCount: 3 }]);
      });
      const listLastRunNetworkTypes = vi.fn().mockResolvedValue([{ networkType: "ipv4", nodeCount: 4 }]);
      const client = makeClient({
        listCrawlRuns,
        getCrawlRun,
        listLastRunAsns,
        listLastRunCountries,
        listLastRunNetworkTypes,
        listLastRunStartHeights: vi.fn().mockResolvedValue([{ startHeight: 900000, nodeCount: 4 }]),
      });

      render(<NetworkAnalyticsPage client={client} />);

      await flushAsyncWork();
      expect(getCrawlRun).toHaveBeenCalledWith("crawl-active-1");
      expect(screen.getByText("crawl-active-1")).toBeTruthy();
      expect(listLastRunNetworkTypes).toHaveBeenCalledWith(10, { phase: "any" });
      expect(listLastRunNetworkTypes).toHaveBeenCalledTimes(2);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(NETWORK_ANALYTICS_LIVE_POLL_INTERVAL_MS);
      });
      await flushAsyncWork();

      expect(getCrawlRun).toHaveBeenCalledWith("crawl-active-2");
      expect(screen.getByText("crawl-active-2")).toBeTruthy();
      expect(listLastRunAsns).toHaveBeenCalledWith(10, { phase: "any" });
      expect(listLastRunNetworkTypes).toHaveBeenCalledWith(10, { phase: "any" });
      expect(listLastRunCountries).toHaveBeenCalledWith(32, { phase: "any" });
      expect(listLastRunNetworkTypes).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("renders a focused overview first, then shows the risk metrics", async () => {
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
      listLastRunAsns: vi.fn().mockResolvedValue([
        {
          asn: 64512,
          asnOrganization: "Example ASN",
          nodeCount: 18,
        },
      ]),
      listLastRunServices: vi.fn().mockResolvedValue([{ services: "1033", nodeCount: 18 }]),
      listLastRunNetworkTypes: vi.fn().mockResolvedValue([
        { networkType: "ipv4", nodeCount: 24 },
        { networkType: "ipv6", nodeCount: 6 },
      ]),
      listLastRunCountries: vi.fn().mockResolvedValue([
        { country: "US", nodeCount: 14 },
        { country: "DE", nodeCount: 10 },
      ]),
      listLastRunStartHeights: vi.fn().mockResolvedValue([
        { startHeight: 900000, nodeCount: 15 },
        { startHeight: 899999, nodeCount: 10 },
        { startHeight: 900001, nodeCount: 5 },
      ]),
      listLastRunNodes: vi.fn().mockResolvedValue({
        items: [
          {
            endpoint: "1.1.1.7:8333",
            networkType: "ipv4",
            protocolVersion: 70016,
            userAgent: "/Satoshi:27.0.0/",
            services: "1033",
            startHeight: 900000,
            country: "US",
            asn: 64512,
            asnOrganization: "Example ASN",
          },
        ],
        nextPageToken: null,
      }),
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
    expect(screen.getByText("Network Risk Snapshot")).toBeTruthy();
    expect(screen.queryByText("Checkpoint Rail")).toBeNull();
    expect(screen.getByRole("button", { name: "Network Analytics overview" })).toBeTruthy();
    expect(screen.queryByText("Block Height")).toBeNull();
    expect(screen.getByRole("img", { name: /Interactive 3D globe/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Zoom in globe" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reset globe view" })).toBeTruthy();
    expect(screen.getByText("Network Type Distribution")).toBeTruthy();
    expect(screen.getByText("Height Consensus")).toBeTruthy();
    expect(screen.getByText("Top ASN Distribution")).toBeTruthy();
    expect(screen.getByText("Top Country Distribution")).toBeTruthy();
    expect(screen.queryByText("Node Inventory")).toBeNull();
    expect(screen.queryByRole("button", { name: "Top ASNs" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Verification" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Risk" }));
    expect(await screen.findByText("Decentralization Score")).toBeTruthy();
    expect(screen.getByText("Eclipse Exposure (Proxy)")).toBeTruthy();
    expect(screen.getByText("Observation Confidence")).toBeTruthy();
    expect(screen.getByText("Transport Diversity")).toBeTruthy();
    expect(scoreCardValue("Decentralization Score")).toBe("37");
    expect(scoreCardValue("Eclipse Exposure (Proxy)")).toBe("65");
    expect(scoreCardValue("Observation Confidence")).toBe("58");
    expect(scoreCardValue("Transport Diversity")).toBe("72");
    expect(screen.getByRole("button", { name: "Decentralization Score score explanation" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Eclipse Exposure (Proxy) score explanation" })).toBeTruthy();
    expect(screen.queryByText("What This Means")).toBeNull();
    expect(screen.queryByText("Risk Drivers")).toBeNull();
    expect(screen.queryByText("Last-Run Inputs")).toBeNull();
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

  it("renders the home-page API spec and agent guide actions", async () => {
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
      listLastRunAsns: vi.fn().mockResolvedValue([{ asn: 64512, asnOrganization: "Example ASN", nodeCount: 18 }]),
      listLastRunServices: vi.fn().mockResolvedValue([{ services: "1033", nodeCount: 18 }]),
      listLastRunNetworkTypes: vi.fn().mockResolvedValue([{ networkType: "ipv4", nodeCount: 24 }]),
      listLastRunCountries: vi.fn().mockResolvedValue([{ country: "US", nodeCount: 14 }]),
      listLastRunStartHeights: vi.fn().mockResolvedValue([{ startHeight: 900000, nodeCount: 15 }]),
      listLastRunNodes: vi.fn().mockResolvedValue({ items: [], nextPageToken: null }),
    });
    const onOpenApiPage = vi.fn();
    const onOpenAgentGuidePage = vi.fn();

    render(
      <NetworkAnalyticsPage
        client={client}
        onOpenApiPage={onOpenApiPage}
        onOpenAgentGuidePage={onOpenAgentGuidePage}
      />,
    );

    expect(await screen.findByText("Integration Docs")).toBeTruthy();
    expect(screen.queryByText("agents.md")).toBeNull();
    expect(screen.queryByText(/Start with latest run, then drill down/i)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Open API spec" }));
    expect(onOpenApiPage).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "Open agent guide" }));
    expect(onOpenAgentGuidePage).toHaveBeenCalledTimes(1);
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

async function flushAsyncWork() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function makeRunSummary(overrides: Partial<CrawlRunListItem> = {}): CrawlRunListItem {
  return {
    runId: "crawl-active",
    phase: "crawling",
    startedAt: "2026-05-06T00:02:34Z",
    lastCheckpointedAt: "2026-05-06T00:17:34Z",
    stopReason: null,
    failureReason: null,
    scheduledTasks: 10,
    successfulHandshakes: 2,
    failedTasks: 8,
    uniqueNodes: 20,
    persistedObservationRows: 10,
    successPct: 20,
    scheduledPct: 50,
    unscheduledGap: 10,
    ...overrides,
  };
}
