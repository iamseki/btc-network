// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";

import { CrawlerRunsPage } from "./crawler-runs-page";

afterEach(() => {
  cleanup();
  window.localStorage.clear();
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
    listLastRunNodes: vi.fn().mockResolvedValue([]),
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

describe("CrawlerRunsPage", () => {
  it("shows an empty state when no runs are available", async () => {
    const client = makeClient({
      listCrawlRuns: vi.fn().mockResolvedValue([]),
    });

    render(<CrawlerRunsPage client={client} />);

    expect(await screen.findByText("No crawler runs persisted yet.")).toBeTruthy();
  });

  it("loads the most recent run and auto-selects its detail", async () => {
    const listRuns = vi.fn().mockResolvedValue([
      {
        runId: "crawl-2",
        phase: "completed",
        startedAt: "2026-03-30T12:00:00Z",
        lastCheckpointedAt: "2026-03-30T12:10:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 120,
        successfulHandshakes: 40,
        failedTasks: 80,
        uniqueNodes: 150,
        persistedObservationRows: 120,
        successPct: 33.33,
        scheduledPct: 80,
        unscheduledGap: 30,
      },
    ]);
    const getRun = vi.fn().mockResolvedValue({
      run: {
        runId: "crawl-2",
        phase: "completed",
        startedAt: "2026-03-30T12:00:00Z",
        lastCheckpointedAt: "2026-03-30T12:10:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 120,
        successfulHandshakes: 40,
        failedTasks: 80,
        uniqueNodes: 150,
        persistedObservationRows: 120,
        successPct: 33.33,
        scheduledPct: 80,
        unscheduledGap: 30,
      },
      checkpoints: [
        {
          phase: "completed",
          checkpointedAt: "2026-03-30T12:10:00Z",
          checkpointSequence: 4,
          stopReason: "idle timeout",
          failureReason: null,
          frontierSize: 0,
          inFlightWork: 0,
          scheduledTasks: 120,
          successfulHandshakes: 40,
          failedTasks: 80,
          uniqueNodes: 150,
          persistedObservationRows: 120,
          writerBacklog: 0,
        },
      ],
      failureCounts: [{ classification: "connect", observations: 50 }],
      networkOutcomes: [
        {
          networkType: "ipv4",
          observations: 100,
          verifiedNodes: 40,
          failedNodes: 60,
          verifiedPct: 40,
        },
      ],
    });
    const client = makeClient({
      listCrawlRuns: listRuns,
      getCrawlRun: getRun,
    });

    render(<CrawlerRunsPage client={client} />);

    await waitFor(() => {
      expect(getRun).toHaveBeenCalledWith("crawl-2");
    });
    expect(screen.queryByText("Latest Snapshot")).toBeNull();
    expect(screen.queryByText("Crawler Snapshot")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Failures" }));
    expect(await screen.findByText("Failure Mix")).toBeTruthy();
    expect((await screen.findAllByText("connect")).length).toBeGreaterThan(0);
  });

  it("shows an error state when the API request fails", async () => {
    const client = makeClient({
      listCrawlRuns: vi.fn().mockRejectedValue(new Error("backend offline")),
    });

    render(<CrawlerRunsPage client={client} />);

    expect(
      await screen.findByText("Crawler runs failed to load: backend offline"),
    ).toBeTruthy();
  });

  it("loads a different run when the compact run picker selection changes", async () => {
    const getRun = vi
      .fn()
      .mockResolvedValueOnce({
        run: {
          runId: "crawl-1",
          phase: "completed",
          startedAt: "2026-03-30T12:00:00Z",
          lastCheckpointedAt: "2026-03-30T12:10:00Z",
          stopReason: "idle timeout",
          failureReason: null,
          scheduledTasks: 90,
          successfulHandshakes: 30,
          failedTasks: 60,
          uniqueNodes: 110,
          persistedObservationRows: 90,
          successPct: 33.33,
          scheduledPct: 81.82,
          unscheduledGap: 20,
        },
        checkpoints: [],
        failureCounts: [],
        networkOutcomes: [],
      })
      .mockResolvedValueOnce({
        run: {
          runId: "crawl-2",
          phase: "failed",
          startedAt: "2026-03-30T13:00:00Z",
          lastCheckpointedAt: "2026-03-30T13:10:00Z",
          stopReason: null,
          failureReason: "shutdown grace period elapsed",
          scheduledTasks: 50,
          successfulHandshakes: 10,
          failedTasks: 40,
          uniqueNodes: 80,
          persistedObservationRows: 50,
          successPct: 20,
          scheduledPct: 62.5,
          unscheduledGap: 30,
        },
        checkpoints: [],
        failureCounts: [{ classification: "handshake", observations: 20 }],
        networkOutcomes: [],
      });
    const client = makeClient({
      listCrawlRuns: vi.fn().mockResolvedValue([
        {
          runId: "crawl-1",
          phase: "completed",
          startedAt: "2026-03-30T12:00:00Z",
          lastCheckpointedAt: "2026-03-30T12:10:00Z",
          stopReason: "idle timeout",
          failureReason: null,
          scheduledTasks: 90,
          successfulHandshakes: 30,
          failedTasks: 60,
          uniqueNodes: 110,
          persistedObservationRows: 90,
          successPct: 33.33,
          scheduledPct: 81.82,
          unscheduledGap: 20,
        },
        {
          runId: "crawl-2",
          phase: "failed",
          startedAt: "2026-03-30T13:00:00Z",
          lastCheckpointedAt: "2026-03-30T13:10:00Z",
          stopReason: null,
          failureReason: "shutdown grace period elapsed",
          scheduledTasks: 50,
          successfulHandshakes: 10,
          failedTasks: 40,
          uniqueNodes: 80,
          persistedObservationRows: 50,
          successPct: 20,
          scheduledPct: 62.5,
          unscheduledGap: 30,
        },
      ]),
      getCrawlRun: getRun,
    });

    render(<CrawlerRunsPage client={client} />);

    await waitFor(() => {
      expect(getRun).toHaveBeenCalledWith("crawl-1");
    });
    fireEvent.click(getRunSelectionButton("crawl-2"));

    await waitFor(() => {
      expect(getRun).toHaveBeenCalledWith("crawl-2");
    });
    fireEvent.click(await screen.findByRole("button", { name: "Failures" }));
    expect(await screen.findByText("Failure Mix")).toBeTruthy();
    expect((await screen.findAllByText("handshake")).length).toBeGreaterThan(0);
  });

  it("keeps crawler runs focused on run inspection without a duplicate snapshot section", async () => {
    const getRun = vi.fn().mockResolvedValue({
      run: {
        runId: "crawl-3",
        phase: "completed",
        startedAt: "2026-03-30T14:00:00Z",
        lastCheckpointedAt: "2026-03-30T14:05:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 140,
        successfulHandshakes: 52,
        failedTasks: 88,
        uniqueNodes: 170,
        persistedObservationRows: 140,
        successPct: 37.14,
        scheduledPct: 82.35,
        unscheduledGap: 30,
      },
      checkpoints: [
        {
          phase: "completed",
          checkpointedAt: "2026-03-30T14:05:00Z",
          checkpointSequence: 5,
          stopReason: "idle timeout",
          failureReason: null,
          frontierSize: 0,
          inFlightWork: 0,
          scheduledTasks: 140,
          successfulHandshakes: 52,
          failedTasks: 88,
          uniqueNodes: 170,
          persistedObservationRows: 140,
          writerBacklog: 0,
        },
      ],
      failureCounts: [],
      networkOutcomes: [],
    });
    const client = makeClient({
      listCrawlRuns: vi.fn().mockResolvedValue([
        {
          runId: "crawl-3",
          phase: "completed",
          startedAt: "2026-03-30T14:00:00Z",
          lastCheckpointedAt: "2026-03-30T14:05:00Z",
          stopReason: "idle timeout",
          failureReason: null,
          scheduledTasks: 140,
          successfulHandshakes: 52,
          failedTasks: 88,
          uniqueNodes: 170,
          persistedObservationRows: 140,
          successPct: 37.14,
          scheduledPct: 82.35,
          unscheduledGap: 30,
        },
      ]),
      getCrawlRun: getRun,
    });

    render(
      <CrawlerRunsPage client={client} />,
    );

    expect((await screen.findAllByText("Selected Run")).length).toBeGreaterThan(0);
    expect(screen.queryByText("Latest Snapshot")).toBeNull();
    expect(screen.queryByText("Crawler Snapshot")).toBeNull();
    expect(screen.queryByRole("button", { name: "Open Latest Snapshot" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Hide Latest Snapshot" })).toBeNull();
  });
});

function getRunSelectionButton(runId: string): HTMLButtonElement {
  return screen.getByRole("button", { name: `Select run ${runId}` }) as HTMLButtonElement;
}
