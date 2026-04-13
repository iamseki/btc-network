// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const mockHandshake = vi.fn();
const mockPing = vi.fn();
const mockGetAddr = vi.fn();
const mockGetLastBlockHeight = vi.fn();
const mockGetBlock = vi.fn();
const mockDownloadBlock = vi.fn();
const mockListCrawlRuns = vi.fn();
const mockGetCrawlRun = vi.fn();
const mockCountNodesByAsn = vi.fn();
const mockGetSuggestedBlockDownloadPath = vi.fn();
const mockGetRecentEvents = vi.fn();
const originalInnerWidth = window.innerWidth;

vi.mock("./lib/api", () => ({
  getAppClient: () => ({
    listCrawlRuns: mockListCrawlRuns,
    getCrawlRun: mockGetCrawlRun,
    countNodesByAsn: mockCountNodesByAsn,
    handshake: mockHandshake,
    ping: mockPing,
    getAddr: mockGetAddr,
    getLastBlockHeight: mockGetLastBlockHeight,
    getBlock: mockGetBlock,
    downloadBlock: mockDownloadBlock,
    getSuggestedBlockDownloadPath: mockGetSuggestedBlockDownloadPath,
    getRecentEvents: mockGetRecentEvents,
  }),
}));

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  mockHandshake.mockReset();
  mockPing.mockReset();
  mockGetAddr.mockReset();
  mockGetLastBlockHeight.mockReset();
  mockGetBlock.mockReset();
  mockDownloadBlock.mockReset();
  mockListCrawlRuns.mockReset();
  mockGetCrawlRun.mockReset();
  mockCountNodesByAsn.mockReset();
  mockGetSuggestedBlockDownloadPath.mockReset();
  mockGetRecentEvents.mockReset();
  mockListCrawlRuns.mockResolvedValue([]);
  mockGetCrawlRun.mockResolvedValue({
    run: {
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
    checkpoints: [],
    failureCounts: [],
    networkOutcomes: [],
  });
  mockCountNodesByAsn.mockResolvedValue([]);
  mockGetSuggestedBlockDownloadPath.mockResolvedValue(
    "downloads/blk-00000000-8ce26f.dat",
  );
});

beforeEach(() => {
  window.localStorage.clear();
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    writable: true,
    value: originalInnerWidth,
  });
  mockGetSuggestedBlockDownloadPath.mockResolvedValue(
    "downloads/blk-00000000-8ce26f.dat",
  );
  mockListCrawlRuns.mockResolvedValue([]);
  mockGetCrawlRun.mockResolvedValue({
    run: {
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
    checkpoints: [],
    failureCounts: [],
    networkOutcomes: [],
  });
  mockCountNodesByAsn.mockResolvedValue([]);
});

function setViewportWidth(width: number) {
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    writable: true,
    value: width,
  });
}

function mockCrawlerPreviewRun() {
  mockListCrawlRuns.mockResolvedValue([
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
  mockGetCrawlRun.mockResolvedValue({
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
    failureCounts: [],
    networkOutcomes: [],
  });
}

describe("App sidebar shell", () => {
  it("renders collapsed by default", () => {
    render(<App />);

    expect(screen.queryByText("Menu")).toBeNull();
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Network Analytics" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Network Analytics" })).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Network Analytics Views" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Top ASNs" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Verification" })).toBeTruthy();
    expect(screen.queryByText("Session Log")).toBeNull();
    expect(screen.queryByText(/Frontend loaded\./)).toBeNull();
  });

  it("expands the sidebar when the trigger is clicked", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));

    expect(screen.getByText("Menu")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeTruthy();
  });

  it("expands the desktop shell width when the sidebar is opened", () => {
    const { container } = render(<App />);

    const shell = container.firstElementChild?.firstElementChild;
    expect(shell?.className).toContain("md:grid-cols-[72px_minmax(0,1fr)]");

    fireEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));

    expect(shell?.className).toContain("md:grid-cols-[252px_minmax(0,1fr)]");
  });

  it("opens and closes the mobile navigation drawer", () => {
    setViewportWidth(390);
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Open navigation" }));

    expect(screen.getByText("Menu")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Close navigation overlay" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Close navigation overlay" }));

    expect(screen.queryByText("Menu")).toBeNull();
    expect(screen.queryByRole("button", { name: "Close navigation overlay" })).toBeNull();
  });

  it("closes the mobile drawer after selecting a page", () => {
    setViewportWidth(390);
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Open navigation" }));
    fireEvent.click(screen.getByRole("button", { name: "Chain Height" }));

    expect(screen.getByRole("heading", { name: "Chain Height" })).toBeTruthy();
    expect(screen.queryByText("Menu")).toBeNull();
    expect(screen.queryByRole("button", { name: "Close navigation overlay" })).toBeNull();
  });

  it("keeps separate trigger semantics for mobile and desktop navigation controls", () => {
    render(<App />);

    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open navigation" })).toBeTruthy();
  });

  it("switches the visible page from the sidebar", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Crawler Runs" }));

    expect(screen.getByRole("heading", { name: "Crawler Runs" })).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Crawler Runs Views" })).toBeTruthy();
    expect(screen.getByText(/latest public snapshot/i)).toBeTruthy();
  });

  it("renders the mocked commercial API page from the analytics navigation", async () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Network Risk API" }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Network Risk API" })).toBeTruthy();
    });
    expect(screen.getByText("Why teams buy this")).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Crawler Runs Views" })).toBeNull();
  });

  it("opens and closes the header crawl preview from the pulse in the header rail", async () => {
    mockCrawlerPreviewRun();

    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Show latest snapshot preview" })).toHaveProperty(
        "disabled",
        false,
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Show latest snapshot preview" }));
    expect(await screen.findByText("Crawler Snapshot")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Close latest snapshot preview" }));
    await waitFor(() => {
      expect(screen.queryByText("Crawler Snapshot")).toBeNull();
    });
  });

  it("persists the crawl pulse cycle anchor in local storage", async () => {
    mockCrawlerPreviewRun();

    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Show latest snapshot preview" })).toHaveProperty(
        "disabled",
        false,
      );
    });

    await waitFor(() => {
      const storedValue = window.localStorage.getItem(
        "btc-network:crawler-signal-cycle:v2:crawl-2",
      );
      expect(storedValue).toBeTruthy();
      const parsed = JSON.parse(storedValue ?? "{}") as {
        cycleAnchorMs?: number;
        lastSeenAtMs?: number;
      };
      expect(parsed.cycleAnchorMs ?? 0).toBeGreaterThan(0);
      expect(parsed.lastSeenAtMs ?? 0).toBeGreaterThan(0);
    });
  });

  it("opens the network analytics page when the header crawl preview is clicked", async () => {
    mockCrawlerPreviewRun();

    render(<App />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Show latest snapshot preview" })).toHaveProperty(
        "disabled",
        false,
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Show latest snapshot preview" }));
    fireEvent.click(await screen.findByRole("button", { name: "Open network analytics from snapshot" }));

    expect(await screen.findByRole("heading", { name: "Network Analytics" })).toBeTruthy();
    await waitFor(() => {
      expect(screen.getByText("Network Risk Snapshot")).toBeTruthy();
    });
  });

  it("keeps crawler runs focused on inspection while the snapshot stays in the header preview", async () => {
    mockCrawlerPreviewRun();

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Crawler Runs" }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Crawler Runs" })).toBeTruthy();
    });
    expect(screen.queryByText("Crawler Snapshot")).toBeNull();
    expect(screen.queryByRole("button", { name: "Open Latest Snapshot" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Hide Latest Snapshot" })).toBeNull();
  });

  it("shows page-specific sub-navigation for analytics pages", () => {
    render(<App />);

    expect(screen.getAllByRole("button", { name: "Network Analytics" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Crawler Runs" })).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Top ASNs" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Crawler Runs" }));

    expect(screen.getByRole("button", { name: "Checkpoints" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Failures" })).toBeTruthy();
  });

  it("updates the header eyebrow when the analytics sub-navigation changes", () => {
    render(<App />);

    expect(screen.getByTestId("page-subview-label").textContent).toBe("Overview");

    fireEvent.click(screen.getByRole("button", { name: "Top ASNs" }));
    expect(screen.getByTestId("page-subview-label").textContent).toBe("Top ASNs");

    fireEvent.click(screen.getByRole("button", { name: "Crawler Runs" }));
    fireEvent.click(screen.getByRole("button", { name: "Failures" }));
    expect(screen.getByTestId("page-subview-label").textContent).toBe("Failures");
  });

  it("requests the last block height from the headers page", async () => {
    mockGetLastBlockHeight.mockImplementation(async (_node, onProgress) => {
      onProgress?.({
        operationId: "test-op",
        node: "seed.bitnodes.io:8333",
        phase: "requesting_headers",
        roundsCompleted: 470,
        headersSeen: 938408,
        lastBatchCount: 408,
        bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
        elapsedMs: 545450,
      });

      return {
        node: "seed.bitnodes.io:8333",
        height: 938408,
        rounds: 470,
        elapsedMs: 545450,
        bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
      };
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Chain Height" }));
    fireEvent.click(screen.getByRole("button", { name: /Fetch Last Block Height/i }));

    expect(mockGetLastBlockHeight).toHaveBeenCalledWith(
      "seed.bitnodes.io:8333",
      expect.any(Function),
    );
    expect(await screen.findByRole("heading", { name: "Chain Height" })).toBeTruthy();
    expect(await screen.findByText("Height")).toBeTruthy();
    expect(await screen.findByText("Best block hash")).toBeTruthy();
    expect(await screen.findByText("Rounds")).toBeTruthy();
  });

  it("fetches peer addresses from the peer tools page", async () => {
    mockGetAddr.mockResolvedValue({
      node: "seed.bitnodes.io:8333",
      addresses: [
        { address: "127.0.0.1", port: 8333, network: "ipv4" },
        { address: "::1", port: 8333, network: "ipv6" },
      ],
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Peer Tools" }));
    fireEvent.click(screen.getByRole("button", { name: /Fetch Peer Addresses/i }));

    expect(mockGetAddr).toHaveBeenCalledWith("seed.bitnodes.io:8333");
    expect(await screen.findByText("127.0.0.1")).toBeTruthy();
    expect(await screen.findByText("::1")).toBeTruthy();
  });

  it("fetches a block summary from the blocks page", async () => {
    mockGetBlock.mockResolvedValue({
      hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      txCount: 1,
      serializedSize: 285,
      coinbaseTxDetected: true,
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Block Explorer" }));
    fireEvent.click(screen.getByRole("button", { name: /Fetch Block/i }));

    expect(mockGetBlock).toHaveBeenCalledWith(
      "seed.bitnodes.io:8333",
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
    expect(await screen.findByText("Serialized size")).toBeTruthy();
    expect(await screen.findByText("285")).toBeTruthy();
  });

  it("downloads a block from the blocks page", async () => {
    mockDownloadBlock.mockResolvedValue({
      hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      outputPath: "blk-00000000-8ce26f.dat",
      rawBytes: 285,
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Block Explorer" }));
    await screen.findByDisplayValue("downloads/blk-00000000-8ce26f.dat");
    fireEvent.click(screen.getByRole("button", { name: /Download to Host Path/i }));

    expect(mockDownloadBlock).toHaveBeenCalledWith({
      node: "seed.bitnodes.io:8333",
      hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      outputPath: "downloads/blk-00000000-8ce26f.dat",
    });
    expect(await screen.findByText("blk-00000000-8ce26f.dat")).toBeTruthy();
  });

  it("logs human-readable services after a successful handshake", async () => {
    mockHandshake.mockResolvedValue({
      node: "seed.bitnodes.io:8333",
      protocolVersion: 70016,
      services: "0x0000000000000409",
      serviceNames: ["NODE_NETWORK", "NODE_WITNESS", "NODE_NETWORK_LIMITED"],
      userAgent: "/Satoshi:28.0.0/",
      startHeight: 938408,
      relay: true,
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Connection" }));
    fireEvent.click(screen.getByRole("button", { name: "Run Handshake" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand session log" }));

    expect(
      await screen.findAllByText(
        /Handshake complete\. Services: NODE_NETWORK, NODE_WITNESS, NODE_NETWORK_LIMITED\./,
      ),
    ).toHaveLength(2);
  });

  it("refreshes the suggested host download path when the block hash changes", async () => {
    mockGetSuggestedBlockDownloadPath
      .mockResolvedValueOnce("downloads/blk-00000000-8ce26f.dat")
      .mockResolvedValueOnce("downloads/blk-ffffffff-abcdef.dat");

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Block Explorer" }));
    const blockHashInput = await screen.findByRole("textbox", { name: "Block hash" });
    fireEvent.change(blockHashInput, {
      target: {
        value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffabcdef",
      },
    });

    expect(
      await screen.findByDisplayValue("downloads/blk-ffffffff-abcdef.dat"),
    ).toBeTruthy();
  });

  it("shows the session log on non-connection pages and can expand it", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Peer Tools" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand session log" }));

    expect(
      screen.getAllByText(/Frontend loaded\. Desktop mode exposes real handshake/),
    ).toHaveLength(2);
  });

  it("clears the session log from the global panel", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Connection" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand session log" }));
    fireEvent.click(screen.getByRole("button", { name: "Clear session log" }));

    expect(screen.getByText("No events captured for this session yet.")).toBeTruthy();
  });
});
