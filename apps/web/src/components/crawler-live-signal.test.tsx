// @vitest-environment jsdom

import { renderHook, act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { CrawlRunDetail } from "@/lib/api/types";

import { CrawlerLiveSignal, type CrawlerSignalPlayback, useCrawlerSignalPlayback } from "./crawler-live-signal";

const STORAGE_KEY = "btc-network:crawler-signal-cycle:v2:crawl-demo";
const IDLE_WINDOW_MS = 15 * 60 * 1000;
const SHORT_GAP_MS = 2 * 60 * 1000;

const DETAIL = {
  run: {
    runId: "crawl-demo",
    phase: "completed",
    startedAt: "2026-03-31T18:00:00Z",
    lastCheckpointedAt: "2026-03-31T18:04:58Z",
    stopReason: "idle timeout",
    failureReason: null,
    scheduledTasks: 23642,
    successfulHandshakes: 9847,
    failedTasks: 13795,
    uniqueNodes: 24816,
    persistedObservationRows: 23642,
    successPct: 41.65,
    scheduledPct: 95.27,
    unscheduledGap: 1174,
  },
  checkpoints: [
    {
      phase: "bootstrapping",
      checkpointedAt: "2026-03-31T18:01:28Z",
      checkpointSequence: 1,
      stopReason: null,
      failureReason: null,
      frontierSize: 17576,
      inFlightWork: 812,
      scheduledTasks: 6482,
      successfulHandshakes: 2714,
      failedTasks: 3768,
      uniqueNodes: 11240,
      persistedObservationRows: 6482,
      writerBacklog: 94,
    },
    {
      phase: "steady_state",
      checkpointedAt: "2026-03-31T18:03:12Z",
      checkpointSequence: 2,
      stopReason: null,
      failureReason: null,
      frontierSize: 6128,
      inFlightWork: 391,
      scheduledTasks: 17148,
      successfulHandshakes: 7162,
      failedTasks: 9986,
      uniqueNodes: 21910,
      persistedObservationRows: 17148,
      writerBacklog: 41,
    },
    {
      phase: "completed",
      checkpointedAt: "2026-03-31T18:04:58Z",
      checkpointSequence: 3,
      stopReason: "idle timeout",
      failureReason: null,
      frontierSize: 1174,
      inFlightWork: 0,
      scheduledTasks: 23642,
      successfulHandshakes: 9847,
      failedTasks: 13795,
      uniqueNodes: 24816,
      persistedObservationRows: 23642,
      writerBacklog: 0,
    },
  ],
  failureCounts: [],
  networkOutcomes: [],
} satisfies CrawlRunDetail;

const PLAYBACK = {
  currentSummary: {
    successfulHandshakes: DETAIL.run.successfulHandshakes,
    scheduledTasks: DETAIL.run.scheduledTasks,
  },
  finalSummary: {
    successfulHandshakes: DETAIL.run.successfulHandshakes,
    scheduledTasks: DETAIL.run.scheduledTasks,
  },
  playbackSnapshot: {
    phase: "steady_state",
    checkpointSequence: 3,
    checkpointedAt: DETAIL.run.lastCheckpointedAt,
    frontierSize: 1174,
    inFlightWork: 0,
    scheduledTasks: DETAIL.run.scheduledTasks,
    successfulHandshakes: DETAIL.run.successfulHandshakes,
    failedTasks: DETAIL.run.failedTasks,
    uniqueNodes: DETAIL.run.uniqueNodes,
    persistedObservationRows: DETAIL.run.persistedObservationRows,
    writerBacklog: 0,
  },
  finalSnapshot: {
    phase: "completed",
    checkpointSequence: 3,
    checkpointedAt: DETAIL.run.lastCheckpointedAt,
    frontierSize: 1174,
    inFlightWork: 0,
    scheduledTasks: DETAIL.run.scheduledTasks,
    successfulHandshakes: DETAIL.run.successfulHandshakes,
    failedTasks: DETAIL.run.failedTasks,
    uniqueNodes: DETAIL.run.uniqueNodes,
    persistedObservationRows: DETAIL.run.persistedObservationRows,
    writerBacklog: 0,
  },
  markers: [
    { phase: "bootstrapping", sequence: 1, progressRatio: 0.33 },
    { phase: "steady_state", sequence: 2, progressRatio: 0.66 },
    { phase: "completed", sequence: 3, progressRatio: 1 },
  ],
  elapsedMs: 120_000,
  loopDurationMs: 300_000,
  loopRatio: 0.4,
  cycleElapsedMs: 120_000,
  visualLoopRatio: 0.55,
  isLive: true,
  startedAt: "2026-04-01T12:00:00Z",
  completedAt: "2026-04-01T12:05:00Z",
} satisfies CrawlerSignalPlayback;

describe("useCrawlerSignalPlayback", () => {
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    window.localStorage.clear();
  });

  it("starts live on first visit, rests after the active window, and resumes after the idle window", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-01T12:00:00Z"));

    const { result } = renderHook(() => useCrawlerSignalPlayback(DETAIL));

    expect(result.current).not.toBeNull();
    expect(result.current?.isLive).toBe(true);

    const loopDurationMs = result.current!.loopDurationMs;

    act(() => {
      vi.advanceTimersByTime(loopDurationMs + 1_000);
    });

    expect(result.current?.isLive).toBe(false);
    const restingVisualLoopRatio = result.current?.visualLoopRatio;

    act(() => {
      vi.advanceTimersByTime(2_000);
    });

    expect(result.current?.isLive).toBe(false);
    expect(result.current?.visualLoopRatio).not.toBe(restingVisualLoopRatio);
    expect(result.current?.loopRatio).toBe(1);

    act(() => {
      vi.advanceTimersByTime(IDLE_WINDOW_MS - 2_000);
    });

    expect(result.current?.isLive).toBe(true);
  });

  it("replaces invalid stored anchors with the current timestamp", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-04-01T12:00:00Z");
    vi.setSystemTime(now);
    window.localStorage.setItem(STORAGE_KEY, "not-a-number");

    const { result } = renderHook(() => useCrawlerSignalPlayback(DETAIL));

    expect(result.current).not.toBeNull();
    expect(readStoredState()).toEqual({
      cycleAnchorMs: now.getTime(),
      lastSeenAtMs: now.getTime(),
    });
    expect(result.current?.isLive).toBe(true);
  });

  it("ignores future stored anchors that would stall the replay", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-04-01T12:00:00Z");
    vi.setSystemTime(now);
    window.localStorage.setItem(STORAGE_KEY, (now.getTime() + 5 * 60 * 1000).toString());

    const { result } = renderHook(() => useCrawlerSignalPlayback(DETAIL));

    expect(result.current).not.toBeNull();
    expect(readStoredState()).toEqual({
      cycleAnchorMs: now.getTime(),
      lastSeenAtMs: now.getTime(),
    });
    expect(result.current?.isLive).toBe(true);
  });

  it("continues the stored cycle when the site was only closed briefly", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-04-01T12:00:00Z");
    vi.setSystemTime(now);
    const cycleAnchorMs = now.getTime() - DETAIL.run.scheduledTasks;
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        cycleAnchorMs,
        lastSeenAtMs: now.getTime() - SHORT_GAP_MS,
      }),
    );

    const { result } = renderHook(() => useCrawlerSignalPlayback(DETAIL));

    expect(result.current).not.toBeNull();
    expect(readStoredState()).toEqual({
      cycleAnchorMs,
      lastSeenAtMs: now.getTime(),
    });
  });

  it("starts a fresh live cycle after a longer absence", async () => {
    vi.useFakeTimers();
    const now = new Date("2026-04-02T12:00:00Z");
    vi.setSystemTime(now);
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        cycleAnchorMs: now.getTime() - IDLE_WINDOW_MS - 5 * 60 * 1000,
        lastSeenAtMs: now.getTime() - IDLE_WINDOW_MS - 1_000,
      }),
    );

    const { result } = renderHook(() => useCrawlerSignalPlayback(DETAIL));

    expect(result.current).not.toBeNull();
    expect(readStoredState()).toEqual({
      cycleAnchorMs: now.getTime(),
      lastSeenAtMs: now.getTime(),
    });
    expect(result.current?.isLive).toBe(true);
  });

  it("shows location and ASN rankings that respond to map hover", () => {
    render(<CrawlerLiveSignal detail={DETAIL} playback={PLAYBACK} variant="hero" />);

    expect(screen.getByText("Top Locations")).toBeTruthy();
    expect(screen.getByText("Top ASNs")).toBeTruthy();
    expect(screen.queryByText("Map Focus")).toBeNull();
    expect(screen.getAllByText("Brazil").length).toBe(1);

    const hotspot = screen.getByLabelText("Show node count for Brazil");

    fireEvent.mouseEnter(hotspot);

    expect(screen.getAllByText("Brazil").length).toBeGreaterThan(1);
    expect(screen.getAllByText("SouthMesh Transit").length).toBeGreaterThan(0);
    expect(screen.getAllByText("500 nodes").length).toBeGreaterThan(0);

    fireEvent.mouseLeave(screen.getByRole("img", { name: "Crawler execution playback across a world route map" }));

    expect(screen.getAllByText("Brazil").length).toBe(1);

    fireEvent.click(hotspot);
    fireEvent.mouseLeave(screen.getByRole("img", { name: "Crawler execution playback across a world route map" }));
    expect(screen.getAllByText("Brazil").length).toBeGreaterThan(1);

    fireEvent.click(screen.getByRole("img", { name: "Crawler execution playback across a world route map" }));
    expect(screen.getAllByText("Brazil").length).toBe(1);
  });

  it("renders after playback becomes available on the normal async mount path", async () => {
    render(<CrawlerLiveSignal detail={DETAIL} variant="hero" />);

    expect(await screen.findByText("Read-Only Snapshot")).toBeTruthy();
    expect(screen.getByText("Top Locations")).toBeTruthy();
  });

  it("renders a compact map preview in the default variant", () => {
    render(<CrawlerLiveSignal detail={DETAIL} playback={PLAYBACK} />);

    expect(screen.getByText("Crawler Snapshot")).toBeTruthy();
    expect(screen.getByText("Global Sweep")).toBeTruthy();
    expect(screen.getByRole("img", { name: "Crawler execution playback across a world route map" })).toBeTruthy();
    expect(screen.getByText("1k")).toBeTruthy();
    expect(screen.queryByText("Map Focus")).toBeNull();
    expect(screen.queryByText("Top Locations")).toBeNull();
    expect(screen.queryByText("Top ASNs")).toBeNull();
  });
});

function readStoredState(): { cycleAnchorMs: number; lastSeenAtMs: number } | null {
  const raw = window.localStorage.getItem(STORAGE_KEY);

  if (!raw) {
    return null;
  }

  return JSON.parse(raw) as { cycleAnchorMs: number; lastSeenAtMs: number };
}
