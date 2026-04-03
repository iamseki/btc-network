// @vitest-environment jsdom

import { renderHook, act, cleanup } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { CrawlRunDetail } from "@/lib/api/types";

import { useCrawlerSignalPlayback } from "./crawler-live-signal";

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
});

function readStoredState(): { cycleAnchorMs: number; lastSeenAtMs: number } | null {
  const raw = window.localStorage.getItem(STORAGE_KEY);

  if (!raw) {
    return null;
  }

  return JSON.parse(raw) as { cycleAnchorMs: number; lastSeenAtMs: number };
}
