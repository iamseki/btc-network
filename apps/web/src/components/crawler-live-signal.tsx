import type { ReactNode } from "react";
import { Activity } from "lucide-react";
import { useEffect, useState } from "react";

import type { CrawlRunCheckpointItem, CrawlRunDetail, CrawlRunListItem } from "@/lib/api/types";

const PLAYBACK_IDLE_MS = 15 * 60 * 1000;
const PLAYBACK_TICK_MS = 1000;
const CRAWL_SIGNAL_CYCLE_STORAGE_KEY_PREFIX = "btc-network:crawler-signal-cycle:v2:";
const VISUAL_SWEEP_LOOP_MS = 18_000;
const REPLAY_RESUME_RESET_GAP_MS = PLAYBACK_IDLE_MS;
const MAX_FUTURE_ANCHOR_DRIFT_MS = 60 * 1000;
const MAX_PAST_ANCHOR_AGE_MS = 30 * 24 * 60 * 60 * 1000;

const GLOBE_NODE_SEEDS = [
  { lat: 56, lon: -122 },
  { lat: 48, lon: -78 },
  { lat: 42, lon: -12 },
  { lat: 34, lon: 18 },
  { lat: 28, lon: 77 },
  { lat: 21, lon: 114 },
  { lat: 12, lon: 103 },
  { lat: 5, lon: -74 },
  { lat: -7, lon: -53 },
  { lat: -16, lon: 28 },
  { lat: -22, lon: 133 },
  { lat: -33, lon: 18 },
  { lat: -35, lon: -58 },
  { lat: 61, lon: 37 },
  { lat: 52, lon: 14 },
  { lat: 40, lon: 139 },
  { lat: 31, lon: -97 },
  { lat: 19, lon: -99 },
  { lat: 14, lon: 121 },
  { lat: 2, lon: 32 },
  { lat: -1, lon: 36 },
  { lat: -12, lon: -77 },
  { lat: -23, lon: -46 },
  { lat: 64, lon: -19 },
  { lat: 59, lon: 18 },
  { lat: 50, lon: -1 },
  { lat: 37, lon: -122 },
  { lat: 35, lon: 51 },
  { lat: 25, lon: 55 },
  { lat: -34, lon: 151 },
  { lat: -26, lon: 28 },
  { lat: 1, lon: 104 },
] as const;

type PlaybackSnapshot = {
  phase: string;
  checkpointSequence: number;
  checkpointedAt: string;
  frontierSize: number;
  inFlightWork: number;
  scheduledTasks: number;
  successfulHandshakes: number;
  failedTasks: number;
  uniqueNodes: number;
  persistedObservationRows: number;
  writerBacklog: number;
};

type PlaybackMarker = {
  phase: string;
  sequence: number;
  progressRatio: number;
};

type StoredCycleState = {
  cycleAnchorMs: number;
  lastSeenAtMs: number;
};

export type CrawlerSignalPlayback = {
  currentSummary: CrawlPulseSummary;
  finalSummary: CrawlPulseSummary;
  playbackSnapshot: PlaybackSnapshot;
  finalSnapshot: PlaybackSnapshot;
  markers: PlaybackMarker[];
  elapsedMs: number;
  loopDurationMs: number;
  loopRatio: number;
  cycleElapsedMs: number;
  visualLoopRatio: number;
  isLive: boolean;
  startedAt: string;
  completedAt: string;
};

export type CrawlPulseSummary = Pick<
  CrawlRunListItem,
  "successfulHandshakes" | "scheduledTasks"
>;

export function CrawlerPulseButton({
  summary,
  live = false,
  expanded = false,
  disabled = false,
  ariaLabel,
  onClick,
}: {
  summary: CrawlPulseSummary | null;
  live?: boolean;
  expanded?: boolean;
  disabled?: boolean;
  ariaLabel: string;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      className={
        disabled
          ? "inline-flex min-w-[13rem] items-center gap-3 rounded-[10px] border border-border/70 bg-background/45 px-3 py-2.5 text-left text-muted-foreground"
          : "inline-flex min-w-[13rem] cursor-pointer items-center gap-3 rounded-[10px] border border-border/80 bg-background/72 px-3 py-2.5 text-left transition-colors outline-none hover:border-primary/35 hover:bg-primary/8 focus-visible:ring-2 focus-visible:ring-ring"
      }
      aria-expanded={disabled ? false : expanded}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={onClick}
    >
      <span
        className={
          live
            ? "relative flex h-9 w-9 items-center justify-center rounded-full border border-primary/25 bg-primary/10 text-primary"
            : "relative flex h-9 w-9 items-center justify-center rounded-full border border-border/80 bg-muted/55 text-primary"
        }
      >
        {live ? (
          <span className="absolute inline-flex h-full w-full rounded-full bg-primary/18 animate-ping" />
        ) : null}
        <Activity className="relative h-4 w-4" />
      </span>
      <span className="min-w-0">
        <span className="flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          <span>Latest Snapshot</span>
          <span className={live ? "text-primary" : "text-muted-foreground/80"}>
            {live ? "Live" : "Resting"}
          </span>
        </span>
        <span className="mt-1 block font-mono text-sm text-foreground">
          {summary
            ? live
              ? "Background snapshot updating"
              : "Last snapshot ready"
            : "Waiting for latest snapshot"}
        </span>
        {summary ? (
          <span className="mt-1 block font-mono text-[11px] text-muted-foreground">
            {summary.successfulHandshakes.toLocaleString()} / {summary.scheduledTasks.toLocaleString()} verified
          </span>
        ) : null}
      </span>
    </button>
  );
}

export function useCrawlerSignalPlayback(detail: CrawlRunDetail | null): CrawlerSignalPlayback | null {
  const [now, setNow] = useState(() => Date.now());
  const [cycleAnchorMs, setCycleAnchorMs] = useState<number | null>(null);

  useEffect(() => {
    if (!detail) {
      setCycleAnchorMs(null);
      return;
    }

    const nextNow = Date.now();
    const nextAnchorMs = getOrCreateCycleAnchorMs(detail.run.runId, nextNow);

    setNow(nextNow);
    setCycleAnchorMs(nextAnchorMs);
  }, [detail?.run.runId]);

  useEffect(() => {
    if (!detail) {
      return;
    }

    const timer = window.setInterval(() => {
      setNow(Date.now());
    }, PLAYBACK_TICK_MS);

    return () => {
      window.clearInterval(timer);
    };
  }, [detail?.run.runId]);

  useEffect(() => {
    if (!detail || cycleAnchorMs === null) {
      return;
    }

    persistCycleState(detail.run.runId, {
      cycleAnchorMs,
      lastSeenAtMs: Date.now(),
    });

    const persistCurrentTime = () => {
      persistCycleState(detail.run.runId, {
        cycleAnchorMs,
        lastSeenAtMs: Date.now(),
      });
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        persistCurrentTime();
      }
    };

    window.addEventListener("pagehide", persistCurrentTime);
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.removeEventListener("pagehide", persistCurrentTime);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      persistCurrentTime();
    };
  }, [detail?.run.runId, cycleAnchorMs]);

  if (!detail || cycleAnchorMs === null) {
    return null;
  }

  const anchors = buildPlaybackAnchors(detail);
  const finalSnapshot = anchors[anchors.length - 1]!;
  const markers = normalizeCheckpoints(detail).map((checkpoint, index, checkpoints) => ({
    phase: checkpoint.phase,
    sequence: checkpoint.checkpointSequence,
    progressRatio:
      checkpoints.length === 1 ? 1 : index / Math.max(1, checkpoints.length - 1),
  })) satisfies PlaybackMarker[];
  const loopDurationMs = simulatedRunDurationMs(detail.run.runId);
  const cycleDurationMs = loopDurationMs + PLAYBACK_IDLE_MS;
  const cycleElapsedMs = Math.max(0, now - cycleAnchorMs) % cycleDurationMs;
  const isLive = cycleElapsedMs < loopDurationMs;
  const elapsedMs = isLive ? cycleElapsedMs : loopDurationMs;
  const loopRatio = loopDurationMs <= 0 ? 1 : elapsedMs / loopDurationMs;
  const visualLoopRatio = (cycleElapsedMs % VISUAL_SWEEP_LOOP_MS) / VISUAL_SWEEP_LOOP_MS;
  const startedAtMs = now - cycleElapsedMs;
  const completedAtMs = startedAtMs + loopDurationMs;
  const playbackSnapshot = derivePlaybackSnapshot(anchors, elapsedMs, loopDurationMs);

  return {
    currentSummary: {
      successfulHandshakes: playbackSnapshot.successfulHandshakes,
      scheduledTasks: playbackSnapshot.scheduledTasks,
    },
    finalSummary: {
      successfulHandshakes: finalSnapshot.successfulHandshakes,
      scheduledTasks: finalSnapshot.scheduledTasks,
    },
    playbackSnapshot,
    finalSnapshot,
    markers,
    elapsedMs,
    loopDurationMs,
    loopRatio,
    cycleElapsedMs,
    visualLoopRatio,
    isLive,
    startedAt: new Date(startedAtMs).toISOString(),
    completedAt: new Date(completedAtMs).toISOString(),
  };
}

export function CrawlerLiveSignal({
  detail,
  playback,
  variant = "default",
  heroFooter,
}: {
  detail: CrawlRunDetail;
  playback?: CrawlerSignalPlayback | null;
  variant?: "default" | "hero";
  heroFooter?: ReactNode;
}) {
  const localPlayback = useCrawlerSignalPlayback(detail);
  const signalPlayback = playback ?? localPlayback;

  if (!signalPlayback) {
    return null;
  }

  const playbackSnapshot = signalPlayback.playbackSnapshot;
  const finalSnapshot = signalPlayback.finalSnapshot;
  const loopRatio = signalPlayback.loopRatio;
  const visualLoopRatio = signalPlayback.visualLoopRatio;
  const discoveredNodeCount = clampCount(
    Math.round(
      progressRatio(playbackSnapshot.uniqueNodes, finalSnapshot.uniqueNodes) * GLOBE_NODE_SEEDS.length,
    ),
  );
  const verifiedNodeCount = Math.min(
    discoveredNodeCount,
    clampCount(
      Math.round(
        progressRatio(playbackSnapshot.successfulHandshakes, finalSnapshot.successfulHandshakes) *
          GLOBE_NODE_SEEDS.length,
      ),
    ),
  );
  const sweepRotation = -180 + visualLoopRatio * 360;
  const visibleNodes = GLOBE_NODE_SEEDS.map((seed, index) => {
    if (index >= discoveredNodeCount) {
      return null;
    }

    const projected = projectNode(seed.lat, seed.lon, sweepRotation);
    if (!projected.visible) {
      return null;
    }

    const isVerified = index < verifiedNodeCount;
    const isRecent = index >= Math.max(0, discoveredNodeCount - 4);

    return {
      ...projected,
      key: `${seed.lat}-${seed.lon}`,
      isVerified,
      isRecent,
    };
  }).filter((node) => node !== null);
  const markers = signalPlayback.markers;
  const isHero = variant === "hero";
  const shellClass = isHero
    ? "space-y-4"
    : "rounded-[12px] border border-border/80 bg-background/88 p-4 shadow-[0_18px_42px_rgba(0,0,0,0.24)]";
  const visualPanelClass = isHero
    ? "rounded-[14px] border border-primary/16 bg-[radial-gradient(circle_at_top,rgba(245,179,1,0.18),transparent_48%),linear-gradient(180deg,rgba(255,255,255,0.03),rgba(255,255,255,0))] p-4 shadow-[0_18px_40px_rgba(0,0,0,0.18)] sm:p-5"
    : "fx-ambient-panel rounded-[12px] border border-border/70 p-4";
  const canvasClass = isHero
    ? "mt-5 rounded-[10px] border border-primary/16 bg-background/45 p-3 sm:p-4 xl:p-5"
    : "mt-4 rounded-[10px] border border-border/70 bg-background/52 p-3";
  const svgClass = isHero ? "h-[320px] w-full sm:h-[360px] xl:h-[420px]" : "h-[240px] w-full";

  return (
    <section className={shellClass}>
      {isHero ? null : (
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
              Crawler Snapshot
            </p>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              A compact replay of the latest sweep with just the movement and numbers that matter.
            </p>
          </div>
          <div className="rounded-[8px] border border-border/70 bg-muted/35 px-3 py-2.5 text-right">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              Sweep State
            </p>
            <p className="mt-1 font-mono text-sm text-foreground">
              {signalPlayback.isLive ? "Live" : "Archived"}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {formatDuration(signalPlayback.loopDurationMs)} scan window
            </p>
          </div>
        </div>
      )}

      <div className={isHero ? "space-y-4" : "mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.25fr)_minmax(18rem,0.75fr)]"}>
        <div className={visualPanelClass}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                Read-Only Snapshot
              </p>
              <p className="mt-1 font-mono text-lg text-foreground">
                {formatPhase(playbackSnapshot.phase)}
              </p>
            </div>
            {isHero ? (
              <div className="rounded-[8px] border border-border/60 bg-background/35 px-3 py-2 text-right">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                  Sweep State
                </p>
                <p className="mt-1 font-mono text-sm text-foreground">
                  {signalPlayback.isLive ? "Background sweep active" : "Last sweep archived"}
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-3 gap-2 text-right">
                <SignalPill label="Tracked" value={playbackSnapshot.uniqueNodes} />
                <SignalPill label="Verified" value={playbackSnapshot.successfulHandshakes} />
                <SignalPill label="Frontier" value={playbackSnapshot.frontierSize} />
              </div>
            )}
          </div>

          <div className={canvasClass}>
            <svg
              viewBox="0 0 420 260"
              role="img"
              aria-label="Crawler execution playback around a projected globe"
              className={svgClass}
            >
              <defs>
                <radialGradient id="globe-core" cx="50%" cy="45%" r="60%">
                  <stop offset="0%" stopColor="rgba(245,179,1,0.22)" />
                  <stop offset="50%" stopColor="rgba(245,179,1,0.10)" />
                  <stop offset="100%" stopColor="rgba(15,23,42,0.06)" />
                </radialGradient>
                <linearGradient id="globe-sweep" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="rgba(245,179,1,0)" />
                  <stop offset="45%" stopColor="rgba(245,179,1,0.04)" />
                  <stop offset="55%" stopColor="rgba(245,179,1,0.18)" />
                  <stop offset="100%" stopColor="rgba(245,179,1,0)" />
                </linearGradient>
              </defs>

              <rect x="0" y="0" width="420" height="260" rx="18" fill="rgba(0,0,0,0.16)" />

              <g transform="translate(16 8)">
                <ellipse cx="170" cy="122" rx="120" ry="96" fill="url(#globe-core)" />
                <ellipse
                  cx="170"
                  cy="122"
                  rx="120"
                  ry="96"
                  fill="none"
                  stroke="rgba(245,239,226,0.18)"
                  strokeWidth="1.2"
                />
                <ellipse
                  cx="170"
                  cy="122"
                  rx="92"
                  ry="96"
                  fill="none"
                  stroke="rgba(245,239,226,0.08)"
                  strokeWidth="1"
                />
                <ellipse
                  cx="170"
                  cy="122"
                  rx="52"
                  ry="96"
                  fill="none"
                  stroke="rgba(245,239,226,0.07)"
                  strokeWidth="1"
                />
                <ellipse
                  cx="170"
                  cy="122"
                  rx="24"
                  ry="96"
                  fill="none"
                  stroke="rgba(245,239,226,0.06)"
                  strokeWidth="1"
                />
                <ellipse
                  cx="170"
                  cy="122"
                  rx="103"
                  ry="20"
                  fill="none"
                  stroke="rgba(245,239,226,0.08)"
                  strokeWidth="1"
                />
                <ellipse
                  cx="170"
                  cy="92"
                  rx="88"
                  ry="16"
                  fill="none"
                  stroke="rgba(245,239,226,0.07)"
                  strokeWidth="1"
                />
                <ellipse
                  cx="170"
                  cy="152"
                  rx="88"
                  ry="16"
                  fill="none"
                  stroke="rgba(245,239,226,0.07)"
                  strokeWidth="1"
                />
                <ellipse
                  cx="170"
                  cy="122"
                  rx="136"
                  ry="110"
                  fill="none"
                  stroke="rgba(245,179,1,0.16)"
                  strokeDasharray="3 8"
                  strokeWidth="1"
                />

                <g
                  transform={`rotate(${sweepRotation} 170 122)`}
                  style={{ transformOrigin: "170px 122px" }}
                >
                  <ellipse
                    cx="170"
                    cy="122"
                    rx="120"
                    ry="96"
                    fill="url(#globe-sweep)"
                    opacity="0.8"
                  />
                </g>

                {visibleNodes.map((node) => (
                  <g key={node.key}>
                    {node.isRecent ? (
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r="9"
                        fill={node.isVerified ? "rgba(245,179,1,0.16)" : "rgba(245,239,226,0.09)"}
                      />
                    ) : null}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.isRecent ? 3.8 : 2.8}
                      fill={node.isVerified ? "rgb(245,179,1)" : "rgba(245,239,226,0.74)"}
                      stroke={node.isVerified ? "rgba(255,240,197,0.65)" : "rgba(245,239,226,0.26)"}
                      strokeWidth="1"
                    />
                  </g>
                ))}

                {[0, 1, 2, 3, 4, 5].map((index) => {
                  const orbitAngle = visualLoopRatio * Math.PI * 2 + index * ((Math.PI * 2) / 6);
                  const x = 170 + Math.cos(orbitAngle) * 146;
                  const y = 122 + Math.sin(orbitAngle) * 116;

                  return (
                    <circle
                      key={`orbit-${index}`}
                      cx={x}
                      cy={y}
                      r={index % 2 === 0 ? 2.5 : 1.7}
                      fill="rgba(245,179,1,0.72)"
                      opacity={0.36 + index * 0.08}
                    />
                  );
                })}
              </g>
            </svg>
          </div>

          {isHero ? null : <div className="fx-signal-track mt-4 h-[2px] rounded-full" />}
        </div>

        {isHero ? null : (
          <div className="space-y-4">
            <SignalMetric
              label="Verification Yield"
              value={`${formatPercent(progressRatio(playbackSnapshot.successfulHandshakes, playbackSnapshot.scheduledTasks))}%`}
              detail={`${playbackSnapshot.successfulHandshakes.toLocaleString()} verified out of ${playbackSnapshot.scheduledTasks.toLocaleString()} attempts`}
            />
            <SignalMetric
              label="Sweep Completion"
              value={`${formatPercent(loopRatio)}%`}
              detail={`${formatDuration(signalPlayback.elapsedMs)} into the current replay window`}
            />
            <SignalMetric
              label="Checkpoint Pulse"
              value={`#${playbackSnapshot.checkpointSequence}`}
              detail={formatTimestamp(playbackSnapshot.checkpointedAt)}
            />

            <div className="rounded-[10px] border border-border/70 bg-background/68 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                    Checkpoint Rail
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Playback follows the same checkpoint progression returned by the API.
                  </p>
                </div>
                <p className="font-mono text-xs text-foreground">{detail.run.runId}</p>
              </div>

              <div className="mt-4 h-2 overflow-hidden rounded-full bg-muted/40">
                <div
                  className="h-full rounded-full bg-[linear-gradient(90deg,rgba(245,179,1,0.42),rgba(245,179,1,0.95))] transition-[width]"
                  style={{ width: `${Math.max(6, loopRatio * 100)}%` }}
                />
              </div>

              <div className="mt-4 grid gap-2">
                {markers.map((marker) => {
                  const isActive = loopRatio >= marker.progressRatio;

                  return (
                    <div
                      key={`${marker.sequence}-${marker.phase}`}
                      className={
                        isActive
                          ? "rounded-[8px] border border-primary/25 bg-primary/10 px-3 py-2"
                          : "rounded-[8px] border border-border/70 bg-muted/25 px-3 py-2"
                      }
                    >
                      <div className="flex items-center justify-between gap-3">
                        <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                          Checkpoint {marker.sequence}
                        </p>
                        <p className="font-mono text-xs text-foreground">{formatPhase(marker.phase)}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {isHero ? heroFooter ?? null : null}
    </section>
  );
}

function simulatedRunDurationMs(runId: string): number {
  return 295_000 + (hashSeed(runId) % 5_001);
}

function getOrCreateCycleAnchorMs(runId: string, now: number): number {
  const initialState: StoredCycleState = {
    cycleAnchorMs: now,
    lastSeenAtMs: now,
  };

  try {
    const storedState = readStoredCycleState(runId, now);
    if (storedState) {
      const wasAwayLongEnoughToRestart =
        now - storedState.lastSeenAtMs >= REPLAY_RESUME_RESET_GAP_MS;
      const nextState = wasAwayLongEnoughToRestart
        ? initialState
        : {
            cycleAnchorMs: storedState.cycleAnchorMs,
            lastSeenAtMs: now,
          };

      persistCycleState(runId, nextState);
      return nextState.cycleAnchorMs;
    }
  } catch {
    return initialState.cycleAnchorMs;
  }

  persistCycleState(runId, initialState);
  return initialState.cycleAnchorMs;
}

function isValidCycleAnchorMs(value: number, now: number): boolean {
  if (!Number.isFinite(value) || value <= 0) {
    return false;
  }

  if (value > now + MAX_FUTURE_ANCHOR_DRIFT_MS) {
    return false;
  }

  if (value < now - MAX_PAST_ANCHOR_AGE_MS) {
    return false;
  }

  return true;
}

function isValidLastSeenAtMs(value: number, now: number): boolean {
  if (!Number.isFinite(value) || value <= 0) {
    return false;
  }

  if (value > now + MAX_FUTURE_ANCHOR_DRIFT_MS) {
    return false;
  }

  if (value < now - MAX_PAST_ANCHOR_AGE_MS) {
    return false;
  }

  return true;
}

function readStoredCycleState(runId: string, now: number): StoredCycleState | null {
  const storageKey = `${CRAWL_SIGNAL_CYCLE_STORAGE_KEY_PREFIX}${runId}`;
  const storedValue = window.localStorage.getItem(storageKey);

  if (!storedValue) {
    return null;
  }

  try {
    const parsed = JSON.parse(storedValue) as Partial<StoredCycleState>;
    if (
      isValidCycleAnchorMs(parsed.cycleAnchorMs ?? Number.NaN, now) &&
      isValidLastSeenAtMs(parsed.lastSeenAtMs ?? Number.NaN, now)
    ) {
      return {
        cycleAnchorMs: parsed.cycleAnchorMs!,
        lastSeenAtMs: parsed.lastSeenAtMs!,
      };
    }
  } catch {
    const parsedValue = Number.parseInt(storedValue, 10);
    if (isValidCycleAnchorMs(parsedValue, now)) {
      return {
        cycleAnchorMs: parsedValue,
        lastSeenAtMs: parsedValue,
      };
    }
  }

  return null;
}

function persistCycleState(runId: string, state: StoredCycleState): void {
  const storageKey = `${CRAWL_SIGNAL_CYCLE_STORAGE_KEY_PREFIX}${runId}`;

  try {
    window.localStorage.setItem(storageKey, JSON.stringify(state));
  } catch {
    // Ignore storage write failures so the replay still works in-memory.
  }
}

function hashSeed(value: string): number {
  let hash = 0;

  for (const char of value) {
    hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  }

  return hash;
}

function SignalPill({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-[6px] border border-border/70 bg-background/60 px-2.5 py-2">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 font-mono text-sm text-foreground">{value}</p>
    </div>
  );
}

function SignalMetric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="rounded-[6px] border border-border/70 bg-muted/30 px-4 py-3">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-2 font-mono text-xl text-foreground">{value}</p>
      <p className="mt-2 text-sm text-muted-foreground">{detail}</p>
    </div>
  );
}

function normalizeCheckpoints(detail: CrawlRunDetail): CrawlRunCheckpointItem[] {
  return [...detail.checkpoints].sort((left, right) => left.checkpointSequence - right.checkpointSequence);
}

function buildPlaybackAnchors(detail: CrawlRunDetail): PlaybackSnapshot[] {
  const checkpoints = normalizeCheckpoints(detail);
  const baseline: PlaybackSnapshot = {
    phase: checkpoints[0]?.phase ?? "bootstrapping",
    checkpointSequence: 0,
    checkpointedAt: detail.run.startedAt,
    frontierSize: 0,
    inFlightWork: 0,
    scheduledTasks: 0,
    successfulHandshakes: 0,
    failedTasks: 0,
    uniqueNodes: 0,
    persistedObservationRows: 0,
    writerBacklog: 0,
  };

  if (checkpoints.length === 0) {
    return [
      baseline,
      {
        phase: detail.run.phase,
        checkpointSequence: 1,
        checkpointedAt: detail.run.lastCheckpointedAt,
        frontierSize: detail.run.unscheduledGap,
        inFlightWork: 0,
        scheduledTasks: detail.run.scheduledTasks,
        successfulHandshakes: detail.run.successfulHandshakes,
        failedTasks: detail.run.failedTasks,
        uniqueNodes: detail.run.uniqueNodes,
        persistedObservationRows: detail.run.persistedObservationRows,
        writerBacklog: 0,
      },
    ];
  }

  return [
    baseline,
    ...checkpoints.map((checkpoint) => ({
      phase: checkpoint.phase,
      checkpointSequence: checkpoint.checkpointSequence,
      checkpointedAt: checkpoint.checkpointedAt,
      frontierSize: checkpoint.frontierSize,
      inFlightWork: checkpoint.inFlightWork,
      scheduledTasks: checkpoint.scheduledTasks,
      successfulHandshakes: checkpoint.successfulHandshakes,
      failedTasks: checkpoint.failedTasks,
      uniqueNodes: checkpoint.uniqueNodes,
      persistedObservationRows: checkpoint.persistedObservationRows,
      writerBacklog: checkpoint.writerBacklog,
    })),
  ];
}

function derivePlaybackSnapshot(
  anchors: PlaybackSnapshot[],
  elapsedMs: number,
  loopDurationMs: number,
): PlaybackSnapshot {
  if (anchors.length === 1 || loopDurationMs <= 0) {
    return anchors[anchors.length - 1]!;
  }

  const segmentCount = anchors.length - 1;
  const scaledProgress = (elapsedMs / loopDurationMs) * segmentCount;
  const index = Math.min(segmentCount - 1, Math.floor(scaledProgress));
  const localProgress = scaledProgress - index;
  const from = anchors[index]!;
  const to = anchors[index + 1]!;

  return {
    phase: localProgress < 0.55 ? from.phase : to.phase,
    checkpointSequence: localProgress < 0.55 ? from.checkpointSequence : to.checkpointSequence,
    checkpointedAt: localProgress < 0.55 ? from.checkpointedAt : to.checkpointedAt,
    frontierSize: Math.round(interpolateNumber(from.frontierSize, to.frontierSize, localProgress)),
    inFlightWork: Math.round(interpolateNumber(from.inFlightWork, to.inFlightWork, localProgress)),
    scheduledTasks: Math.round(interpolateNumber(from.scheduledTasks, to.scheduledTasks, localProgress)),
    successfulHandshakes: Math.round(
      interpolateNumber(from.successfulHandshakes, to.successfulHandshakes, localProgress),
    ),
    failedTasks: Math.round(interpolateNumber(from.failedTasks, to.failedTasks, localProgress)),
    uniqueNodes: Math.round(interpolateNumber(from.uniqueNodes, to.uniqueNodes, localProgress)),
    persistedObservationRows: Math.round(
      interpolateNumber(from.persistedObservationRows, to.persistedObservationRows, localProgress),
    ),
    writerBacklog: Math.round(interpolateNumber(from.writerBacklog, to.writerBacklog, localProgress)),
  };
}

function interpolateNumber(from: number, to: number, progress: number): number {
  return from + (to - from) * progress;
}

function progressRatio(current: number, total: number): number {
  if (total <= 0) {
    return 0;
  }

  return Math.max(0, Math.min(1, current / total));
}

function clampCount(value: number): number {
  return Math.max(1, Math.min(GLOBE_NODE_SEEDS.length, value));
}

function projectNode(lat: number, lon: number, rotationDeg: number) {
  const latRad = (lat * Math.PI) / 180;
  const lonRad = ((lon - rotationDeg) * Math.PI) / 180;
  const horizon = Math.cos(latRad) * Math.cos(lonRad);

  return {
    x: 186 + Math.cos(latRad) * Math.sin(lonRad) * 120,
    y: 130 - Math.sin(latRad) * 96,
    visible: horizon >= -0.14,
  };
}

function formatClock(valueMs: number): string {
  const totalSeconds = Math.floor(valueMs / 1000);
  const minutes = Math.floor(totalSeconds / 60)
    .toString()
    .padStart(2, "0");
  const seconds = (totalSeconds % 60).toString().padStart(2, "0");
  return `${minutes}:${seconds}`;
}

function formatDuration(valueMs: number): string {
  return formatClock(valueMs).replace(/^00:/, "");
}

function formatPercent(value: number): string {
  return (Math.max(0, Math.min(1, value)) * 100).toFixed(1);
}

function formatPhase(value: string): string {
  if (!value) {
    return "Unknown";
  }

  return value
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((token) => token[0]!.toUpperCase() + token.slice(1))
    .join(" ");
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}
