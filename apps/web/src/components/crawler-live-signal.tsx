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

type WorldNodeSeed = {
  lat: number;
  lon: number;
  city: string;
  countryCode: string;
  countryName: string;
  asnLabel: string;
  nodeCount: number;
};

const GLOBE_NODE_SEEDS: readonly WorldNodeSeed[] = [
  { lat: 56, lon: -122, city: "Seattle", countryCode: "US", countryName: "United States", asnLabel: "NorthGrid Transit", nodeCount: 420 },
  { lat: 48, lon: -78, city: "Toronto", countryCode: "CA", countryName: "Canada", asnLabel: "Northern Relay", nodeCount: 280 },
  { lat: 42, lon: -12, city: "Lisbon", countryCode: "PT", countryName: "Portugal", asnLabel: "Atlantic Fiber", nodeCount: 170 },
  { lat: 34, lon: 18, city: "Tunis", countryCode: "TN", countryName: "Tunisia", asnLabel: "Mediterranean Core", nodeCount: 120 },
  { lat: 28, lon: 77, city: "Delhi", countryCode: "IN", countryName: "India", asnLabel: "Monsoon Carrier", nodeCount: 480 },
  { lat: 21, lon: 114, city: "Hong Kong", countryCode: "HK", countryName: "Hong Kong", asnLabel: "Harbour Exchange", nodeCount: 320 },
  { lat: 12, lon: 103, city: "Bangkok", countryCode: "TH", countryName: "Thailand", asnLabel: "Mekong Transit", nodeCount: 190 },
  { lat: 5, lon: -74, city: "Bogota", countryCode: "CO", countryName: "Colombia", asnLabel: "Andean Link", nodeCount: 150 },
  { lat: -7, lon: -53, city: "Brasilia", countryCode: "BR", countryName: "Brazil", asnLabel: "SouthMesh Transit", nodeCount: 220 },
  { lat: -16, lon: 28, city: "Lusaka", countryCode: "ZM", countryName: "Zambia", asnLabel: "Copper Route", nodeCount: 90 },
  { lat: -22, lon: 133, city: "Adelaide", countryCode: "AU", countryName: "Australia", asnLabel: "Southern Cross Exchange", nodeCount: 140 },
  { lat: -33, lon: 18, city: "Cape Town", countryCode: "ZA", countryName: "South Africa", asnLabel: "Cape Backbone", nodeCount: 180 },
  { lat: -35, lon: -58, city: "Buenos Aires", countryCode: "AR", countryName: "Argentina", asnLabel: "SouthMesh Transit", nodeCount: 160 },
  { lat: 61, lon: 37, city: "Moscow", countryCode: "RU", countryName: "Russia", asnLabel: "Volga Networks", nodeCount: 260 },
  { lat: 52, lon: 14, city: "Berlin", countryCode: "DE", countryName: "Germany", asnLabel: "Atlas Backbone", nodeCount: 340 },
  { lat: 40, lon: 139, city: "Tokyo", countryCode: "JP", countryName: "Japan", asnLabel: "Kanto Transit", nodeCount: 520 },
  { lat: 31, lon: -97, city: "Dallas", countryCode: "US", countryName: "United States", asnLabel: "NorthGrid Transit", nodeCount: 380 },
  { lat: 19, lon: -99, city: "Mexico City", countryCode: "MX", countryName: "Mexico", asnLabel: "Aztec Route", nodeCount: 230 },
  { lat: 14, lon: 121, city: "Manila", countryCode: "PH", countryName: "Philippines", asnLabel: "Pacific Relay", nodeCount: 140 },
  { lat: 2, lon: 32, city: "Kampala", countryCode: "UG", countryName: "Uganda", asnLabel: "Equator Net", nodeCount: 80 },
  { lat: -1, lon: 36, city: "Nairobi", countryCode: "KE", countryName: "Kenya", asnLabel: "Rift Fiber", nodeCount: 110 },
  { lat: -12, lon: -77, city: "Lima", countryCode: "PE", countryName: "Peru", asnLabel: "Pacific Andes", nodeCount: 130 },
  { lat: -23, lon: -46, city: "Sao Paulo", countryCode: "BR", countryName: "Brazil", asnLabel: "SouthMesh Transit", nodeCount: 280 },
  { lat: 64, lon: -19, city: "Reykjavik", countryCode: "IS", countryName: "Iceland", asnLabel: "North Atlantic", nodeCount: 70 },
  { lat: 59, lon: 18, city: "Stockholm", countryCode: "SE", countryName: "Sweden", asnLabel: "Atlas Backbone", nodeCount: 160 },
  { lat: 50, lon: -1, city: "London", countryCode: "GB", countryName: "United Kingdom", asnLabel: "Atlas Backbone", nodeCount: 260 },
  { lat: 37, lon: -122, city: "San Francisco", countryCode: "US", countryName: "United States", asnLabel: "NorthGrid Transit", nodeCount: 300 },
  { lat: 35, lon: 51, city: "Tehran", countryCode: "IR", countryName: "Iran", asnLabel: "Silk Route", nodeCount: 210 },
  { lat: 25, lon: 55, city: "Dubai", countryCode: "AE", countryName: "United Arab Emirates", asnLabel: "Gulf Exchange", nodeCount: 240 },
  { lat: -34, lon: 151, city: "Sydney", countryCode: "AU", countryName: "Australia", asnLabel: "Southern Cross Exchange", nodeCount: 110 },
  { lat: -26, lon: 28, city: "Johannesburg", countryCode: "ZA", countryName: "South Africa", asnLabel: "Cape Backbone", nodeCount: 140 },
  { lat: 1, lon: 104, city: "Singapore", countryCode: "SG", countryName: "Singapore", asnLabel: "Southern Cross Exchange", nodeCount: 210 },
] as const;

type VisibleMapNode = ReturnType<typeof projectWorldNode> & {
  key: string;
  city: string;
  countryCode: string;
  countryName: string;
  locationKey: string;
  asnLabel: string;
  nodeCount: number;
  isVerified: boolean;
  isRecent: boolean;
};

type LocationInsight = {
  key: string;
  countryName: string;
  countryCode: string;
  count: number;
  verifiedCount: number;
  x: number;
  y: number;
  topAsnLabel: string;
  topAsnCount: number;
};

type AsnInsight = {
  key: string;
  label: string;
  count: number;
  verifiedCount: number;
  countryCount: number;
  leadCountryName: string;
};

const WORLD_LANDMASSES = [
  [
    { lat: 72, lon: -168 },
    { lat: 68, lon: -158 },
    { lat: 63, lon: -150 },
    { lat: 59, lon: -140 },
    { lat: 56, lon: -132 },
    { lat: 52, lon: -128 },
    { lat: 48, lon: -125 },
    { lat: 43, lon: -124 },
    { lat: 36, lon: -121 },
    { lat: 31, lon: -117 },
    { lat: 26, lon: -112 },
    { lat: 22, lon: -106 },
    { lat: 20, lon: -98 },
    { lat: 22, lon: -90 },
    { lat: 27, lon: -83 },
    { lat: 30, lon: -81 },
    { lat: 35, lon: -77 },
    { lat: 40, lon: -73 },
    { lat: 46, lon: -66 },
    { lat: 52, lon: -60 },
    { lat: 58, lon: -64 },
    { lat: 63, lon: -78 },
    { lat: 69, lon: -102 },
    { lat: 73, lon: -132 },
  ],
  [
    { lat: 82, lon: -70 },
    { lat: 78, lon: -34 },
    { lat: 72, lon: -18 },
    { lat: 64, lon: -30 },
    { lat: 60, lon: -48 },
    { lat: 67, lon: -62 },
  ],
  [
    { lat: 13, lon: -81 },
    { lat: 8, lon: -78 },
    { lat: 4, lon: -75 },
    { lat: -6, lon: -78 },
    { lat: -15, lon: -75 },
    { lat: -23, lon: -71 },
    { lat: -33, lon: -71 },
    { lat: -41, lon: -66 },
    { lat: -52, lon: -69 },
    { lat: -55, lon: -64 },
    { lat: -50, lon: -58 },
    { lat: -38, lon: -55 },
    { lat: -24, lon: -46 },
    { lat: -12, lon: -38 },
    { lat: -1, lon: -47 },
    { lat: 7, lon: -60 },
  ],
  [
    { lat: 71, lon: -11 },
    { lat: 65, lon: -7 },
    { lat: 58, lon: -5 },
    { lat: 54, lon: -2 },
    { lat: 50, lon: 2 },
    { lat: 45, lon: 8 },
    { lat: 43, lon: 16 },
    { lat: 46, lon: 24 },
    { lat: 52, lon: 31 },
    { lat: 58, lon: 35 },
    { lat: 64, lon: 33 },
    { lat: 71, lon: 26 },
    { lat: 72, lon: 12 },
  ],
  [
    { lat: 58, lon: -8 },
    { lat: 55, lon: -6 },
    { lat: 51, lon: -4 },
    { lat: 50, lon: -6 },
    { lat: 53, lon: -8 },
  ],
  [
    { lat: 35, lon: -17 },
    { lat: 33, lon: -5 },
    { lat: 31, lon: 7 },
    { lat: 26, lon: 17 },
    { lat: 18, lon: 27 },
    { lat: 11, lon: 35 },
    { lat: 4, lon: 42 },
    { lat: -6, lon: 44 },
    { lat: -17, lon: 40 },
    { lat: -29, lon: 31 },
    { lat: -35, lon: 21 },
    { lat: -31, lon: 12 },
    { lat: -18, lon: 4 },
    { lat: -4, lon: -4 },
    { lat: 9, lon: -10 },
    { lat: 21, lon: -15 },
    { lat: 29, lon: -14 },
  ],
  [
    { lat: 39, lon: 26 },
    { lat: 43, lon: 37 },
    { lat: 50, lon: 50 },
    { lat: 56, lon: 68 },
    { lat: 62, lon: 92 },
    { lat: 66, lon: 118 },
    { lat: 62, lon: 140 },
    { lat: 56, lon: 156 },
    { lat: 48, lon: 162 },
    { lat: 38, lon: 148 },
    { lat: 28, lon: 132 },
    { lat: 22, lon: 120 },
    { lat: 14, lon: 108 },
    { lat: 9, lon: 98 },
    { lat: 8, lon: 86 },
    { lat: 15, lon: 76 },
    { lat: 22, lon: 70 },
    { lat: 28, lon: 63 },
    { lat: 33, lon: 52 },
  ],
  [
    { lat: -11, lon: 113 },
    { lat: -16, lon: 127 },
    { lat: -20, lon: 138 },
    { lat: -28, lon: 153 },
    { lat: -36, lon: 148 },
    { lat: -39, lon: 136 },
    { lat: -34, lon: 123 },
    { lat: -24, lon: 114 },
  ],
  [
    { lat: 18, lon: -91 },
    { lat: 16, lon: -88 },
    { lat: 14, lon: -86 },
    { lat: 11, lon: -84 },
    { lat: 9, lon: -81 },
    { lat: 8, lon: -78 },
    { lat: 11, lon: -80 },
    { lat: 15, lon: -84 },
  ],
  [
    { lat: 37, lon: 138 },
    { lat: 41, lon: 142 },
    { lat: 35, lon: 141 },
    { lat: 31, lon: 135 },
    { lat: 34, lon: 131 },
  ],
  [
    { lat: -13, lon: 48 },
    { lat: -16, lon: 50 },
    { lat: -22, lon: 49 },
    { lat: -25, lon: 46 },
    { lat: -18, lon: 45 },
  ],
  [
    { lat: 5, lon: 95 },
    { lat: 2, lon: 104 },
    { lat: -3, lon: 112 },
    { lat: -6, lon: 121 },
    { lat: -4, lon: 131 },
    { lat: 1, lon: 124 },
    { lat: 4, lon: 113 },
  ],
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
  const [hoveredLocationKey, setHoveredLocationKey] = useState<string | null>(null);
  const [pinnedLocationKey, setPinnedLocationKey] = useState<string | null>(null);
  const playbackSnapshot = signalPlayback?.playbackSnapshot ?? null;
  const finalSnapshot = signalPlayback?.finalSnapshot ?? null;
  const loopRatio = signalPlayback?.loopRatio ?? 0;
  const visualLoopRatio = signalPlayback?.visualLoopRatio ?? 0;
  const discoveredNodeCount =
    playbackSnapshot && finalSnapshot
      ? clampCount(
          Math.round(
            progressRatio(playbackSnapshot.uniqueNodes, finalSnapshot.uniqueNodes) * GLOBE_NODE_SEEDS.length,
          ),
        )
      : 0;
  const verifiedNodeCount =
    playbackSnapshot && finalSnapshot
      ? Math.min(
          discoveredNodeCount,
          clampCount(
            Math.round(
              progressRatio(playbackSnapshot.successfulHandshakes, finalSnapshot.successfulHandshakes) *
                GLOBE_NODE_SEEDS.length,
            ),
          ),
        )
      : 0;
  const scanX = 26 + visualLoopRatio * 332;
  const visibleNodes: VisibleMapNode[] = playbackSnapshot
    ? GLOBE_NODE_SEEDS.map((seed, index) => {
        if (index >= discoveredNodeCount) {
          return null;
        }

        const projected = projectWorldNode(seed.lat, seed.lon);

        const isVerified = index < verifiedNodeCount;
        const isRecent = index >= Math.max(0, discoveredNodeCount - 4);

        return {
          ...projected,
          key: `${seed.countryCode}-${seed.city}-${seed.lat}-${seed.lon}`,
          city: seed.city,
          countryCode: seed.countryCode,
          countryName: seed.countryName,
          locationKey: seed.countryCode,
          asnLabel: seed.asnLabel,
          nodeCount: seed.nodeCount,
          isVerified,
          isRecent,
        };
      }).filter((node) => node !== null)
    : [];
  const { locations: locationInsights, asns: asnInsights } = summarizeVisibleNodes(visibleNodes);
  const mapLocations = locationInsights.slice(0, 8);
  const activeLocationKey = pinnedLocationKey ?? hoveredLocationKey;
  const activeLocation = activeLocationKey
    ? locationInsights.find((location) => location.key === activeLocationKey) ?? null
    : null;
  const activeFlowNodes = visibleNodes.filter((node) => node.isRecent).slice(0, 4);
  const activeLocationTooltipStyle = activeLocation
    ? {
        left: `${(((18 + activeLocation.x) / 420) * 100).toFixed(2)}%`,
        top: `${(((16 + activeLocation.y) / 260) * 100).toFixed(2)}%`,
        transform:
          activeLocation.x > 280
            ? "translate(-100%, calc(-100% - 0.75rem))"
            : "translate(-12%, calc(-100% - 0.75rem))",
      }
    : null;
  const isHero = variant === "hero";
  const isCompactPreview = variant === "default";
  const shellClass = isHero
    ? "space-y-4"
    : "rounded-[12px] border border-border/80 bg-background/88 p-4 shadow-[0_18px_42px_rgba(0,0,0,0.24)]";
  const visualPanelClass = isHero
    ? "rounded-[14px] border border-primary/16 bg-[radial-gradient(circle_at_top,rgba(245,179,1,0.18),transparent_48%),linear-gradient(180deg,rgba(255,255,255,0.03),rgba(255,255,255,0))] p-4 shadow-[0_18px_40px_rgba(0,0,0,0.18)] sm:p-5"
    : "fx-ambient-panel rounded-[12px] border border-border/70 p-4";
  const canvasClass = isHero
    ? "relative mt-5 overflow-hidden rounded-[10px] border border-primary/16 bg-background/45 p-3 sm:p-4 xl:p-5"
    : "relative mt-4 overflow-hidden rounded-[10px] border border-border/70 bg-background/52 p-3";
  const mapFrameClass = isHero
    ? "relative mx-auto aspect-[420/260] w-full max-w-[920px]"
    : "relative mx-auto aspect-[420/260] w-full max-w-[620px]";
  const svgClass = "absolute inset-0 h-full w-full";

  useEffect(() => {
    if (!hoveredLocationKey && !pinnedLocationKey) {
      return;
    }

    if (hoveredLocationKey && !locationInsights.some((location) => location.key === hoveredLocationKey)) {
      setHoveredLocationKey(null);
    }

    if (pinnedLocationKey && !locationInsights.some((location) => location.key === pinnedLocationKey)) {
      setPinnedLocationKey(null);
    }
  }, [hoveredLocationKey, pinnedLocationKey, locationInsights]);

  if (!signalPlayback || !playbackSnapshot || !finalSnapshot) {
    return null;
  }

  const markers = signalPlayback.markers;

  if (isCompactPreview) {
    return (
      <section className={shellClass}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
              Crawler Snapshot
            </p>
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
              Latest public window, reduced to the shortest useful read.
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
              {formatPhase(playbackSnapshot.phase)}
            </p>
          </div>
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <SignalMetric
            label="Tracked"
            value={playbackSnapshot.uniqueNodes.toLocaleString()}
            detail="Endpoints in the latest snapshot window"
          />
          <SignalMetric
            label="Verified"
            value={playbackSnapshot.successfulHandshakes.toLocaleString()}
            detail="Successful handshakes in the latest sweep"
          />
          <SignalMetric
            label="Yield"
            value={`${formatPercent(progressRatio(playbackSnapshot.successfulHandshakes, playbackSnapshot.scheduledTasks))}%`}
            detail={`${playbackSnapshot.scheduledTasks.toLocaleString()} total attempts`}
          />
        </div>

        <div className="mt-4 rounded-[10px] border border-border/70 bg-background/62 p-3">
          <div className="flex items-center justify-between gap-3">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              Global Sweep
            </p>
            <p className="text-[11px] text-muted-foreground">Static preview</p>
          </div>
          <div className="mt-3 relative mx-auto aspect-[420/260] w-full max-w-[420px]">
            <svg
              viewBox="0 0 420 260"
              role="img"
              aria-label="Crawler execution playback across a world route map"
              className="absolute inset-0 h-full w-full cursor-default"
            >
              <defs>
                <linearGradient id="map-scan-compact" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="rgba(245,179,1,0)" />
                  <stop offset="45%" stopColor="rgba(245,179,1,0.02)" />
                  <stop offset="50%" stopColor="rgba(245,179,1,0.12)" />
                  <stop offset="55%" stopColor="rgba(245,179,1,0.02)" />
                  <stop offset="100%" stopColor="rgba(245,179,1,0)" />
                </linearGradient>
              </defs>

              <rect x="0" y="0" width="420" height="260" rx="18" fill="rgba(0,0,0,0.16)" />

              <g transform="translate(18 16)">
                <rect
                  x="0"
                  y="0"
                  width="384"
                  height="228"
                  rx="16"
                  fill="rgba(8,8,8,0.34)"
                  stroke="rgba(245,239,226,0.1)"
                />

                {WORLD_LANDMASSES.map((polygon, index) => (
                  <path
                    key={`compact-landmass-${index}`}
                    d={buildProjectedPolygonPath(polygon)}
                    fill={index % 2 === 0 ? "rgba(245,239,226,0.06)" : "rgba(245,239,226,0.048)"}
                    stroke="rgba(245,239,226,0.08)"
                    strokeWidth="1"
                    strokeLinejoin="round"
                  />
                ))}

                <rect x={scanX} y="18" width="22" height="192" fill="url(#map-scan-compact)" opacity="0.9" />

                <g>
                  <circle cx="18" cy="114" r="5.5" fill="rgba(245,179,1,0.9)" />
                  <circle cx="18" cy="114" r="12" className="fx-node-pulse" fill="rgba(245,179,1,0.12)" />
                </g>

                {activeFlowNodes.map((node) => (
                  <g key={`compact-flow-${node.key}`}>
                    <path
                      d={buildFlowArcPath(18, 114, node.x, node.y)}
                      fill="none"
                      stroke={node.isVerified ? "rgba(245,179,1,0.58)" : "rgba(245,239,226,0.22)"}
                      strokeWidth={node.isVerified ? 1.4 : 1}
                      strokeLinecap="round"
                      className="fx-arc-flow"
                    />
                  </g>
                ))}

                {visibleNodes.map((node) => (
                  <g key={`compact-node-${node.key}`}>
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.isRecent ? 3.4 : 2.4}
                      fill={node.isVerified ? "rgb(245,179,1)" : "rgba(245,239,226,0.68)"}
                      stroke={node.isVerified ? "rgba(255,240,197,0.5)" : "rgba(245,239,226,0.18)"}
                      strokeWidth="1"
                    />
                  </g>
                ))}

                {mapLocations.map((location) => (
                  <g key={`compact-location-${location.key}`} transform={`translate(${location.x}, ${location.y})`} aria-hidden="true">
                    <circle
                      r={8 + Math.min(4, location.count)}
                      fill="rgba(245,179,1,0.12)"
                      stroke="rgba(245,179,1,0.34)"
                      strokeWidth="1"
                    />
                    <text
                      x="0"
                      y="3.5"
                      textAnchor="middle"
                      className="fill-[rgba(245,239,226,0.82)]"
                      style={{ fontSize: "9px", fontFamily: "monospace", fontWeight: 700 }}
                    >
                      {formatMapBubbleCount(location.count)}
                    </text>
                  </g>
                ))}
              </g>
            </svg>
          </div>
        </div>

      </section>
    );
  }

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

      <div className={isHero || isCompactPreview ? "mt-5 space-y-4" : "mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.25fr)_minmax(18rem,0.75fr)]"}>
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
              <div className="flex flex-1 flex-wrap items-center justify-end gap-2 sm:flex-nowrap">
                <div className="min-w-[12rem] flex-1 rounded-[8px] border border-border/60 bg-background/35 px-3 py-2 text-center sm:max-w-[16rem]">
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                    Map Focus
                  </p>
                  {activeLocation ? (
                    <div className="mt-1">
                      <p className="font-mono text-sm text-foreground">{activeLocation.count} nodes</p>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        {activeLocation.topAsnLabel} · {activeLocation.topAsnCount}
                      </p>
                      {pinnedLocationKey ? (
                        <p className="mt-1 text-[10px] uppercase tracking-[0.14em] text-primary/85">Pinned</p>
                      ) : null}
                    </div>
                  ) : (
                    <p className="mt-1 text-[11px] text-muted-foreground">Hover a country hotspot or click to pin</p>
                  )}
                </div>
                <div className="rounded-[8px] border border-border/60 bg-background/35 px-3 py-2 text-right">
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                    Sweep State
                  </p>
                  <p className="mt-1 font-mono text-sm text-foreground">
                    {signalPlayback.isLive ? "Live" : "Archived"}
                  </p>
                </div>
              </div>
            )}
          </div>

          <div
            className={canvasClass}
            onClick={(event) => {
              const target = event.target as Element;
              if (target.closest("[data-map-hotspot='true']")) {
                return;
              }

              setPinnedLocationKey(null);
              setHoveredLocationKey(null);
            }}
            onMouseLeave={() => {
              if (!pinnedLocationKey) {
                setHoveredLocationKey(null);
              }
            }}
          >
            <div className={mapFrameClass}>
              {activeLocation && activeLocationTooltipStyle ? (
                <div
                  className="pointer-events-none absolute z-10 rounded-[8px] border border-primary/20 bg-[linear-gradient(180deg,rgba(10,10,10,0.94),rgba(10,10,10,0.82))] px-2.5 py-2 shadow-[0_12px_26px_rgba(0,0,0,0.28)]"
                  style={activeLocationTooltipStyle}
                >
                  <p className="font-mono text-[11px] text-foreground">{activeLocation.countryName}</p>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    {activeLocation.count} nodes
                  </p>
                </div>
              ) : null}

              <svg
                viewBox="0 0 420 260"
                role="img"
                aria-label="Crawler execution playback across a world route map"
                className={`${svgClass} cursor-default`}
              >
                <defs>
                  <linearGradient id="map-scan" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="rgba(245,179,1,0)" />
                    <stop offset="45%" stopColor="rgba(245,179,1,0.03)" />
                    <stop offset="50%" stopColor="rgba(245,179,1,0.18)" />
                    <stop offset="55%" stopColor="rgba(245,179,1,0.03)" />
                    <stop offset="100%" stopColor="rgba(245,179,1,0)" />
                  </linearGradient>
                </defs>

                <rect x="0" y="0" width="420" height="260" rx="18" fill="rgba(0,0,0,0.16)" />

                <g transform="translate(18 16)">
                  <rect
                    x="0"
                    y="0"
                    width="384"
                    height="228"
                    rx="16"
                    fill="rgba(8,8,8,0.34)"
                    stroke="rgba(245,239,226,0.1)"
                  />

                  {[42, 76, 110, 144, 178].map((y) => (
                    <line
                      key={`lat-${y}`}
                      x1="16"
                      y1={y}
                      x2="368"
                      y2={y}
                      stroke="rgba(245,239,226,0.06)"
                      strokeWidth="1"
                    />
                  ))}

                  {[56, 104, 152, 200, 248, 296, 344].map((x) => (
                    <line
                      key={`lon-${x}`}
                      x1={x}
                      y1="18"
                      x2={x}
                      y2="210"
                      stroke="rgba(245,239,226,0.05)"
                      strokeWidth="1"
                    />
                  ))}

                  {WORLD_LANDMASSES.map((polygon, index) => (
                    <path
                      key={`landmass-${index}`}
                      d={buildProjectedPolygonPath(polygon)}
                      fill={index % 2 === 0 ? "rgba(245,239,226,0.065)" : "rgba(245,239,226,0.052)"}
                      stroke="rgba(245,239,226,0.08)"
                      strokeWidth="1"
                      strokeLinejoin="round"
                    />
                  ))}

                  <rect x={scanX} y="18" width="28" height="192" fill="url(#map-scan)" opacity="0.95" />

                  <g>
                    <circle cx="18" cy="114" r="5.5" fill="rgba(245,179,1,0.92)" />
                    <circle cx="18" cy="114" r="12" className="fx-node-pulse" fill="rgba(245,179,1,0.14)" />
                  </g>

                  {activeFlowNodes.map((node) => (
                    <g key={`flow-${node.key}`}>
                      <path
                        d={buildFlowArcPath(18, 114, node.x, node.y)}
                        fill="none"
                        stroke={node.isVerified ? "rgba(245,179,1,0.72)" : "rgba(245,239,226,0.34)"}
                        strokeWidth={node.isVerified ? 1.8 : 1.2}
                        strokeLinecap="round"
                        className="fx-arc-flow"
                      />
                    </g>
                  ))}

                  {visibleNodes.map((node) => (
                    <g key={node.key}>
                      {node.isRecent ? (
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r="9"
                          className="fx-node-pulse"
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

                  {mapLocations.map((location) => {
                    const isActive = activeLocation?.key === location.key;
                    const ringRadius = 9 + Math.min(6, location.count);

                    return (
                      <g
                        key={`location-${location.key}`}
                        transform={`translate(${location.x}, ${location.y})`}
                        aria-hidden="true"
                      >
                        <circle
                          r={ringRadius}
                          fill={isActive ? "rgba(245,179,1,0.16)" : "rgba(0,0,0,0.28)"}
                          stroke={isActive ? "rgba(245,179,1,0.72)" : "rgba(245,239,226,0.16)"}
                          strokeWidth="1"
                        />
                        <text
                          x="0"
                          y="3.5"
                          textAnchor="middle"
                          className={isActive ? "fill-primary" : "fill-[rgba(245,239,226,0.82)]"}
                          style={{ fontSize: "10px", fontFamily: "monospace", fontWeight: 700 }}
                        >
                          {formatMapBubbleCount(location.count)}
                        </text>
                      </g>
                    );
                  })}

                  {[0, 1, 2, 3, 4, 5].map((index) => {
                    const x = 32 + ((visualLoopRatio * 332 + index * 48) % 332);
                    const y = 24 + index * 30;
                    return (
                      <circle
                        key={`orbit-${index}`}
                        cx={x}
                        cy={y}
                        r={index % 2 === 0 ? 2.5 : 1.7}
                        fill="rgba(245,179,1,0.72)"
                        opacity={0.24 + index * 0.08}
                      />
                    );
                  })}
                </g>
              </svg>

              {mapLocations.map((location) => (
                <button
                  key={`hotspot-${location.key}`}
                type="button"
                data-map-hotspot="true"
                aria-label={`Show node count for ${location.countryName}`}
                className="absolute z-10 h-10 w-10 -translate-x-1/2 -translate-y-1/2 cursor-pointer rounded-full border border-transparent bg-transparent outline-none focus-visible:border-primary/50 focus-visible:ring-2 focus-visible:ring-ring"
                style={{
                  left: `${(((18 + location.x) / 420) * 100).toFixed(2)}%`,
                  top: `${(((16 + location.y) / 260) * 100).toFixed(2)}%`,
                }}
                  onMouseEnter={() => setHoveredLocationKey(location.key)}
                  onMouseMove={() => setHoveredLocationKey(location.key)}
                  onMouseLeave={() => {
                    if (!pinnedLocationKey) {
                      setHoveredLocationKey(null);
                    }
                  }}
                  onFocus={() => setHoveredLocationKey(location.key)}
                  onBlur={() => {
                    if (!pinnedLocationKey) {
                      setHoveredLocationKey(null);
                    }
                  }}
                  onClick={(event) => {
                    event.stopPropagation();
                    setPinnedLocationKey((current) => (current === location.key ? null : location.key));
                    setHoveredLocationKey(location.key);
                  }}
                />
              ))}
            </div>
          </div>

          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            <div className="rounded-[10px] border border-border/70 bg-background/68 p-3">
              <div className="flex items-center justify-between gap-3">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                  Top Locations
                </p>
                <p className="font-mono text-[10px] text-muted-foreground">
                  Hover map to inspect
                </p>
              </div>
              <div className="mt-3 grid gap-2">
                {locationInsights.slice(0, 5).map((location) => (
                  <button
                    key={location.key}
                    type="button"
                    className={
                      activeLocation?.key === location.key
                        ? "flex items-center justify-between gap-3 rounded-[8px] border border-primary/25 bg-primary/10 px-3 py-2 text-left"
                        : "flex items-center justify-between gap-3 rounded-[8px] border border-border/70 bg-muted/20 px-3 py-2 text-left"
                    }
                    onMouseEnter={() => setHoveredLocationKey(location.key)}
                    onMouseMove={() => setHoveredLocationKey(location.key)}
                    onFocus={() => setHoveredLocationKey(location.key)}
                    onMouseLeave={() => {
                      if (!pinnedLocationKey) {
                        setHoveredLocationKey(null);
                      }
                    }}
                    onBlur={() => {
                      if (!pinnedLocationKey) {
                        setHoveredLocationKey(null);
                      }
                    }}
                    onClick={() => {
                      setPinnedLocationKey((current) => (current === location.key ? null : location.key));
                      setHoveredLocationKey(location.key);
                    }}
                  >
                    <div>
                      <p className="font-mono text-[11px] text-foreground">{location.countryName}</p>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        {location.topAsnLabel}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="font-mono text-sm text-foreground">{location.count}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {location.verifiedCount} verified
                      </p>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-[10px] border border-border/70 bg-background/68 p-3">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                Top ASNs
              </p>
              <div className="mt-3 grid gap-2">
                {asnInsights.slice(0, 5).map((asn) => (
                  <div
                    key={asn.key}
                    className="flex items-center justify-between gap-3 rounded-[8px] border border-border/70 bg-muted/20 px-3 py-2"
                  >
                    <div>
                      <p className="font-mono text-[11px] text-foreground">{asn.label}</p>
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        Strongest footprint in {asn.leadCountryName}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="font-mono text-sm text-foreground">{asn.count}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {asn.countryCount} countries
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {isHero ? null : <div className="fx-signal-track mt-4 h-[2px] rounded-full" />}
        </div>

        {isHero || isCompactPreview ? null : (
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

function summarizeVisibleNodes(visibleNodes: VisibleMapNode[]): {
  locations: LocationInsight[];
  asns: AsnInsight[];
} {
  const locationMap = new Map<
    string,
    {
      key: string;
      countryName: string;
      countryCode: string;
      count: number;
      verifiedCount: number;
      xTotal: number;
      yTotal: number;
      asnCounts: Map<string, number>;
    }
  >();
  const asnMap = new Map<
    string,
    {
      key: string;
      label: string;
      count: number;
      verifiedCount: number;
      countries: Map<string, number>;
    }
  >();

  for (const node of visibleNodes) {
    const nextLocation =
      locationMap.get(node.locationKey) ??
      {
        key: node.locationKey,
        countryName: node.countryName,
        countryCode: node.countryCode,
        count: 0,
        verifiedCount: 0,
        xTotal: 0,
        yTotal: 0,
        asnCounts: new Map<string, number>(),
      };

    nextLocation.count += node.nodeCount;
    nextLocation.verifiedCount += node.isVerified ? node.nodeCount : 0;
    nextLocation.xTotal += node.x * node.nodeCount;
    nextLocation.yTotal += node.y * node.nodeCount;
    nextLocation.asnCounts.set(node.asnLabel, (nextLocation.asnCounts.get(node.asnLabel) ?? 0) + node.nodeCount);
    locationMap.set(node.locationKey, nextLocation);

    const nextAsn =
      asnMap.get(node.asnLabel) ??
      {
        key: node.asnLabel,
        label: node.asnLabel,
        count: 0,
        verifiedCount: 0,
        countries: new Map<string, number>(),
      };

    nextAsn.count += node.nodeCount;
    nextAsn.verifiedCount += node.isVerified ? node.nodeCount : 0;
    nextAsn.countries.set(node.countryName, (nextAsn.countries.get(node.countryName) ?? 0) + node.nodeCount);
    asnMap.set(node.asnLabel, nextAsn);
  }

  const locations = [...locationMap.values()]
    .map((location) => {
      const [topAsnLabel, topAsnCount] =
        [...location.asnCounts.entries()].sort(
          (left, right) => right[1] - left[1] || left[0].localeCompare(right[0]),
        )[0] ?? ["Unknown ASN", 0];

      return {
        key: location.key,
        countryName: location.countryName,
        countryCode: location.countryCode,
        count: location.count,
        verifiedCount: location.verifiedCount,
        x: location.xTotal / location.count,
        y: location.yTotal / location.count,
        topAsnLabel,
        topAsnCount,
      };
    })
    .sort(
      (left, right) =>
        right.count - left.count ||
        right.verifiedCount - left.verifiedCount ||
        left.countryName.localeCompare(right.countryName),
    );

  const asns = [...asnMap.values()]
    .map((asn) => {
      const [leadCountryName] =
        [...asn.countries.entries()].sort(
          (left, right) => right[1] - left[1] || left[0].localeCompare(right[0]),
        )[0] ?? ["Unknown region", 0];

      return {
        key: asn.key,
        label: asn.label,
        count: asn.count,
        verifiedCount: asn.verifiedCount,
        countryCount: asn.countries.size,
        leadCountryName,
      };
    })
    .sort(
      (left, right) =>
        right.count - left.count ||
        right.verifiedCount - left.verifiedCount ||
        left.label.localeCompare(right.label),
    );

  return { locations, asns };
}

function projectWorldNode(lat: number, lon: number) {
  return {
    x: 26 + ((lon + 180) / 360) * 332,
    y: 34 + ((90 - lat) / 180) * 152,
  };
}

function buildProjectedPolygonPath(points: readonly { lat: number; lon: number }[]): string {
  const projected = points.map((point) => projectWorldNode(point.lat, point.lon));

  if (projected.length < 3) {
    return projected
      .map((point, index) => `${index === 0 ? "M" : "L"} ${point.x.toFixed(1)} ${point.y.toFixed(1)}`)
      .concat("Z")
      .join(" ");
  }

  const midpoints = projected.map((point, index) => {
    const nextPoint = projected[(index + 1) % projected.length]!;

    return {
      x: (point.x + nextPoint.x) / 2,
      y: (point.y + nextPoint.y) / 2,
    };
  });

  return [
    `M ${midpoints.at(-1)!.x.toFixed(1)} ${midpoints.at(-1)!.y.toFixed(1)}`,
    ...projected.map((point, index) => {
      const midpoint = midpoints[index]!;
      return `Q ${point.x.toFixed(1)} ${point.y.toFixed(1)} ${midpoint.x.toFixed(1)} ${midpoint.y.toFixed(1)}`;
    }),
    "Z",
  ].join(" ");
}

function buildFlowArcPath(fromX: number, fromY: number, toX: number, toY: number): string {
  const midX = (fromX + toX) / 2;
  const midY = (fromY + toY) / 2;
  const dx = toX - fromX;
  const dy = toY - fromY;
  const distance = Math.sqrt(dx * dx + dy * dy);
  const lift = Math.max(16, Math.min(42, distance * 0.22));
  const controlY = midY - lift;

  return `M ${fromX} ${fromY} Q ${midX} ${controlY} ${toX} ${toY}`;
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

function formatMapBubbleCount(value: number): string {
  if (value < 1000) {
    return value.toString();
  }

  if (value < 1_000_000) {
    return `${Math.round(value / 1000)}k`;
  }

  return `${Math.round(value / 1_000_000)}m`;
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
