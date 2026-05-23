import { CircleHelp, LoaderCircle, RotateCw } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  LastRunDashboard,
  LastRunSidebarCharts,
} from "@/components/analytics/last-run-dashboard";
import { CountryGlobe } from "@/components/analytics/country-globe";
import {
  useCrawlerSignalPlayback,
} from "@/components/crawler-live-signal";
import type { BtcAppClient } from "@/lib/api/client";
import type {
  CrawlRunDetail,
  CrawlRunListItem,
  LastRunAsnCountItem,
  LastRunCountryCountItem,
  LastRunNetworkTypeCountItem,
  LastRunStartHeightCountItem,
  NodeStatusItem,
} from "@/lib/api/types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

export type NetworkAnalyticsPanel = "overview" | "status" | "crawler-runs";
export const NETWORK_ANALYTICS_LIVE_POLL_INTERVAL_MS = 15_000;

const LATEST_RUN_PHASE_FILTER = { phase: "any" as const };

type NetworkAnalyticsPageProps = {
  client: BtcAppClient;
  onOpenApiPage?: () => void;
  onOpenAgentGuidePage?: () => void;
  onOpenStatusPage?: () => void;
};

export function NetworkAnalyticsPage({
  client,
  onOpenApiPage,
  onOpenAgentGuidePage,
  onOpenStatusPage,
}: NetworkAnalyticsPageProps) {
  const demoMode = isDemoModeEnabled();
  const [lastRunAsns, setLastRunAsns] = useState<LastRunAsnCountItem[]>([]);
  const [lastRunNetworkTypes, setLastRunNetworkTypes] = useState<LastRunNetworkTypeCountItem[]>([]);
  const [lastRunCountries, setLastRunCountries] = useState<LastRunCountryCountItem[]>([]);
  const [latestRunAsns, setLatestRunAsns] = useState<LastRunAsnCountItem[]>([]);
  const [latestRunNetworkTypes, setLatestRunNetworkTypes] = useState<LastRunNetworkTypeCountItem[]>([]);
  const [latestRunCountries, setLatestRunCountries] = useState<LastRunCountryCountItem[]>([]);
  const [latestRunStartHeights, setLatestRunStartHeights] = useState<LastRunStartHeightCountItem[]>([]);
  const [lastRunStartHeights, setLastRunStartHeights] = useState<LastRunStartHeightCountItem[]>([]);
  const [statusRows, setStatusRows] = useState<NodeStatusItem[]>([]);
  const [latestRun, setLatestRun] = useState<CrawlRunListItem | null>(null);
  const [latestDetail, setLatestDetail] = useState<CrawlRunDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    void refreshAnalytics(() => cancelled);
    const interval = window.setInterval(() => {
      void refreshLatestRunSnapshot(() => cancelled);
    }, NETWORK_ANALYTICS_LIVE_POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [client]);

  async function refreshAnalytics(isCancelled: () => boolean = () => false) {
    setIsLoading(true);
    setError(null);

    try {
      const [
        latestRunSnapshot,
        nextLastRunAsns,
        nextLastRunNetworkTypes,
        nextLastRunCountries,
        nextLastRunStartHeights,
        nextStatusRows,
      ] = await Promise.all([
        loadLatestRunSnapshot(),
        client.listLastRunAsns(10),
        client.listLastRunNetworkTypes(10),
        client.listLastRunCountries(10),
        client.listLastRunStartHeights(5),
        client.listNodeStatus().catch(() => []),
      ]);

      if (isCancelled()) {
        return;
      }

      applyLatestRunSnapshot(latestRunSnapshot);
      setLastRunAsns(nextLastRunAsns);
      setLastRunNetworkTypes(nextLastRunNetworkTypes);
      setLastRunCountries(nextLastRunCountries);
      setLastRunStartHeights(nextLastRunStartHeights);
      setStatusRows(nextStatusRows);
    } catch (nextError) {
      if (isCancelled()) {
        return;
      }

      setLatestRun(null);
      setLatestDetail(null);
      setLastRunAsns([]);
      setLastRunNetworkTypes([]);
      setLastRunCountries([]);
      setLatestRunAsns([]);
      setLatestRunNetworkTypes([]);
      setLatestRunCountries([]);
      setLatestRunStartHeights([]);
      setLastRunStartHeights([]);
      setStatusRows([]);
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      if (!isCancelled()) {
        setIsLoading(false);
      }
    }
  }

  async function refreshLatestRunSnapshot(isCancelled: () => boolean = () => false) {
    try {
      const latestRunSnapshot = await loadLatestRunSnapshot();

      if (!isCancelled()) {
        applyLatestRunSnapshot(latestRunSnapshot);
      }
    } catch {
      // Keep last good snapshot during background polling failures.
    }
  }

  async function loadLatestRunSnapshot() {
    const [
      runs,
      nextLatestRunAsns,
      nextLatestRunNetworkTypes,
      nextLatestRunCountries,
      nextLatestRunStartHeights,
    ] = await Promise.all([
      client.listCrawlRuns(1),
      client.listLastRunAsns(10, LATEST_RUN_PHASE_FILTER),
      client.listLastRunNetworkTypes(10, LATEST_RUN_PHASE_FILTER),
      client.listLastRunCountries(32, LATEST_RUN_PHASE_FILTER),
      client.listLastRunStartHeights(5, LATEST_RUN_PHASE_FILTER),
    ]);
    const mostRecentRun = runs[0] ?? null;
    const detail = mostRecentRun ? await client.getCrawlRun(mostRecentRun.runId) : null;

    return {
      run: mostRecentRun,
      detail,
      asns: nextLatestRunAsns,
      networkTypes: nextLatestRunNetworkTypes,
      countries: nextLatestRunCountries,
      startHeights: nextLatestRunStartHeights,
    };
  }

  function applyLatestRunSnapshot(snapshot: Awaited<ReturnType<typeof loadLatestRunSnapshot>>) {
    setLatestRun(snapshot.run);
    setLatestDetail(snapshot.detail);
    setLatestRunAsns(snapshot.asns);
    setLatestRunNetworkTypes(snapshot.networkTypes);
    setLatestRunCountries(snapshot.countries);
    setLatestRunStartHeights(snapshot.startHeights);
  }

  const networkOutcomes = latestDetail?.networkOutcomes ?? [];
  const hasAnyAnalytics =
    lastRunAsns.length > 0 ||
    lastRunNetworkTypes.length > 0 ||
    lastRunCountries.length > 0 ||
    latestRunAsns.length > 0 ||
    latestRunNetworkTypes.length > 0 ||
    latestRunCountries.length > 0 ||
    latestRunStartHeights.length > 0 ||
    lastRunStartHeights.length > 0 ||
    networkOutcomes.length > 0 ||
    latestRun !== null;
  const hasLatestRunDistributions =
    latestRunAsns.length > 0 ||
    latestRunNetworkTypes.length > 0 ||
    latestRunCountries.length > 0 ||
    latestRunStartHeights.length > 0;
  const playback = useCrawlerSignalPlayback(latestDetail);
  const overviewPhaseLabel = playback ? formatPhase(playback.playbackSnapshot.phase) : "Awaiting snapshot";
  const overviewSweepLabel = playback
    ? playback.isLive
      ? "Background sweep active"
      : "Last sweep archived"
    : "Waiting for sweep state";
  const statusSummary = summarizeStatusRows(statusRows);
  const panelDescription = demoMode
    ? "Public home dashboard from the hosted demo snapshot."
    : "Public home dashboard with latest-run globe replay and latest finished-run analytics.";
  return (
    <Card>
      <CardContent className="space-y-5 p-3 sm:space-y-8 sm:p-6">
        <div className="flex items-start justify-between gap-3 border-b border-border/80 pb-4 sm:items-center sm:pb-5">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="sr-only">Network Analytics</h1>
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.28em] text-primary">
              Network Analytics Snapshot
            </p>
            <HeaderTooltip label="Network Analytics overview" tooltip={panelDescription} />
            <span className="hidden h-3 w-px bg-border/80 sm:inline-block" />
            <span className="font-mono text-[11px] text-foreground">{overviewPhaseLabel}</span>
            <span className="hidden font-mono text-[11px] text-muted-foreground sm:inline">•</span>
            <span className="text-[11px] text-muted-foreground">{overviewSweepLabel}</span>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 w-8 rounded-md px-0"
            aria-label="Refresh network analytics"
            title="Refresh network analytics"
            onClick={() => void refreshAnalytics()}
            disabled={isLoading}
          >
            {isLoading ? (
              <LoaderCircle className="h-4 w-4 animate-spin" />
            ) : (
              <RotateCw className="h-4 w-4" />
            )}
          </Button>
        </div>

        {isLoading ? (
          <StatusPanel
            message={
              demoMode
                ? "Loading demo ASN concentration and verification outcomes."
                : "Loading ASN concentration and recent verification outcomes."
            }
          />
        ) : error ? (
          <StatusPanel tone="error" message={`Network analytics failed to load: ${error}`} />
        ) : !hasAnyAnalytics ? (
          <StatusPanel
            message={
              demoMode
                ? "No demo analytics are configured for this build."
                : "No crawler analytics are available yet. Run the crawler locally or point the app at a populated API."
            }
          />
        ) : (
          <div className="space-y-6">
            <div className="space-y-4 sm:space-y-6">
                <section className="grid gap-4 sm:gap-6 xl:grid-cols-[minmax(0,1.58fr)_minmax(16.5rem,0.52fr)] xl:items-stretch">
                  <div className="order-1 h-full xl:order-1">
                    {latestRunCountries.length > 0 ? (
                      <CountryGlobe
                        countries={latestRunCountries}
                        playback={playback}
                      />
                    ) : (
                      <StatusPanel message="No country buckets are available for globe replay." />
                    )}
                  </div>

                  <div className="order-2 xl:order-2">
                    <LastRunSidebarCharts
                      networkTypes={latestRunNetworkTypes}
                      startHeights={latestRunStartHeights}
                    />
                  </div>
                </section>

                {hasLatestRunDistributions ? (
                  <LastRunDashboard
                    asns={latestRunAsns}
                    countries={latestRunCountries}
                    runId={latestRun?.runId ?? null}
                  />
                ) : null}

                <section className="grid gap-3 sm:gap-4 xl:grid-cols-[minmax(0,1.14fr)_minmax(15rem,0.86fr)]">
                  <div className="rounded-[14px] border border-border/80 bg-background/72 p-3 sm:p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="muted">Status</Badge>
                      <Badge variant="muted">DNS + P2P handshake</Badge>
                      <Badge variant="muted">Curated targets</Badge>
                    </div>
                    <div className="mt-4 grid gap-2 sm:grid-cols-4">
                      <MiniStatusStat label="Healthy" value={statusSummary.healthy} />
                      <MiniStatusStat label="Failed" value={statusSummary.failed} />
                      <MiniStatusStat label="Stale" value={statusSummary.stale} />
                      <MiniStatusStat label="Unknown" value={statusSummary.unknown} />
                    </div>
                  </div>

                  <div className="rounded-[14px] border border-primary/20 bg-[linear-gradient(135deg,rgba(245,179,1,0.1),rgba(245,179,1,0.02))] p-3 sm:p-4">
                    <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                      Status
                    </p>
                    <p className="mt-3 text-sm leading-6 text-muted-foreground">
                      Track selected DNS seeders and community endpoints separately from broad crawler analytics.
                    </p>
                    <Button
                      type="button"
                      className="mt-4 w-full sm:w-auto"
                      onClick={onOpenStatusPage}
                    >
                      Open status
                    </Button>
                  </div>
                </section>

                <section className="rounded-[16px] border border-border/80 bg-background/72 p-3 shadow-[0_16px_30px_rgba(0,0,0,0.16)] sm:p-4">
                  <div className="rounded-[14px] border border-primary/20 bg-[linear-gradient(135deg,rgba(245,179,1,0.1),rgba(245,179,1,0.02))] p-3 sm:p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="muted">API product</Badge>
                      <Badge variant="muted">OpenAPI generated</Badge>
                      <Badge variant="muted">Agent guide</Badge>
                      <Badge variant="muted">Scalar reference</Badge>
                    </div>
                    <div className="mt-4 space-y-3">
                      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                        Integration Docs
                      </p>
                      <p className="max-w-2xl text-sm leading-6 text-muted-foreground">
                        Pair the generated OpenAPI contract with a small agent guide that explains cheap first calls,
                        pagination discipline, cache posture, and when to drill into exact schemas.
                      </p>
                      <div className="grid gap-2 sm:grid-cols-2">
                        <Button
                          type="button"
                          variant="secondary"
                          className="w-full"
                          onClick={onOpenApiPage}
                        >
                          Open API spec
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          className="w-full border border-primary/20 bg-background/45"
                          onClick={onOpenAgentGuidePage}
                        >
                          Open agent guide
                        </Button>
                      </div>
                    </div>
                  </div>
                </section>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function HeaderTooltip({ label, tooltip }: { label: string; tooltip: string }) {
  return (
    <span className="group/tooltip relative inline-flex">
      <button
        type="button"
        aria-label={label}
        className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-border/70 text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <CircleHelp className="h-3.5 w-3.5" />
      </button>
      <span
        role="tooltip"
        className="pointer-events-none absolute left-0 top-[calc(100%+0.45rem)] z-10 w-64 rounded-[8px] border border-border/80 bg-popover/96 px-2.5 py-2 text-[11px] leading-4 text-popover-foreground opacity-0 shadow-[0_14px_28px_rgba(0,0,0,0.3)] transition-all duration-150 group-hover/tooltip:translate-y-0.5 group-hover/tooltip:opacity-100 group-focus-within/tooltip:translate-y-0.5 group-focus-within/tooltip:opacity-100"
      >
        {tooltip}
      </span>
    </span>
  );
}

function MiniStatusStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-[10px] border border-border/70 bg-background/52 p-3">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 font-serif text-2xl text-foreground">{value.toLocaleString()}</p>
    </div>
  );
}

function StatusPanel({
  message,
  tone = "neutral",
}: {
  message: string;
  tone?: "neutral" | "error";
}) {
  return (
    <div
      className={
        tone === "error"
          ? "rounded-[8px] border border-red-500/30 bg-red-500/8 px-4 py-3 text-sm text-red-200"
          : "rounded-[8px] border border-border/80 bg-background/80 px-4 py-3 text-sm text-muted-foreground"
      }
    >
      {message}
    </div>
  );
}

function summarizeStatusRows(rows: NodeStatusItem[]) {
  return rows.reduce(
    (summary, row) => {
      const checkedAtMs = Date.parse(row.checkedAt);
      if (!Number.isFinite(checkedAtMs) || Date.now() - checkedAtMs > 5 * 60_000) {
        summary.stale += 1;
      } else if (row.status === "healthy") {
        summary.healthy += 1;
      } else if (row.status === "failed") {
        summary.failed += 1;
      } else {
        summary.unknown += 1;
      }
      return summary;
    },
    { healthy: 0, failed: 0, stale: 0, unknown: 0 },
  );
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
