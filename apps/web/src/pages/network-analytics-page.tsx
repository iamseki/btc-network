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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { BtcAppClient } from "@/lib/api/client";
import type {
  CrawlRunDetail,
  CrawlRunListItem,
  LastBlockHeightResult,
  LastRunAsnCountItem,
  LastRunCountryCountItem,
  LastRunNetworkTypeCountItem,
  LastRunNodeSummaryItem,
  LastRunServicesCountItem,
  LastRunStartHeightCountItem,
} from "@/lib/api/types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

export type NetworkAnalyticsPanel = "overview" | "risk" | "asn" | "verification";

const ANALYTICS_HEIGHT_NODE = "seed.bitnodes.io:8333";

type NetworkAnalyticsPageProps = {
  client: BtcAppClient;
  activePanel?: NetworkAnalyticsPanel;
  onPanelChange?: (panel: NetworkAnalyticsPanel) => void;
  onOpenApiPage?: () => void;
  showPanelNav?: boolean;
};

export function NetworkAnalyticsPage({
  client,
  activePanel: controlledActivePanel,
  onPanelChange,
  onOpenApiPage,
  showPanelNav = true,
}: NetworkAnalyticsPageProps) {
  const demoMode = isDemoModeEnabled();
  const [lastRunAsns, setLastRunAsns] = useState<LastRunAsnCountItem[]>([]);
  const [lastRunServices, setLastRunServices] = useState<LastRunServicesCountItem[]>([]);
  const [lastRunNetworkTypes, setLastRunNetworkTypes] = useState<LastRunNetworkTypeCountItem[]>([]);
  const [lastRunCountries, setLastRunCountries] = useState<LastRunCountryCountItem[]>([]);
  const [lastRunStartHeights, setLastRunStartHeights] = useState<LastRunStartHeightCountItem[]>([]);
  const [lastRunNodes, setLastRunNodes] = useState<LastRunNodeSummaryItem[]>([]);
  const [latestRun, setLatestRun] = useState<CrawlRunListItem | null>(null);
  const [latestDetail, setLatestDetail] = useState<CrawlRunDetail | null>(null);
  const [lastBlockHeight, setLastBlockHeight] = useState<LastBlockHeightResult | null>(null);
  const [internalActivePanel, setInternalActivePanel] = useState<NetworkAnalyticsPanel>("overview");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const activePanel = controlledActivePanel ?? internalActivePanel;

  useEffect(() => {
    void refreshAnalytics();
  }, []);

  function selectPanel(panel: NetworkAnalyticsPanel) {
    onPanelChange?.(panel);
    if (controlledActivePanel === undefined) {
      setInternalActivePanel(panel);
    }
  }

  async function refreshAnalytics() {
    setIsLoading(true);
    setError(null);

    try {
      const [
        runs,
        nextLastRunAsns,
        nextLastRunServices,
        nextLastRunNetworkTypes,
        nextLastRunCountries,
        nextLastRunStartHeights,
        nextLastRunNodes,
        nextBlockHeight,
      ] = await Promise.all([
        client.listCrawlRuns(10),
        client.listLastRunAsns(10),
        client.listLastRunServices(10),
        client.listLastRunNetworkTypes(10),
        client.listLastRunCountries(10),
        client.listLastRunStartHeights(5),
        client.listLastRunNodes(250),
        client.getLastBlockHeight(ANALYTICS_HEIGHT_NODE).catch(() => null),
      ]);
      const mostRecentRun = runs.find((run) => run.phase === "finished") ?? runs[0] ?? null;
      const detail = mostRecentRun ? await client.getCrawlRun(mostRecentRun.runId) : null;

      setLatestRun(mostRecentRun);
      setLatestDetail(detail);
      setLastRunAsns(nextLastRunAsns);
      setLastRunServices(nextLastRunServices);
      setLastRunNetworkTypes(nextLastRunNetworkTypes);
      setLastRunCountries(nextLastRunCountries);
      setLastRunStartHeights(nextLastRunStartHeights);
      setLastRunNodes(nextLastRunNodes);
      setLastBlockHeight(nextBlockHeight);
    } catch (nextError) {
      setLatestRun(null);
      setLatestDetail(null);
      setLastRunAsns([]);
      setLastRunServices([]);
      setLastRunNetworkTypes([]);
      setLastRunCountries([]);
      setLastRunStartHeights([]);
      setLastRunNodes([]);
      setLastBlockHeight(null);
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setIsLoading(false);
    }
  }

  const networkOutcomes = latestDetail?.networkOutcomes ?? [];
  const hasAnyAnalytics =
    lastRunAsns.length > 0 ||
    lastRunNetworkTypes.length > 0 ||
    lastRunCountries.length > 0 ||
    lastRunStartHeights.length > 0 ||
    lastRunNodes.length > 0 ||
    networkOutcomes.length > 0 ||
    latestRun !== null;
  const leadAsn = lastRunAsns[0] ?? null;
  const dominantNetwork =
    [...lastRunNetworkTypes].sort((left, right) => right.nodeCount - left.nodeCount)[0] ?? null;
  const weakestNetwork =
    [...networkOutcomes].sort((left, right) => left.verifiedPct - right.verifiedPct)[0] ?? null;
  const playback = useCrawlerSignalPlayback(latestDetail);
  const overviewPhaseLabel = playback ? formatPhase(playback.playbackSnapshot.phase) : "Awaiting snapshot";
  const overviewSweepLabel = playback
    ? playback.isLive
      ? "Background sweep active"
      : "Last sweep archived"
    : "Waiting for sweep state";
  const observedNodes = lastRunNetworkTypes.reduce((sum, row) => sum + row.nodeCount, 0);
  const visibleVerifiedNodes = lastRunAsns.reduce((sum, row) => sum + row.nodeCount, 0);
  const asnConcentrationPct =
    visibleVerifiedNodes > 0 && leadAsn ? (leadAsn.nodeCount / visibleVerifiedNodes) * 100 : null;
  const verificationFailurePct = latestRun ? Math.max(0, 100 - latestRun.successPct) : null;
  const frontierGapPct =
    latestRun && latestRun.uniqueNodes > 0
      ? (latestRun.unscheduledGap / latestRun.uniqueNodes) * 100
      : null;
  const weakestNetworkFailurePct = weakestNetwork ? Math.max(0, 100 - weakestNetwork.verifiedPct) : null;
  const transportDiversityScore = computeDiversityScore(
    lastRunNetworkTypes.map((row) => row.nodeCount),
  );
  const transportCentralizationRisk = 100 - transportDiversityScore;
  const persistenceCoveragePct =
    latestRun && latestRun.scheduledTasks > 0
      ? Math.min(100, (latestRun.persistedObservationRows / latestRun.scheduledTasks) * 100)
      : null;
  const decentralizationScore = clampPercent(
    100 -
      ((asnConcentrationPct ?? 100) * 0.5 +
        transportCentralizationRisk * 0.3 +
        (frontierGapPct ?? 100) * 0.2),
  );
  const eclipseExposureScore = clampPercent(
    (asnConcentrationPct ?? 100) * 0.4 +
      transportCentralizationRisk * 0.3 +
      (verificationFailurePct ?? 100) * 0.2 +
      (frontierGapPct ?? 100) * 0.1,
  );
  const observationConfidenceScore = clampPercent(
    (latestRun?.successPct ?? 0) * 0.5 +
      (latestRun?.scheduledPct ?? 0) * 0.3 +
      (persistenceCoveragePct ?? 0) * 0.2,
  );
  const operatorDeckItems = [
    {
      label: "Exchange view",
      detail:
        "Concentration and verification weakness show where market-stress connectivity can become operational risk instead of just crawler trivia.",
    },
    {
      label: "Custody view",
      detail:
        "The snapshot keeps transport balance, frontier pressure, and verification confidence together so teams can reason about resilience before incidents force it.",
    },
    {
      label: "Research view",
      detail:
        "Every score stays tied to source evidence from ASN counts, network outcomes, and the public crawler window rather than decorative KPI filler.",
    },
  ];
  const panelDescription =
    activePanel === "overview"
      ? demoMode
        ? "Public home dashboard from the hosted demo snapshot."
        : "Public home dashboard from the latest finished read-only crawler snapshot."
      : activePanel === "risk"
        ? demoMode
          ? "Inspect the demo risk brief and derived resilience signals without changing the live snapshot surface."
          : "Inspect derived resilience signals and risk brief context from the latest finished crawl run."
      : activePanel === "asn"
        ? demoMode
          ? "Inspect the embedded demo ASN concentration set without depending on the public API."
          : "Inspect where verified nodes concentrate by ASN without leaving the analytics surface."
        : demoMode
          ? "Compare demo observed, verified, and failed nodes by network type for the latest run."
          : "Compare observed, verified, and failed nodes by network type for the latest run.";
  return (
    <Card>
      <CardContent className="space-y-8 p-4 sm:p-6">
        <div className="flex items-center justify-between gap-3 border-b border-border/80 pb-5">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="sr-only">Network Analytics</h1>
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.28em] text-primary">
              Network Risk Snapshot
            </p>
            <HeaderTooltip label="Network Analytics overview" tooltip={panelDescription} />
            {activePanel === "overview" ? (
              <>
                <span className="hidden h-3 w-px bg-border/80 sm:inline-block" />
                <span className="font-mono text-[11px] text-foreground">{overviewPhaseLabel}</span>
                <span className="hidden font-mono text-[11px] text-muted-foreground sm:inline">•</span>
                <span className="text-[11px] text-muted-foreground">{overviewSweepLabel}</span>
              </>
            ) : null}
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
            {showPanelNav ? (
              <div className="flex flex-wrap gap-2">
                <PanelButton
                  label="Overview"
                  selected={activePanel === "overview"}
                  onClick={() => selectPanel("overview")}
                />
                <PanelButton
                  label="Risk"
                  selected={activePanel === "risk"}
                  onClick={() => selectPanel("risk")}
                />
                <PanelButton
                  label="Top ASNs"
                  selected={activePanel === "asn"}
                  onClick={() => selectPanel("asn")}
                />
                <PanelButton
                  label="Verification"
                  selected={activePanel === "verification"}
                  onClick={() => selectPanel("verification")}
                />
              </div>
            ) : null}

            {activePanel === "overview" ? (
              <div className="space-y-6">
                <section className="grid gap-6 xl:grid-cols-[minmax(0,1.58fr)_minmax(16.5rem,0.52fr)] xl:items-stretch">
                  <div className="order-1 h-full xl:order-1">
                    {lastRunCountries.length > 0 ? (
                      <CountryGlobe
                        countries={lastRunCountries}
                        playback={playback}
                      />
                    ) : (
                      <StatusPanel message="No country buckets are available for globe replay." />
                    )}
                  </div>

                  <div className="order-2 xl:order-2">
                    <LastRunSidebarCharts
                      networkTypes={lastRunNetworkTypes}
                      startHeights={lastRunStartHeights}
                    />
                  </div>
                </section>

                <LastRunDashboard
                  asns={lastRunAsns}
                  countries={lastRunCountries}
                  runId={latestRun?.runId ?? null}
                />

                <section className="grid gap-4 xl:grid-cols-[minmax(0,1.14fr)_minmax(15rem,0.86fr)]">
                  <div className="rounded-[16px] border border-primary/20 bg-[linear-gradient(135deg,rgba(245,179,1,0.1),rgba(245,179,1,0.02))] p-4 shadow-[0_16px_30px_rgba(0,0,0,0.16)]">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="muted">API product</Badge>
                      <Badge variant="muted">OpenAPI generated</Badge>
                      <Badge variant="muted">Scalar reference</Badge>
                    </div>
                    <div className="mt-4 space-y-3">
                      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                        Build on the snapshot
                      </p>
                      <p className="max-w-2xl text-sm leading-6 text-muted-foreground">
                        Turn the live crawler snapshot into a sellable integration surface with one generated OpenAPI contract,
                        hosted reference docs, and a cleaner path from analytics preview to production API usage.
                      </p>
                      <Button
                        type="button"
                        variant="secondary"
                        className="w-full sm:w-auto"
                        onClick={onOpenApiPage}
                      >
                        Explore API docs
                      </Button>
                    </div>
                  </div>

                  <div className="rounded-[16px] border border-border/80 bg-background/72 p-4">
                    <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                      Next step
                    </p>
                    <p className="mt-3 text-sm leading-6 text-muted-foreground">
                      Open the API page for docs, packaging, and commercial access framing built around the same generated spec.
                    </p>
                    <Button
                      type="button"
                      className="mt-4 w-full sm:w-auto"
                      onClick={onOpenApiPage}
                    >
                      Explore API
                    </Button>
                  </div>
                </section>

              </div>
            ) : null}

            {activePanel === "risk" ? (
              <div className="space-y-6">
                <section className="grid gap-6 xl:grid-cols-[minmax(0,0.82fr)_minmax(0,1.18fr)]">
                  <div className="w-full self-start rounded-[14px] border border-border/70 bg-[linear-gradient(180deg,rgba(255,255,255,0.03),rgba(255,255,255,0.01))] p-3 shadow-[0_14px_24px_rgba(0,0,0,0.14)]">
                    <div className="flex items-center justify-between gap-3 rounded-[10px] border border-border/60 bg-background/38 px-3 py-2.5">
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                          Control Deck
                        </p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          Derived resilience view from the latest finished crawl run
                        </p>
                      </div>
                      <Badge variant="muted">{latestRun?.phase ?? "awaiting run"}</Badge>
                    </div>

                    <div className="mt-2.5 space-y-2">
                      <ScoreCard
                        label="Decentralization Score"
                        value={`${Math.round(decentralizationScore)}`}
                        emphasis="primary"
                        density="compact"
                        tooltip="Weighted from ASN concentration, transport balance, and uncovered frontier pressure. Higher is healthier."
                        tone={classifyScoreTone(decentralizationScore, { healthy: 68, warning: 48 })}
                        detail={
                          leadAsn
                            ? `${leadAsn.asnOrganization ?? "Unknown ASN"} currently holds the lead in the visible ASN set.`
                            : "Waiting for concentration data from the visible ASN set."
                        }
                        footnote={
                          asnConcentrationPct !== null
                            ? `${asnConcentrationPct.toFixed(1)}% of visible verified nodes concentrate in the leading ASN`
                            : "Derived from ASN concentration, transport spread, and frontier coverage"
                        }
                      />
                      <ScoreCard
                        label="Eclipse Exposure (Proxy)"
                        value={`${Math.round(eclipseExposureScore)}`}
                        emphasis="primary"
                        density="compact"
                        tooltip="Proxy risk from concentration, transport skew, failed verification, and uncovered frontier. Higher means more exposure."
                        tone={classifyRiskTone(eclipseExposureScore, { warning: 42, critical: 62 })}
                        detail={
                          dominantNetwork
                            ? `${dominantNetwork.networkType} currently dominates the observed transport mix.`
                            : "Waiting for transport-mix data from the latest run."
                        }
                        footnote={
                          weakestNetworkFailurePct !== null
                            ? `${weakestNetworkFailurePct.toFixed(1)}% failure pressure on the weakest transport`
                            : "Derived from concentration, transport skew, verification weakness, and frontier gap"
                        }
                      />
                    </div>

                    <div className="mt-2">
                      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
                        <RiskMiniMetric
                          label="Observation Confidence"
                          value={`${Math.round(observationConfidenceScore)}`}
                          tooltip="Confidence in the current public read-only view based on visit success, scheduled coverage, and persistence coverage."
                          tone={classifyScoreTone(observationConfidenceScore, { healthy: 64, warning: 42 })}
                          detail={
                            latestRun
                              ? `${latestRun.successPct.toFixed(1)}% visit success with ${latestRun.scheduledPct.toFixed(1)}% scheduled coverage.`
                              : "Waiting for the latest run summary."
                          }
                          footnote={
                            persistenceCoveragePct !== null
                              ? `${persistenceCoveragePct.toFixed(1)}% persistence coverage`
                              : "Verification, scheduling, persistence coverage"
                          }
                        />
                        <RiskMiniMetric
                          label="Transport Diversity"
                          value={`${Math.round(transportDiversityScore)}`}
                          tooltip="Entropy-style spread across observed network types. Higher means the visible network is less concentrated in one transport."
                          tone={classifyScoreTone(transportDiversityScore, { healthy: 58, warning: 34 })}
                          detail={
                            dominantNetwork
                              ? `${dominantNetwork.networkType} accounts for the largest observed transport slice.`
                              : "Waiting for network outcome rows."
                          }
                          footnote={
                            observedNodes > 0
                              ? `${observedNodes.toLocaleString()} observed nodes`
                              : "Current network-outcome distribution"
                          }
                        />
                      </div>
                    </div>
                  </div>

                  <div className="space-y-6">
                    {latestDetail ? (
                      <RiskDriversStrip
                        runId={latestDetail.run.runId}
                        items={[
                          {
                            label: "Lead Concentration",
                            value:
                              asnConcentrationPct !== null
                                ? `${asnConcentrationPct.toFixed(1)}%`
                                : "n/a",
                            detail: leadAsn
                              ? `${leadAsn.asnOrganization ?? "Unknown ASN"} leads visible verified nodes`
                              : "Waiting for ASN concentration data",
                          },
                          {
                            label: "Weakest Transport",
                            value: weakestNetwork ? weakestNetwork.networkType : "n/a",
                            detail: weakestNetworkFailurePct !== null
                              ? `${weakestNetworkFailurePct.toFixed(1)}% failure pressure on this network`
                              : "Waiting for transport verification mix",
                          },
                          {
                            label: "Frontier Gap",
                            value: frontierGapPct !== null ? `${frontierGapPct.toFixed(1)}%` : "n/a",
                            detail: latestRun
                              ? `${latestRun.unscheduledGap.toLocaleString()} tracked endpoints still unscheduled`
                              : "Waiting for crawl coverage data",
                          },
                          {
                            label: "Chain Height",
                            value: lastBlockHeight ? lastBlockHeight.height.toLocaleString() : "n/a",
                            detail: lastBlockHeight?.bestBlockHash
                              ? `Peer tip ${truncateHash(lastBlockHeight.bestBlockHash)}`
                              : "Read-only peer tip lookup",
                          },
                        ]}
                      />
                    ) : null}

                    <section className="grid gap-6 xl:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
                      <div className="rounded-[14px] border border-border/80 bg-background/72 p-4">
                        <div className="flex items-center justify-between gap-3">
                          <div>
                            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                              What This Means
                            </p>
                            <p className="mt-1 text-sm text-muted-foreground">
                              What this dashboard means in product and risk terms.
                            </p>
                          </div>
                          <Badge variant="muted">
                            {demoMode ? "Demo dataset" : "Latest finished run"}
                          </Badge>
                        </div>

                        <div className="mt-4 grid gap-3">
                          {operatorDeckItems.map((item) => (
                            <OperatorBriefCard key={item.label} label={item.label} detail={item.detail} />
                          ))}
                        </div>
                      </div>

                      <div className="rounded-[14px] border border-border/80 bg-background/72 p-4">
                        <div className="flex items-center justify-between gap-3">
                          <div>
                            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                              Last-Run Inputs
                            </p>
                            <p className="mt-1 text-sm text-muted-foreground">
                              Inputs backing the charts below from the latest finished crawl run.
                            </p>
                          </div>
                          <Badge variant="muted">{lastRunNodes.length} nodes</Badge>
                        </div>

                        <div className="mt-4 grid gap-3 sm:grid-cols-2">
                          <OperatorBriefCard
                            label="Lead Service Flags"
                            detail={
                              lastRunServices[0]
                                ? `${lastRunServices[0].services} appears on ${lastRunServices[0].nodeCount.toLocaleString()} verified nodes in the latest finished run.`
                                : "Waiting for last-run services buckets."
                            }
                          />
                          <OperatorBriefCard
                            label="Transport Leader"
                            detail={
                              dominantNetwork
                                ? `${dominantNetwork.networkType} leads the latest finished run with ${dominantNetwork.nodeCount.toLocaleString()} verified nodes.`
                                : "Waiting for last-run network-type buckets."
                            }
                          />
                        </div>
                      </div>
                    </section>
                  </div>
                </section>
              </div>
            ) : null}

            {activePanel === "asn" ? (
              <section className="space-y-4">
                <div className="flex items-center gap-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                    Top ASNs
                  </p>
                  <Badge variant="muted">{lastRunAsns.length} rows</Badge>
                </div>
                {lastRunAsns.length === 0 ? (
                  <StatusPanel message="No ASN matches were returned yet." />
                ) : (
                  <div className="space-y-4">
                    <AsnConcentrationChart title="ASN Concentration" rows={lastRunAsns} />
                    <div className="overflow-x-auto rounded-[8px] border border-border/80 bg-background/70">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>ASN</TableHead>
                            <TableHead>Organization</TableHead>
                            <TableHead className="text-right">Verified Nodes</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {lastRunAsns.map((row) => (
                            <TableRow key={`${row.asn ?? "none"}-${row.asnOrganization ?? "unknown"}`}>
                              <TableCell className="font-mono">{row.asn ?? "n/a"}</TableCell>
                              <TableCell>{row.asnOrganization ?? "Unknown ASN"}</TableCell>
                              <TableCell className="text-right font-mono">
                                {row.nodeCount.toLocaleString()}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </div>
                )}
              </section>
            ) : null}

            {activePanel === "verification" ? (
              <section className="space-y-4">
                <div className="flex items-center gap-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                    Verification Mix
                  </p>
                  <Badge variant="muted">
                    {latestRun ? `Run ${latestRun.runId}` : "No recent run"}
                  </Badge>
                </div>

                {networkOutcomes.length === 0 ? (
                  <StatusPanel message="No network outcome breakdown is available for the latest run." />
                ) : (
                  <div className="space-y-4">
                    <VerificationMixChart title="Verification Distribution" rows={networkOutcomes} />
                    <div className="overflow-x-auto rounded-[8px] border border-border/80 bg-background/70">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Network</TableHead>
                            <TableHead className="text-right">Observed</TableHead>
                            <TableHead className="text-right">Verified</TableHead>
                            <TableHead className="text-right">Failed</TableHead>
                            <TableHead className="text-right">Verified %</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {networkOutcomes.map((row) => (
                            <TableRow key={row.networkType}>
                              <TableCell className="font-mono">{row.networkType}</TableCell>
                              <TableCell className="text-right font-mono">
                                {row.observations.toLocaleString()}
                              </TableCell>
                              <TableCell className="text-right font-mono">
                                {row.verifiedNodes.toLocaleString()}
                              </TableCell>
                              <TableCell className="text-right font-mono">
                                {row.failedNodes.toLocaleString()}
                              </TableCell>
                              <TableCell className="text-right font-mono">
                                {row.verifiedPct.toFixed(2)}%
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </div>
                )}
              </section>
            ) : null}
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

function PanelButton({
  label,
  selected,
  onClick,
}: {
  label: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <Button type="button" variant={selected ? "default" : "secondary"} size="sm" onClick={onClick}>
      {label}
    </Button>
  );
}

function ScoreCard({
  label,
  value,
  tooltip,
  detail,
  footnote,
  tone,
  emphasis = "secondary",
  density = "regular",
}: {
  label: string;
  value: string;
  tooltip: string;
  detail: string;
  footnote: string;
  tone: "healthy" | "warning" | "critical";
  emphasis?: "primary" | "secondary";
  density?: "regular" | "compact";
}) {
  const toneClass =
    tone === "critical"
      ? "border-[rgba(176,88,63,0.42)] bg-[linear-gradient(180deg,rgba(176,88,63,0.18),rgba(24,12,10,0.74))]"
      : tone === "warning"
        ? "border-primary/28 bg-[linear-gradient(180deg,rgba(245,179,1,0.16),rgba(23,18,8,0.74))]"
        : "border-[rgba(112,145,100,0.3)] bg-[linear-gradient(180deg,rgba(112,145,100,0.16),rgba(11,18,12,0.76))]";
  const badgeClass =
    tone === "critical"
      ? "text-[rgb(241,171,149)]"
      : tone === "warning"
        ? "text-[color:var(--color-primary-strong)]"
        : "text-[rgb(177,214,164)]";
  const isCompact = density === "compact";
  const valueClass =
    emphasis === "primary"
      ? isCompact
        ? "mt-1.5 font-serif text-[2rem] uppercase tracking-[0.03em] text-foreground sm:text-[2.25rem]"
        : "mt-2 font-serif text-3xl uppercase tracking-[0.04em] text-foreground sm:text-[2.5rem]"
      : isCompact
        ? "mt-1.5 font-serif text-[1.5rem] uppercase tracking-[0.05em] text-foreground"
        : "mt-2 font-serif text-[1.75rem] uppercase tracking-[0.06em] text-foreground";
  const shellClass =
    emphasis === "primary"
      ? isCompact
        ? `rounded-[12px] border ${toneClass} p-3.5 shadow-[0_14px_24px_rgba(0,0,0,0.18)]`
        : `rounded-[12px] border ${toneClass} p-4 shadow-[0_16px_30px_rgba(0,0,0,0.2)]`
      : isCompact
        ? `rounded-[12px] border ${toneClass} p-3 shadow-[0_10px_18px_rgba(0,0,0,0.12)]`
        : `rounded-[12px] border ${toneClass} p-3.5 shadow-[0_12px_22px_rgba(0,0,0,0.14)]`;

  return (
    <div className={shellClass}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex items-start gap-1.5">
          <p className="min-w-0 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            {label}
          </p>
          <RiskTooltip label={label} tooltip={tooltip} />
        </div>
        <span
          className={`shrink-0 whitespace-nowrap rounded-full border border-current/14 px-1.5 py-0.5 font-mono text-[9px] leading-none font-semibold uppercase tracking-[0.14em] ${badgeClass}`}
        >
          {tone}
        </span>
      </div>
      <p className={valueClass}>{value}</p>
      <p className={isCompact ? "mt-1 text-[12px] text-foreground" : "mt-1.5 text-[13px] text-foreground"}>
        {detail}
      </p>
      <p className={isCompact ? "mt-1.5 text-[10px] text-muted-foreground" : "mt-2 text-[11px] text-muted-foreground"}>
        {footnote}
      </p>
    </div>
  );
}

function RiskMiniMetric({
  label,
  value,
  tooltip,
  detail,
  footnote,
  tone,
}: {
  label: string;
  value: string;
  tooltip: string;
  detail: string;
  footnote: string;
  tone: "healthy" | "warning" | "critical";
}) {
  const toneClass =
    tone === "critical"
      ? "border-[rgba(176,88,63,0.34)] bg-[rgba(176,88,63,0.1)]"
      : tone === "warning"
        ? "border-primary/24 bg-primary/8"
        : "border-[rgba(112,145,100,0.24)] bg-[rgba(112,145,100,0.08)]";
  const badgeClass =
    tone === "critical"
      ? "text-[rgb(241,171,149)]"
      : tone === "warning"
        ? "text-[color:var(--color-primary-strong)]"
        : "text-[rgb(177,214,164)]";

  return (
    <div className={`rounded-[10px] border ${toneClass} p-3`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex items-start gap-1.5">
          <p className="min-w-0 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            {label}
          </p>
          <RiskTooltip label={label} tooltip={tooltip} />
        </div>
        <span
          className={`shrink-0 whitespace-nowrap rounded-full border border-current/14 px-1.5 py-0.5 font-mono text-[9px] leading-none font-semibold uppercase tracking-[0.14em] ${badgeClass}`}
        >
          {tone}
        </span>
      </div>
      <p className="mt-1.5 font-serif text-[1.5rem] uppercase tracking-[0.05em] text-foreground">{value}</p>
      <p className="mt-1 text-[12px] text-foreground">{detail}</p>
      <p className="mt-1.5 text-[10px] text-muted-foreground">{footnote}</p>
    </div>
  );
}

function RiskTooltip({ label, tooltip }: { label: string; tooltip: string }) {
  return (
    <span className="group/tooltip relative mt-0.5 inline-flex">
      <button
        type="button"
        className="inline-flex h-4 w-4 items-center justify-center rounded-full text-muted-foreground/80 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-label={`${label} score explanation`}
      >
        <CircleHelp className="h-3.5 w-3.5" />
      </button>
      <span
        role="tooltip"
        className="pointer-events-none absolute left-0 top-[calc(100%+0.45rem)] z-10 w-52 rounded-[8px] border border-border/80 bg-popover/96 px-2.5 py-2 text-[11px] leading-4 text-popover-foreground opacity-0 shadow-[0_14px_28px_rgba(0,0,0,0.3)] transition-all duration-150 group-hover/tooltip:translate-y-0.5 group-hover/tooltip:opacity-100 group-focus-within/tooltip:translate-y-0.5 group-focus-within/tooltip:opacity-100"
      >
        {tooltip}
      </span>
    </span>
  );
}

function OperatorBriefCard({ label, detail }: { label: string; detail: string }) {
  return (
    <div className="rounded-[10px] border border-border/75 bg-background/60 px-3 py-3">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
        {label}
      </p>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{detail}</p>
    </div>
  );
}

function RiskDriversStrip({
  runId,
  items,
}: {
  runId: string;
  items: Array<{ label: string; value: string; detail: string }>;
}) {
  return (
    <div className="w-full rounded-[10px] border border-border/70 bg-background/52 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Risk Drivers
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            The strongest factors shaping the current public network view.
          </p>
        </div>
        <p className="font-mono text-xs text-foreground">{runId}</p>
      </div>

      <div className="mt-4 grid w-full gap-3 md:grid-cols-2 xl:grid-cols-4">
        {items.map((item) => (
          <div
            key={item.label}
            className="min-w-0 rounded-[8px] border border-border/70 bg-muted/24 px-3 py-3"
          >
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              {item.label}
            </p>
            <p className="mt-2 truncate font-mono text-lg text-foreground">{item.value}</p>
            <p className="mt-2 text-sm text-muted-foreground">{item.detail}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function AsnConcentrationChart({
  title,
  rows,
}: {
  title: string;
  rows: LastRunAsnCountItem[];
}) {
  const maxValue = Math.max(...rows.map((row) => row.nodeCount), 1);

  return (
    <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">{title}</p>
        <p className="font-mono text-[11px] text-muted-foreground">{rows.length} ASNs</p>
      </div>
      <div className="mt-5 space-y-3">
        {rows.map((row) => (
          <div key={`${title}-${row.asn ?? "none"}-${row.asnOrganization ?? "unknown"}`} className="space-y-2">
            <div className="flex items-end justify-between gap-3">
              <div className="min-w-0">
                <p className="truncate font-mono text-xs text-foreground">{row.asn ?? "n/a"}</p>
              <p className="truncate text-xs text-muted-foreground">
                {row.asnOrganization ?? "Unknown ASN"}
              </p>
            </div>
            <p className="shrink-0 font-mono text-xs text-foreground">
                {row.nodeCount.toLocaleString()}
            </p>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-muted/40">
            <div
              className="h-full rounded-full bg-[linear-gradient(90deg,rgba(245,179,1,0.42),rgba(245,179,1,0.92))]"
                style={{ width: `${Math.max(8, (row.nodeCount / maxValue) * 100)}%` }}
            />
          </div>
        </div>
      ))}
      </div>
    </div>
  );
}

function VerificationMixChart({
  title,
  rows,
}: {
  title: string;
  rows: CrawlRunDetail["networkOutcomes"];
}) {
  return (
    <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">{title}</p>
        <div className="flex flex-wrap gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          <LegendSwatch label="Verified" className="bg-primary" />
          <LegendSwatch label="Failed" className="bg-amber-100/35" />
        </div>
      </div>
      <div className="mt-5 space-y-4">
        {rows.map((row) => {
          const observed = Math.max(row.observations, 1);
          const verifiedWidth = (row.verifiedNodes / observed) * 100;
          const failedWidth = (row.failedNodes / observed) * 100;

          return (
            <div key={`${title}-${row.networkType}`} className="space-y-2">
              <div className="flex items-end justify-between gap-3">
                <div className="min-w-0">
                  <p className="font-mono text-xs text-foreground">{row.networkType}</p>
                  <p className="text-xs text-muted-foreground">
                    {row.observations.toLocaleString()} observed nodes
                  </p>
                </div>
                <p className="shrink-0 font-mono text-xs text-foreground">
                  {row.verifiedPct.toFixed(2)}%
                </p>
              </div>
              <div className="flex h-3 overflow-hidden rounded-full bg-muted/35">
                <div
                  className="h-full bg-[linear-gradient(90deg,rgba(245,179,1,0.58),rgba(245,179,1,0.96))]"
                  style={{ width: `${verifiedWidth}%` }}
                />
                <div
                  className="h-full bg-[linear-gradient(90deg,rgba(245,239,226,0.14),rgba(245,239,226,0.34))]"
                  style={{ width: `${failedWidth}%` }}
                />
              </div>
              <div className="flex justify-between gap-3 text-[11px] text-muted-foreground">
                <span>{row.verifiedNodes.toLocaleString()} verified</span>
                <span>{row.failedNodes.toLocaleString()} failed</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function LegendSwatch({ label, className }: { label: string; className: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`h-2.5 w-2.5 rounded-full ${className}`} />
      <span>{label}</span>
    </span>
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

function classifyScoreTone(
  value: number,
  thresholds: { healthy: number; warning: number },
): "healthy" | "warning" | "critical" {
  if (value >= thresholds.healthy) {
    return "healthy";
  }

  if (value >= thresholds.warning) {
    return "warning";
  }

  return "critical";
}

function classifyRiskTone(
  value: number,
  thresholds: { warning: number; critical: number },
): "healthy" | "warning" | "critical" {
  if (value >= thresholds.critical) {
    return "critical";
  }

  if (value >= thresholds.warning) {
    return "warning";
  }

  return "healthy";
}

function computeDiversityScore(values: number[]): number {
  const counts = values.filter((value) => value > 0);
  const total = counts.reduce((sum, value) => sum + value, 0);

  if (counts.length <= 1 || total <= 0) {
    return 0;
  }

  const entropy = counts.reduce((sum, value) => {
    const share = value / total;
    return sum - share * Math.log2(share);
  }, 0);
  const maxEntropy = Math.log2(counts.length);

  if (maxEntropy <= 0) {
    return 0;
  }

  return clampPercent((entropy / maxEntropy) * 100);
}

function clampPercent(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.max(0, Math.min(100, value));
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

function truncateHash(value: string): string {
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}
