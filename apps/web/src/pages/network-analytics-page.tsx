import { LoaderCircle, RotateCw } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { SectionHeading } from "@/components/ui/section-heading";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { BtcAppClient } from "@/lib/api/client";
import type { AsnNodeCountItem, CrawlRunDetail, CrawlRunListItem } from "@/lib/api/types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

export type NetworkAnalyticsPanel = "overview" | "asn" | "verification";

type NetworkAnalyticsPageProps = {
  client: BtcAppClient;
  activePanel?: NetworkAnalyticsPanel;
  onPanelChange?: (panel: NetworkAnalyticsPanel) => void;
  showPanelNav?: boolean;
};

export function NetworkAnalyticsPage({
  client,
  activePanel: controlledActivePanel,
  onPanelChange,
  showPanelNav = true,
}: NetworkAnalyticsPageProps) {
  const demoMode = isDemoModeEnabled();
  const [asnRows, setAsnRows] = useState<AsnNodeCountItem[]>([]);
  const [latestRun, setLatestRun] = useState<CrawlRunListItem | null>(null);
  const [latestDetail, setLatestDetail] = useState<CrawlRunDetail | null>(null);
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
      const [runs, nextAsnRows] = await Promise.all([
        client.listCrawlRuns(1),
        client.countNodesByAsn(10),
      ]);
      const mostRecentRun = runs[0] ?? null;
      const detail = mostRecentRun ? await client.getCrawlRun(mostRecentRun.runId) : null;

      setLatestRun(mostRecentRun);
      setLatestDetail(detail);
      setAsnRows(nextAsnRows);
    } catch (nextError) {
      setLatestRun(null);
      setLatestDetail(null);
      setAsnRows([]);
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setIsLoading(false);
    }
  }

  const networkOutcomes = latestDetail?.networkOutcomes ?? [];
  const hasAnyAnalytics = asnRows.length > 0 || networkOutcomes.length > 0 || latestRun !== null;
  const leadAsn = asnRows[0] ?? null;
  const secondAsn = asnRows[1] ?? null;
  const topNetwork = [...networkOutcomes].sort((left, right) => right.verifiedNodes - left.verifiedNodes)[0] ?? null;
  const weakestNetwork =
    [...networkOutcomes].sort((left, right) => left.verifiedPct - right.verifiedPct)[0] ?? null;
  const panelDescription =
    activePanel === "overview"
      ? demoMode
        ? "Review deterministic demo analytics while the public crawler API remains undeployed."
        : "Use the public read-only analytics contract for ASN concentration and recent verification outcomes."
      : activePanel === "asn"
        ? demoMode
          ? "Inspect the embedded demo ASN concentration set without depending on the public API."
          : "Inspect where verified nodes concentrate by ASN without leaving the analytics surface."
        : demoMode
          ? "Compare demo observed, verified, and failed nodes by network type for the latest run."
          : "Compare observed, verified, and failed nodes by network type for the latest run.";
  const headerStats =
    activePanel === "overview"
      ? [
          {
            label: "Latest Run",
            value: latestRun?.runId ?? "No recent run",
            detail: latestRun?.phase ?? "No phase recorded",
          },
          {
            label: "Verified Success",
            value: latestRun ? `${latestRun.successPct.toFixed(2)}%` : "n/a",
            detail: latestRun
              ? `${latestRun.successfulHandshakes.toLocaleString()} successful visits`
              : "No run loaded",
          },
          {
            label: "Tracked Nodes",
            value: latestRun ? latestRun.uniqueNodes.toLocaleString() : "n/a",
            detail: latestRun
              ? `${latestRun.unscheduledGap.toLocaleString()} still unscheduled`
              : "No frontier context",
          },
          {
            label: "Persisted Rows",
            value: latestRun ? latestRun.persistedObservationRows.toLocaleString() : "n/a",
            detail: latestRun ? formatTimestamp(latestRun.lastCheckpointedAt) : "No checkpoint timestamp",
          },
        ]
      : activePanel === "asn"
        ? [
            {
              label: "Lead ASN",
              value: leadAsn?.asn ?? "n/a",
              detail: leadAsn?.asnOrganization ?? "No ASN concentration returned",
            },
            {
              label: "Lead Verified",
              value: leadAsn?.verifiedNodes ?? "n/a",
              detail: leadAsn ? "Verified nodes tied to the leading ASN" : "No ASN rows available",
            },
            {
              label: "Second ASN",
              value: secondAsn?.asn ?? "n/a",
              detail: secondAsn?.asnOrganization ?? "No second ASN available",
            },
            {
              label: "ASN Rows",
              value: asnRows.length,
              detail: latestRun ? `Latest run ${latestRun.runId}` : "Current analytics snapshot",
            },
          ]
        : [
            {
              label: "Best Network",
              value: topNetwork?.networkType ?? "n/a",
              detail: topNetwork ? `${topNetwork.verifiedPct.toFixed(2)}% verified` : "No outcome rows available",
            },
            {
              label: "Weakest Network",
              value: weakestNetwork?.networkType ?? "n/a",
              detail: weakestNetwork
                ? `${weakestNetwork.verifiedPct.toFixed(2)}% verified`
                : "No outcome rows available",
            },
            {
              label: "Observed Nodes",
              value: networkOutcomes.reduce((sum, row) => sum + row.observations, 0),
              detail: "Observed nodes across the current network breakdown",
            },
            {
              label: "Latest Run",
              value: latestRun?.runId ?? "No recent run",
              detail: latestRun?.phase ?? "No phase recorded",
            },
          ];

  return (
    <Card>
      <CardContent className="space-y-8 p-4 sm:p-6">
        <SectionHeading
          eyebrow="Network Analytics"
          title="Network Analytics"
          description={panelDescription}
          actions={
            <div className="flex w-full flex-wrap items-center justify-end gap-2 sm:w-auto">
              {headerStats.map((stat) => (
                <HeaderStat
                  key={stat.label}
                  label={stat.label}
                  value={stat.value}
                  detail={stat.detail}
                />
              ))}
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
          }
        />

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
                <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                  <OverviewCard
                    title="Latest Run Focus"
                    items={[
                      {
                        label: "Latest run",
                        value: latestRun?.runId ?? "No recent run",
                      },
                      {
                        label: "Visit success",
                        value: latestRun ? `${latestRun.successPct.toFixed(2)}%` : "n/a",
                      },
                      {
                        label: "Lead ASN",
                        value: leadAsn
                          ? `${leadAsn.asn ?? "n/a"} · ${leadAsn.asnOrganization ?? "Unknown ASN"}`
                          : "No ASN concentration returned",
                      },
                      {
                        label: "Top network",
                        value: topNetwork
                          ? `${topNetwork.networkType} · ${topNetwork.verifiedPct.toFixed(2)}% verified`
                          : "No network outcome breakdown returned",
                      },
                    ]}
                  />
                  <OverviewCard
                    title="What This View Shows"
                    items={[
                      {
                        label: "ASN concentration",
                        value: "Use Top ASNs to inspect where verified nodes cluster.",
                      },
                      {
                        label: "Verification mix",
                        value: "Use Verification to compare observed, verified, and failed nodes by network.",
                      },
                      {
                        label: "Run context",
                        value: latestRun
                          ? `${latestRun.uniqueNodes.toLocaleString()} tracked nodes with ${latestRun.unscheduledGap.toLocaleString()} still unscheduled.`
                          : "No latest run context is available.",
                      },
                    ]}
                  />
                </div>
                <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                  <AsnConcentrationChart title="ASN Concentration" rows={asnRows} />
                  <VerificationMixChart title="Verification Distribution" rows={networkOutcomes} />
                </div>
              </div>
            ) : null}

            {activePanel === "asn" ? (
              <section className="space-y-4">
                <div className="flex items-center gap-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                    Top ASNs
                  </p>
                  <Badge variant="muted">{asnRows.length} rows</Badge>
                </div>
                {asnRows.length === 0 ? (
                  <StatusPanel message="No ASN matches were returned yet." />
                ) : (
                  <div className="space-y-4">
                    <AsnConcentrationChart title="ASN Concentration" rows={asnRows} />
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
                          {asnRows.map((row) => (
                            <TableRow key={`${row.asn ?? "none"}-${row.asnOrganization ?? "unknown"}`}>
                              <TableCell className="font-mono">{row.asn ?? "n/a"}</TableCell>
                              <TableCell>{row.asnOrganization ?? "Unknown ASN"}</TableCell>
                              <TableCell className="text-right font-mono">
                                {row.verifiedNodes.toLocaleString()}
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

function OverviewCard({
  title,
  items,
}: {
  title: string;
  items: { label: string; value: string }[];
}) {
  return (
    <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">{title}</p>
      <div className="mt-4 grid gap-4">
        {items.map((item) => (
          <div key={`${title}-${item.label}`} className="grid gap-1">
            <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              {item.label}
            </p>
            <p className="text-sm text-foreground">{item.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function HeaderStat({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="min-w-[8rem] rounded-[8px] border border-border/70 bg-background/75 px-2.5 py-2 text-left sm:min-w-[8.75rem]">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 break-all font-mono text-[13px] text-foreground">{value}</p>
      <p className="mt-1 truncate text-[11px] text-muted-foreground">{detail}</p>
    </div>
  );
}

function AsnConcentrationChart({
  title,
  rows,
}: {
  title: string;
  rows: AsnNodeCountItem[];
}) {
  const maxValue = Math.max(...rows.map((row) => row.verifiedNodes), 1);

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
                {row.verifiedNodes.toLocaleString()}
              </p>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-muted/40">
              <div
                className="h-full rounded-full bg-[linear-gradient(90deg,rgba(245,179,1,0.42),rgba(245,179,1,0.92))]"
                style={{ width: `${Math.max(8, (row.verifiedNodes / maxValue) * 100)}%` }}
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

function formatTimestamp(value: string): string {
  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}
