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
      ? "Use the public read-only analytics contract for ASN concentration and recent verification outcomes."
      : activePanel === "asn"
        ? "Inspect where verified nodes concentrate by ASN without leaving the analytics surface."
        : "Compare observed, verified, and failed nodes by network type for the latest run.";
  const summaryCards =
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
            detail: latestRun ? `${latestRun.successfulHandshakes} successful visits` : "No run loaded",
          },
          {
            label: "Tracked Nodes",
            value: latestRun?.uniqueNodes ?? "n/a",
            detail: latestRun ? `${latestRun.unscheduledGap} still unscheduled` : "No frontier context",
          },
          {
            label: "Persisted Rows",
            value: latestRun?.persistedObservationRows ?? "n/a",
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
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Network Analytics"
          title="Network Analytics"
          description={panelDescription}
          actions={
            <Button
              type="button"
              variant="secondary"
              onClick={() => void refreshAnalytics()}
              disabled={isLoading}
            >
              {isLoading ? (
                <LoaderCircle className="h-4 w-4 animate-spin" />
              ) : (
                <RotateCw className="h-4 w-4" />
              )}
              Refresh
            </Button>
          }
        />

        {latestRun ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {summaryCards.map((card) => (
              <MetricCard
                key={card.label}
                label={card.label}
                value={card.value}
                detail={card.detail}
              />
            ))}
          </div>
        ) : null}

        {isLoading ? (
          <StatusPanel message="Loading ASN concentration and recent verification outcomes." />
        ) : error ? (
          <StatusPanel tone="error" message={`Network analytics failed to load: ${error}`} />
        ) : !hasAnyAnalytics ? (
          <StatusPanel message="No crawler analytics are available yet. Run the crawler locally or point the app at a populated API." />
        ) : (
          <div className="space-y-6">
            <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
              <div className="flex flex-wrap items-center gap-3">
                <p className="font-mono text-sm text-foreground">
                  {latestRun ? latestRun.runId : "No recent run"}
                </p>
                <Badge variant="muted">{latestRun ? latestRun.phase : "Analytics snapshot"}</Badge>
              </div>
              <p className="mt-3 text-sm text-muted-foreground">
                Pick one slice instead of rendering every analytics table at once.
              </p>
            </div>

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
                        ? `${latestRun.uniqueNodes} tracked nodes with ${latestRun.unscheduledGap} still unscheduled.`
                        : "No latest run context is available.",
                    },
                  ]}
                />
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
                            <TableCell className="text-right font-mono">{row.verifiedNodes}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
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
                            <TableCell className="text-right font-mono">{row.observations}</TableCell>
                            <TableCell className="text-right font-mono">{row.verifiedNodes}</TableCell>
                            <TableCell className="text-right font-mono">{row.failedNodes}</TableCell>
                            <TableCell className="text-right font-mono">
                              {row.verifiedPct.toFixed(2)}%
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
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

function MetricCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-3 break-all font-mono text-base text-foreground">{value}</p>
      <p className="mt-2 text-sm text-muted-foreground">{detail}</p>
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

function formatTimestamp(value: string): string {
  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}
