import {
  Activity,
  ChartColumn,
  Database,
  LoaderCircle,
  RotateCw,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import { useEffect, useState } from "react";

import { CrawlerLiveSignal, useCrawlerSignalPlayback } from "@/components/crawler-live-signal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { SectionHeading } from "@/components/ui/section-heading";
import type { BtcAppClient } from "@/lib/api/client";
import type { AsnNodeCountItem, CrawlRunDetail, CrawlRunListItem, LastBlockHeightResult } from "@/lib/api/types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

const ANALYTICS_HEIGHT_NODE = "seed.bitnodes.io:8333";

type RiskApiPageProps = {
  client: BtcAppClient;
};

export function RiskApiPage({ client }: RiskApiPageProps) {
  const demoMode = isDemoModeEnabled();
  const [asnRows, setAsnRows] = useState<AsnNodeCountItem[]>([]);
  const [latestRun, setLatestRun] = useState<CrawlRunListItem | null>(null);
  const [latestDetail, setLatestDetail] = useState<CrawlRunDetail | null>(null);
  const [lastBlockHeight, setLastBlockHeight] = useState<LastBlockHeightResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshPreview();
  }, []);

  async function refreshPreview() {
    setIsLoading(true);
    setError(null);

    try {
      const [runs, nextAsnRows, nextBlockHeight] = await Promise.all([
        client.listCrawlRuns(1),
        client.countNodesByAsn(6),
        client.getLastBlockHeight(ANALYTICS_HEIGHT_NODE).catch(() => null),
      ]);
      const mostRecentRun = runs[0] ?? null;
      const detail = mostRecentRun ? await client.getCrawlRun(mostRecentRun.runId) : null;

      setLatestRun(mostRecentRun);
      setLatestDetail(detail);
      setAsnRows(nextAsnRows);
      setLastBlockHeight(nextBlockHeight);
    } catch (nextError) {
      setLatestRun(null);
      setLatestDetail(null);
      setAsnRows([]);
      setLastBlockHeight(null);
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setIsLoading(false);
    }
  }

  const playback = useCrawlerSignalPlayback(latestDetail);
  const networkOutcomes = latestDetail?.networkOutcomes ?? [];
  const leadAsn = asnRows[0] ?? null;
  const topNetwork = [...networkOutcomes].sort((left, right) => right.observations - left.observations)[0] ?? null;
  const weakestNetwork = [...networkOutcomes].sort((left, right) => left.verifiedPct - right.verifiedPct)[0] ?? null;
  const visibleVerifiedNodes = asnRows.reduce((sum, row) => sum + row.verifiedNodes, 0);
  const asnConcentrationPct =
    visibleVerifiedNodes > 0 && leadAsn ? (leadAsn.verifiedNodes / visibleVerifiedNodes) * 100 : null;
  const snapshotWindowMs = latestRun
    ? Math.max(
        0,
        Date.parse(latestRun.lastCheckpointedAt) - Date.parse(latestRun.startedAt),
      )
    : null;
  const launchSignals = [
    {
      label: "Tracked Endpoints",
      value: (latestRun?.uniqueNodes ?? 24_816).toLocaleString(),
      detail: latestRun
        ? `Latest public snapshot tracked ${latestRun.uniqueNodes.toLocaleString()} endpoints`
        : "Mocked target shape for high-cardinality crawler output",
    },
    {
      label: "Verification Yield",
      value: `${(latestRun?.successPct ?? 41.65).toFixed(2)}%`,
      detail: latestRun
        ? `${latestRun.successfulHandshakes.toLocaleString()} successful handshakes in the current window`
        : "Derived from recent verification success in the preview dataset",
    },
    {
      label: "Lead ASN Share",
      value: asnConcentrationPct !== null ? `${asnConcentrationPct.toFixed(1)}%` : "38.4%",
      detail: leadAsn
        ? `${leadAsn.asnOrganization ?? "Unknown ASN"} leads the visible verified set`
        : "Preview concentration signal for treasury and exchange risk teams",
    },
  ];
  const postureItems = [
    {
      icon: ShieldCheck,
      title: "SLA-Ready Read Path",
      value: "99.95% target",
      detail:
        "Commercial posture is framed as regional read availability, not write-heavy transactional uptime. That keeps the promise aligned with analytics reality.",
    },
    {
      icon: Database,
      title: "High-Cardinality Feeds",
      value: "50M rows/day target",
      detail:
        "The product pitch leans on snapshot deltas, failure mixes, ASN counts, and transport outcomes instead of raw firehose exports by default.",
    },
    {
      icon: ChartColumn,
      title: "Risk-Focused Contract",
      value: "4 core signals",
      detail:
        "Start with decentralization, eclipse exposure, verification confidence, and concentration evidence before expanding to custom analytics slices.",
    },
    {
      icon: Waypoints,
      title: "Operator-Friendly Rollout",
      value: snapshotWindowMs ? formatDuration(snapshotWindowMs) : "5m windows",
      detail:
        "Sell the API around repeatable snapshot windows, historical replay, and alerting hooks rather than a vague ‘node intelligence’ story.",
    },
  ];
  const useCases = [
    {
      title: "Treasury and Custody Risk",
      detail:
        "Flag concentration drift, verification deterioration, and transport imbalance before internal connectivity assumptions become blind spots.",
    },
    {
      title: "Exchange Reliability",
      detail:
        "Watch snapshot health and tip continuity during market stress without wiring peer protocol logic into product services.",
    },
    {
      title: "Research and Compliance",
      detail:
        "Export reproducible snapshots with traceable scores so analysts can defend why a given run looked risky or healthy.",
    },
  ];
  const previewResponse = JSON.stringify(
    {
      snapshot_at: latestRun?.lastCheckpointedAt ?? "2026-03-31T18:04:58Z",
      run_id: latestRun?.runId ?? "crawl-demo-2026-03-31-1800",
      tracked_endpoints: latestRun?.uniqueNodes ?? 24_816,
      verified_ratio_pct: Number((latestRun?.successPct ?? 41.65).toFixed(2)),
      lead_asn: leadAsn?.asn ?? 24940,
      lead_asn_share_pct: Number((asnConcentrationPct ?? 38.4).toFixed(1)),
      dominant_transport: topNetwork?.networkType ?? "ipv4",
      weakest_transport: weakestNetwork?.networkType ?? "torv3",
      chain_height: lastBlockHeight?.height ?? 892_345,
      product_scores: {
        decentralization: 62,
        eclipse_exposure: 37,
        observation_confidence: 71,
        market_readiness: 68,
      },
    },
    null,
    2,
  );
  const headerStats = [
    {
      label: "Contract",
      value: "preview-v0",
      detail: "Mocked browser-only commercial surface",
    },
    {
      label: "SLA Target",
      value: "99.95%",
      detail: "Design target for regional read availability",
    },
    {
      label: "Snapshot Window",
      value: snapshotWindowMs ? formatDuration(snapshotWindowMs) : "5m 0s",
      detail: latestRun
        ? `${latestRun.uniqueNodes.toLocaleString()} tracked endpoints in latest window`
        : "Preview cadence before live commercial rollout",
    },
    {
      label: "Tip Height",
      value: lastBlockHeight ? lastBlockHeight.height.toLocaleString() : "892,345",
      detail: lastBlockHeight?.bestBlockHash
        ? `Tip ${truncateHash(lastBlockHeight.bestBlockHash)}`
        : "Read-only chain tip context",
    },
  ];

  return (
    <Card>
      <CardContent className="space-y-8 p-4 sm:p-6">
        <SectionHeading
          eyebrow="Commercial Preview"
          title="Network Risk API"
          description={
            demoMode
              ? "Mocked product page for selling Bitcoin network risk analytics before the commercial API ships."
              : "Preview the commercial API posture using the current read-only analytics shape without pretending the SLA already exists."
          }
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
                aria-label="Refresh risk API preview"
                title="Refresh risk API preview"
                onClick={() => void refreshPreview()}
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

        {error ? (
          <PreviewBanner
            tone="error"
            title="Preview is showing mocked commercial framing only"
            detail={`Live analytics refresh failed: ${error}`}
          />
        ) : null}

        <section className="grid gap-6 xl:grid-cols-[minmax(0,1.08fr)_minmax(0,0.92fr)]">
          <div className="fx-ambient-panel fx-fade-up space-y-5 rounded-[18px] border border-primary/18 p-5 shadow-[0_18px_36px_rgba(0,0,0,0.24)]">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="muted">Preview only</Badge>
              <Badge variant="muted">Web mock</Badge>
              <Badge variant="muted">Read-only analytics</Badge>
            </div>
            <div className="space-y-3">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.22em] text-primary">
                Quiet product surface, evidence-first story
              </p>
              <div className="space-y-2">
                <h2 className="max-w-3xl font-serif text-3xl uppercase tracking-[0.04em] text-foreground sm:text-[2.5rem]">
                  Bitcoin network risk intelligence, packaged as a clean API product.
                </h2>
                <p className="max-w-2xl text-sm leading-6 text-muted-foreground">
                  This stays web-only and mocked for now, but the commercial story is clearer:
                  repeatable snapshots, defensible risk signals, and evidence teams can actually use.
                </p>
              </div>
            </div>

            <div className="rounded-[12px] border border-border/75 bg-background/50 px-4 py-3">
              <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
                <span className="font-mono uppercase tracking-[0.18em] text-primary">Signal Loop</span>
                <span>Snapshot cadence over dashboard noise</span>
              </div>
              <div className="fx-signal-track mt-3 h-[3px] rounded-full" />
            </div>

            <div className="grid gap-3 md:grid-cols-3">
              {launchSignals.map((item) => (
                <HeroSignalCard
                  key={item.label}
                  label={item.label}
                  value={item.value}
                  detail={item.detail}
                />
              ))}
            </div>

            <PreviewBanner
              tone="neutral"
              title="Commercial posture is intentionally honest"
              detail="Everything here stays mocked in the web build. The page sells the eventual API shape, but does not claim live commercial SLA or billing yet."
            />
          </div>

          <div className="space-y-4">
            <div className="rounded-[16px] border border-border/80 bg-background/74 p-4 shadow-[0_16px_28px_rgba(0,0,0,0.18)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                    Product posture
                  </p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Minimal promises, strong evidence, realistic rollout.
                  </p>
                </div>
                <Badge variant="muted">No fake launch claims</Badge>
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                {postureItems.map((item) => (
                  <PostureCard
                    key={item.title}
                    icon={item.icon}
                    title={item.title}
                    value={item.value}
                    detail={item.detail}
                  />
                ))}
              </div>
            </div>

            <div className="rounded-[16px] border border-border/80 bg-background/74 p-4">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                Commercial primitives
              </p>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <CommercialMetric
                  label="Alerting posture"
                  value="Webhook roadmap"
                  detail="Start with pull APIs plus incident digests before offering heavier streaming contracts."
                />
                <CommercialMetric
                  label="Latency target"
                  value="< 90s snapshot publish"
                  detail="Fast enough for operations and risk review without pretending this is market-data infrastructure."
                />
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-[minmax(0,1.02fr)_minmax(0,0.98fr)]">
          <div className="space-y-4">
            <div className="rounded-[16px] border border-border/80 bg-background/74 p-4 shadow-[0_16px_28px_rgba(0,0,0,0.18)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                    Evidence snapshot
                  </p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Keep the crawler visible, but let it support the product story instead of dominating it.
                  </p>
                </div>
                <Badge variant="muted">{latestRun?.phase ?? "awaiting run"}</Badge>
              </div>

              <div className="fx-signal-track mt-4 h-[2px] rounded-full" />

              <div className="mt-4">
                {latestDetail ? (
                  <div className="fx-float-soft">
                    <CrawlerLiveSignal detail={latestDetail} playback={playback} variant="hero" />
                  </div>
                ) : (
                  <PreviewBanner
                    tone="neutral"
                    title="Snapshot replay stays mocked for now"
                    detail="The product page still keeps a crawler-shaped evidence panel even when live analytics are unavailable."
                  />
                )}
              </div>
            </div>

            <div className="rounded-[16px] border border-border/80 bg-background/74 p-4">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-primary">
                Why teams buy this
              </p>
              <div className="mt-4 grid gap-3">
                {useCases.map((item) => (
                  <UseCaseCard key={item.title} title={item.title} detail={item.detail} />
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <CodeWindow
              title="Example Snapshot Contract"
              eyebrow="Payload preview"
              caption="Start small: snapshot identity, concentration evidence, transport mix, and business-facing scores."
              code={previewResponse}
            />

            <div className="rounded-[16px] border border-border/80 bg-background/74 p-4">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                Launch shape
              </p>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <CommercialMetric
                  label="Historical access"
                  value="Run replay + deltas"
                  detail="Monetize change over time. Historical comparisons carry more value than one-off dashboard screenshots."
                />
                <CommercialMetric
                  label="Proof surface"
                  value="ASN + transport evidence"
                  detail="Scores stay close to the tables and distributions that make them credible."
                />
              </div>
            </div>
          </div>
        </section>
      </CardContent>
    </Card>
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

function HeroSignalCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-[12px] border border-border/70 bg-background/58 p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-2 font-serif text-[1.8rem] uppercase tracking-[0.04em] text-foreground">
        {value}
      </p>
      <p className="mt-1.5 text-[12px] leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
}

function PostureCard({
  icon: Icon,
  title,
  value,
  detail,
}: {
  icon: typeof Activity;
  title: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-[12px] border border-border/75 bg-background/68 p-3">
      <div className="flex items-center gap-2.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-[8px] border border-primary/18 bg-primary/10 text-primary">
          <Icon className="h-4 w-4" />
        </span>
        <div className="min-w-0">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            {title}
          </p>
          <p className="mt-1 font-mono text-sm text-foreground">{value}</p>
        </div>
      </div>
      <p className="mt-2.5 text-[12px] leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
}

function PreviewBanner({
  tone,
  title,
  detail,
}: {
  tone: "neutral" | "error";
  title: string;
  detail: string;
}) {
  const shellClass =
    tone === "error"
      ? "rounded-[12px] border border-[rgba(176,88,63,0.38)] bg-[rgba(176,88,63,0.12)] p-3"
      : "rounded-[12px] border border-border/80 bg-background/62 p-3";

  return (
    <div className={shellClass}>
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
        {title}
      </p>
      <p className="mt-1 text-sm leading-6 text-muted-foreground">{detail}</p>
    </div>
  );
}

function CodeWindow({
  title,
  eyebrow,
  caption,
  code,
}: {
  title: string;
  eyebrow: string;
  caption: string;
  code: string;
}) {
  return (
    <div className="rounded-[16px] border border-border/80 bg-background/74 p-4 shadow-[0_16px_28px_rgba(0,0,0,0.18)]">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
            {eyebrow}
          </p>
          <h3 className="mt-1 text-lg text-foreground">{title}</h3>
        </div>
        <Badge variant="muted">JSON</Badge>
      </div>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{caption}</p>
      <div className="mt-4 overflow-x-auto rounded-[12px] border border-border/70 bg-[#050505] p-3">
        <pre className="font-mono text-[12px] leading-6 text-primary-strong">{code}</pre>
      </div>
    </div>
  );
}

function UseCaseCard({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-[12px] border border-border/75 bg-background/68 p-3">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
        {title}
      </p>
      <p className="mt-2.5 text-sm leading-6 text-muted-foreground">{detail}</p>
    </div>
  );
}

function CommercialMetric({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-[12px] border border-border/75 bg-background/68 p-3">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1.5 font-mono text-sm text-foreground">{value}</p>
      <p className="mt-2 text-[12px] leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
}

function truncateHash(hash: string): string {
  return `${hash.slice(0, 10)}…${hash.slice(-8)}`;
}

function formatDuration(durationMs: number): string {
  const totalSeconds = Math.max(0, Math.floor(durationMs / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  if (minutes === 0) {
    return `${seconds}s`;
  }

  return `${minutes}m ${seconds}s`;
}
