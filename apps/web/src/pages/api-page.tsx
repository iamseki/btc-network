import { Database, KeyRound, LoaderCircle, RotateCw, ShieldCheck } from "lucide-react";
import { Suspense, lazy, useEffect, useState } from "react";

import {
  AnalyticsHeaderStat,
  AnalyticsPanelButton,
} from "@/components/analytics/page-primitives";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SectionHeading } from "@/components/ui/section-heading";
import type { BtcAppClient } from "@/lib/api/client";
import { getDocsUiConfig, getOpenApiDocument } from "@/lib/api/docs-http";
import type { AsnNodeCountItem, CrawlRunListItem, DocsUiConfig } from "@/lib/api/types";

export type ApiPanel = "overview" | "access" | "docs";

const ScalarApiReference = lazy(async () => {
  const module = await import("@scalar/api-reference-react");
  return { default: module.ApiReferenceReact };
});

type ApiPageProps = {
  client: BtcAppClient;
  activePanel?: ApiPanel;
  onPanelChange?: (panel: ApiPanel) => void;
  showPanelNav?: boolean;
};

export function ApiPage({
  client,
  activePanel: controlledActivePanel,
  onPanelChange,
  showPanelNav = true,
}: ApiPageProps) {
  const [latestRun, setLatestRun] = useState<CrawlRunListItem | null>(null);
  const [asnRows, setAsnRows] = useState<AsnNodeCountItem[]>([]);
  const [internalActivePanel, setInternalActivePanel] = useState<ApiPanel>("docs");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [docsUiConfig, setDocsUiConfig] = useState<DocsUiConfig | null>(null);
  const [openApiDocument, setOpenApiDocument] = useState<Record<string, unknown> | null>(null);
  const [isDocsLoading, setIsDocsLoading] = useState(false);
  const [docsError, setDocsError] = useState<string | null>(null);

  const activePanel = controlledActivePanel ?? internalActivePanel;

  useEffect(() => {
    void refreshPreview();
  }, []);

  useEffect(() => {
    if (activePanel !== "docs" || openApiDocument !== null) {
      return;
    }

    let cancelled = false;
    async function loadDocs() {
      setIsDocsLoading(true);
      setDocsError(null);

      try {
        const nextDocsUiConfig = await getDocsUiConfig();
        const nextOpenApiDocument = await getOpenApiDocument(nextDocsUiConfig.openapiPath);

        if (!cancelled) {
          setDocsUiConfig(nextDocsUiConfig);
          setOpenApiDocument(nextOpenApiDocument);
        }
      } catch (nextError) {
        if (!cancelled) {
          setDocsError(nextError instanceof Error ? nextError.message : String(nextError));
        }
      } finally {
        if (!cancelled) {
          setIsDocsLoading(false);
        }
      }
    }

    void loadDocs();

    return () => {
      cancelled = true;
    };
  }, [activePanel, openApiDocument]);

  function selectPanel(panel: ApiPanel) {
    onPanelChange?.(panel);
    if (controlledActivePanel === undefined) {
      setInternalActivePanel(panel);
    }
  }

  async function refreshPreview() {
    setIsLoading(true);
    setError(null);

    try {
      const [runs, nextAsnRows] = await Promise.all([client.listCrawlRuns(1), client.countNodesByAsn(6)]);
      setLatestRun(runs[0] ?? null);
      setAsnRows(nextAsnRows);
    } catch (nextError) {
      setLatestRun(null);
      setAsnRows([]);
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setIsLoading(false);
    }
  }

  const leadAsn = asnRows[0] ?? null;
  const visibleVerifiedNodes = asnRows.reduce((sum, row) => sum + row.verifiedNodes, 0);
  const asnConcentrationPct =
    visibleVerifiedNodes > 0 && leadAsn ? (leadAsn.verifiedNodes / visibleVerifiedNodes) * 100 : null;
  const snapshotWindowMs = latestRun
    ? Math.max(0, Date.parse(latestRun.lastCheckpointedAt) - Date.parse(latestRun.startedAt))
    : null;
  const panelDescription =
    activePanel === "overview"
      ? "Operational Bitcoin network intelligence for resilience, concentration, and verification analysis."
      : "Project access, API keys, and subscription controls for production teams.";
  const headerStats = [
    {
      label: "Surface",
      value: "early-access",
      detail: "Commercial launch track",
    },
    {
      label: "Target SLA",
      value: "99.95%",
      detail: "Regional read availability target",
    },
    {
      label: "Latest Window",
      value: snapshotWindowMs ? formatDuration(snapshotWindowMs) : "5m 0s",
      detail: latestRun ? `${latestRun.uniqueNodes.toLocaleString()} tracked endpoints` : "Rolling snapshot cadence",
    },
  ];
  const overviewSignals = [
    {
      label: "Verification Yield",
      value: `${(latestRun?.successPct ?? 41.65).toFixed(2)}%`,
      detail: latestRun
        ? `${latestRun.successfulHandshakes.toLocaleString()} successful handshakes in the latest window`
        : "Current verification quality signal",
    },
    {
      label: "Lead ASN Share",
      value: asnConcentrationPct !== null ? `${asnConcentrationPct.toFixed(1)}%` : "38.4%",
      detail: leadAsn
        ? `${leadAsn.asnOrganization ?? "Unknown ASN"} leads the visible verified set`
        : "Current concentration signal",
    },
    {
      label: "Tracked Endpoints",
      value: (latestRun?.uniqueNodes ?? 24_816).toLocaleString(),
      detail: latestRun ? "Current latest public snapshot" : "Current launch baseline",
    },
  ];
  const useCases = [
    {
      title: "Treasury and Custody",
      detail: "Track concentration drift and resilience weakness before internal assumptions become blind spots.",
    },
    {
      title: "Exchange Reliability",
      detail: "Watch network quality and snapshot continuity during stressed periods without embedding peer protocol logic into product services.",
    },
    {
      title: "Research and Compliance",
      detail: "Use reproducible runs, explicit scores, and supporting evidence when teams need to defend why risk moved.",
    },
  ];
  const accessSteps = [
    {
      icon: KeyRound,
      title: "Get an API key",
      detail: "Start with one project-scoped key per environment. The first launch should prefer simple project ownership over team-wide RBAC complexity.",
    },
    {
      icon: Database,
      title: "Pick a subscription",
      detail: "Entry plan for delayed snapshots, growth plan for historical replay and alerts, enterprise plan for higher limits and support posture.",
    },
    {
      icon: ShieldCheck,
      title: "Manage usage safely",
      detail: "Default to bearer keys, rate limits, request logs, and clear monthly quotas before building advanced auth features.",
    },
  ];
  const pricingRows = [
    {
      label: "Starter",
      value: "$99/mo",
      detail: "Delayed snapshots, small monthly quota, browser dashboard access.",
    },
    {
      label: "Growth",
      value: "$499/mo",
      detail: "Higher request limits, replay windows, webhook digests, faster refresh cadence.",
    },
    {
      label: "Enterprise",
      value: "Custom",
      detail: "Commercial SLA, private support, and tailored retention or export posture.",
    },
  ];

  if (activePanel === "docs") {
    return (
      <EmbeddedApiReference
        docsUiConfig={docsUiConfig}
        openApiDocument={openApiDocument}
        isLoading={isDocsLoading}
        error={docsError}
      />
    );
  }

  return (
    <div className="space-y-8 rounded-[20px] border border-border/80 bg-card/82 p-4 shadow-[0_24px_48px_rgba(0,0,0,0.22)] sm:p-6">
      <SectionHeading
        eyebrow="Commercial API"
        title="API"
        description={panelDescription}
        actions={
          <div className="flex w-full flex-wrap items-center justify-end gap-2 sm:w-auto">
            {headerStats.map((stat) => (
              <AnalyticsHeaderStat
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
              aria-label="Refresh API metrics"
              title="Refresh API metrics"
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

      {showPanelNav ? (
        <div className="flex flex-wrap gap-2">
          <AnalyticsPanelButton
            label="Docs"
            selected={false}
            onClick={() => selectPanel("docs")}
          />
          <AnalyticsPanelButton
            label="Overview"
            selected={activePanel === "overview"}
            onClick={() => selectPanel("overview")}
          />
          <AnalyticsPanelButton
            label="Access"
            selected={activePanel === "access"}
            onClick={() => selectPanel("access")}
          />
        </div>
      ) : null}

      {error ? (
        <PreviewBanner
          tone="error"
          title="Live analytics are temporarily unavailable"
          detail={`Showing baseline commercial content while refresh failed: ${error}`}
        />
      ) : null}

      {activePanel === "overview" ? (
        <div className="space-y-6">
            <section className="fx-ambient-panel fx-fade-up rounded-[18px] border border-primary/18 p-5 shadow-[0_18px_36px_rgba(0,0,0,0.24)]">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="muted">Early access</Badge>
                <Badge variant="muted">Founding teams</Badge>
                <Badge variant="muted">Docs live</Badge>
              </div>
              <div className="mt-4">
                <p className="max-w-2xl text-sm leading-6 text-muted-foreground">
                  Resilient Bitcoin network analytics for teams that need faster answers on concentration,
                  verification quality, and historical drift without operating their own crawl stack.
                </p>
              </div>
              <div className="fx-signal-track mt-4 h-[3px] rounded-full" />
              <div className="mt-5 grid gap-3 md:grid-cols-3">
                {overviewSignals.map((item) => (
                  <HeroSignalCard
                    key={item.label}
                    label={item.label}
                    value={item.value}
                    detail={item.detail}
                  />
                ))}
              </div>
            </section>

            <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <div className="rounded-[16px] border border-border/80 bg-background/74 p-4">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                  Why teams buy this
                </p>
                <div className="mt-4 grid gap-3">
                  {useCases.map((item) => (
                    <UseCaseCard key={item.title} title={item.title} detail={item.detail} />
                  ))}
                </div>
              </div>

              <div className="rounded-[16px] border border-border/80 bg-background/74 p-4">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                  Launch posture
                </p>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <CommercialMetric
                    label="API surface"
                    value="Analytics-first"
                    detail="Lead with crawl runs, run detail, latest-run distributions, and verified node inventory before expanding the contract."
                  />
                  <CommercialMetric
                    label="SLA posture"
                    value="Regional read availability"
                    detail="Commercial promise should match the product: stable read access, not write-heavy transactional guarantees."
                  />
                  <CommercialMetric
                    label="Latency target"
                    value="< 90s publish"
                    detail="Fast enough for operations and risk review without pretending this is market-data infrastructure."
                  />
                  <CommercialMetric
                    label="Retention story"
                    value="Replay + deltas"
                    detail="Historical comparisons carry more value than one-off dashboards. Sell trend analysis, not just snapshots."
                  />
                </div>
              </div>
            </section>
        </div>
      ) : null}

      {activePanel === "access" ? (
        <div className="space-y-6">
            <section className="rounded-[16px] border border-border/80 bg-background/74 p-4">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                Access Flow
              </p>
              <div className="mt-4 grid gap-3 md:grid-cols-3">
                {accessSteps.map((item) => (
                  <FeatureCard
                    key={item.title}
                    icon={item.icon}
                    title={item.title}
                    detail={item.detail}
                  />
                ))}
              </div>
            </section>

            <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <div className="rounded-[16px] border border-border/80 bg-background/74 p-4">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                  Subscription Shape
                </p>
                <div className="mt-4 grid gap-3">
                  {pricingRows.map((item) => (
                    <PricingRow key={item.label} label={item.label} value={item.value} detail={item.detail} />
                  ))}
                </div>
              </div>

              <div className="rounded-[16px] border border-border/80 bg-background/74 p-4">
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
                  First Release Rules
                </p>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <CommercialMetric
                    label="API keys"
                    value="Project-scoped"
                    detail="One project, one environment, one key. Keep it simple for launch."
                  />
                  <CommercialMetric
                    label="Rate limits"
                    value="Quota headers"
                    detail="Expose request limits and reset windows clearly from day one."
                  />
                  <CommercialMetric
                    label="Billing"
                    value="Subscription first"
                    detail="Monthly plans are easier to explain than usage-based complexity at the start."
                  />
                  <CommercialMetric
                    label="Support"
                    value="Commercial inbox"
                    detail="Growth and enterprise tiers should include response expectations before deeper support tooling exists."
                  />
                </div>
              </div>
            </section>
        </div>
      ) : null}

    </div>
  );
}

function EmbeddedApiReference({
  docsUiConfig,
  openApiDocument,
  isLoading,
  error,
}: {
  docsUiConfig: DocsUiConfig | null;
  openApiDocument: Record<string, unknown> | null;
  isLoading: boolean;
  error: string | null;
}) {
  if (isLoading) {
    return (
      <div className="rounded-[16px] border border-border/75 bg-background/68 p-5">
        <p className="text-sm text-muted-foreground">Loading generated API reference.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-[16px] border border-red-500/30 bg-background/68 p-5">
        <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-red-300">
          Docs unavailable
        </p>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">
          Could not load the embedded API reference: {error}
        </p>
      </div>
    );
  }

  if (!docsUiConfig || !openApiDocument) {
    return null;
  }

  return (
    <div className="overflow-hidden rounded-[16px] border border-border/75 bg-background/60">
      <div className="border-b border-border/75 bg-background/80 px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
              Live API Reference
            </p>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">
              {docsUiConfig.introduction}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="muted">{docsUiConfig.version}</Badge>
            <Badge variant="muted">OpenAPI source</Badge>
          </div>
        </div>
      </div>
      <div className="panel-scrollbar h-[calc(100vh-9rem)] min-h-[820px] overflow-y-auto overscroll-contain [&_.scalar-app]:h-full [&_.scalar-app]:min-h-full [&_.scalar-app]:bg-transparent">
        <Suspense
          fallback={<p className="p-5 text-sm text-muted-foreground">Loading interactive reference shell.</p>}
        >
          <ScalarApiReference
            configuration={{
              _integration: "react",
              title: docsUiConfig.title,
              content: openApiDocument,
              baseServerURL: docsUiConfig.baseServerUrl ?? undefined,
              theme: "none",
              layout: "modern",
              withDefaultFonts: false,
              showSidebar: true,
              darkMode: true,
            }}
          />
        </Suspense>
      </div>
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

function FeatureCard({
  icon: Icon,
  title,
  detail,
}: {
  icon: typeof ShieldCheck;
  title: string;
  detail: string;
}) {
  return (
    <div className="rounded-[12px] border border-border/75 bg-background/68 p-3">
      <div className="flex items-center gap-2.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-[8px] border border-primary/18 bg-primary/10 text-primary">
          <Icon className="h-4 w-4" />
        </span>
        <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-foreground">
          {title}
        </p>
      </div>
      <p className="mt-2.5 text-[12px] leading-5 text-muted-foreground">{detail}</p>
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

function PricingRow({
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
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
          {label}
        </p>
        <p className="font-mono text-sm text-foreground">{value}</p>
      </div>
      <p className="mt-2 text-[12px] leading-5 text-muted-foreground">{detail}</p>
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
      <p className="mt-2 text-[10px] leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
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
