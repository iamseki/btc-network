import {
  ArrowLeft,
  BookOpenText,
  ChevronRight,
  CircleHelp,
  LoaderCircle,
  RotateCw,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { BtcAppClient } from "@/lib/api/client";
import type {
  CrawlRunDetail,
  CrawlRunListItem,
  LastRunAsnCountItem,
  LastRunNetworkTypeCountItem,
} from "@/lib/api/types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

type RiskPageProps = {
  client: BtcAppClient;
  showHeader?: boolean;
};

type RiskTopic = {
  id: string;
  title: string;
  category: string;
  status: "ready" | "planned";
  summary: string;
  highlight: string;
  metrics: { label: string; value: string; detail: string }[];
  limitations: string[];
  sections: RiskTopicSection[];
};

type RiskTopicSection = {
  id: string;
  label: string;
  title: string;
  body: string[];
  bullets?: string[];
};

export function RiskPage({ client, showHeader = true }: RiskPageProps) {
  const demoMode = isDemoModeEnabled();
  const [lastRunAsns, setLastRunAsns] = useState<LastRunAsnCountItem[]>([]);
  const [lastRunNetworkTypes, setLastRunNetworkTypes] = useState<LastRunNetworkTypeCountItem[]>([]);
  const [latestRun, setLatestRun] = useState<CrawlRunListItem | null>(null);
  const [latestDetail, setLatestDetail] = useState<CrawlRunDetail | null>(null);
  const [selectedTopicId, setSelectedTopicId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    void refreshRisk(() => cancelled);

    return () => {
      cancelled = true;
    };
  }, [client]);

  async function refreshRisk(isCancelled: () => boolean = () => false) {
    setIsLoading(true);
    setError(null);

    try {
      const [runs, nextLastRunAsns, nextLastRunNetworkTypes] = await Promise.all([
        client.listCrawlRuns(1),
        client.listLastRunAsns(10),
        client.listLastRunNetworkTypes(10),
      ]);
      const mostRecentRun = runs[0] ?? null;
      const detail = mostRecentRun ? await client.getCrawlRun(mostRecentRun.runId) : null;

      if (isCancelled()) {
        return;
      }

      setLatestRun(mostRecentRun);
      setLatestDetail(detail);
      setLastRunAsns(nextLastRunAsns);
      setLastRunNetworkTypes(nextLastRunNetworkTypes);
    } catch (nextError) {
      if (isCancelled()) {
        return;
      }

      setLatestRun(null);
      setLatestDetail(null);
      setLastRunAsns([]);
      setLastRunNetworkTypes([]);
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      if (!isCancelled()) {
        setIsLoading(false);
      }
    }
  }

  const networkOutcomes = latestDetail?.networkOutcomes ?? [];
  const leadAsn = lastRunAsns[0] ?? null;
  const visibleVerifiedNodes = lastRunAsns.reduce((sum, row) => sum + row.nodeCount, 0);
  const asnConcentrationPct =
    visibleVerifiedNodes > 0 && leadAsn ? (leadAsn.nodeCount / visibleVerifiedNodes) * 100 : null;
  const verificationFailurePct = latestRun ? Math.max(0, 100 - latestRun.successPct) : null;
  const frontierGapPct =
    latestRun && latestRun.uniqueNodes > 0
      ? (latestRun.unscheduledGap / latestRun.uniqueNodes) * 100
      : null;
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
  const riskTopics = useMemo(
    () =>
      buildRiskTopics({
        asnConcentrationPct,
        decentralizationScore,
        eclipseExposureScore,
        leadAsn,
        observationConfidenceScore,
        transportDiversityScore,
        visibleVerifiedNodes,
      }),
    [
      asnConcentrationPct,
      decentralizationScore,
      eclipseExposureScore,
      leadAsn,
      observationConfidenceScore,
      transportDiversityScore,
      visibleVerifiedNodes,
    ],
  );
  const selectedTopic = riskTopics.find((topic) => topic.id === selectedTopicId) ?? null;
  const hasRiskInputs =
    latestRun !== null ||
    lastRunAsns.length > 0 ||
    lastRunNetworkTypes.length > 0 ||
    networkOutcomes.length > 0;

  return (
    <Card>
      <CardContent className="space-y-5 p-3 sm:space-y-7 sm:p-6">
        {showHeader ? (
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border/80 pb-4 sm:items-center sm:pb-5">
            <div className="min-w-0">
              <h1 className="sr-only">Risk</h1>
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.28em] text-primary">
                  Risk Library
                </p>
                <HeaderTooltip
                  label="Risk Library context"
                  tooltip={
                    demoMode
                      ? "Demo risk library with crawler-visible evidence and limitation notes."
                      : "Crawler-visible risk library with evidence cards, scores, and limitation notes."
                  }
                />
                <span className="hidden h-3 w-px bg-border/80 sm:inline-block" />
                <span className="font-mono text-[11px] text-foreground">
                  {latestRun?.phase ?? "Awaiting run"}
                </span>
              </div>
              <p className="mt-1 text-sm text-muted-foreground">
                {riskTopics.length} clean evidence cards with expanded notes
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              <Badge variant="muted">Crawler-visible</Badge>
              <Badge variant="muted">Mocked details</Badge>
              <Badge variant="muted">No attack claims</Badge>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 w-8 rounded-md px-0"
                aria-label="Refresh risk metrics"
                title="Refresh risk metrics"
                onClick={() => void refreshRisk()}
                disabled={isLoading}
              >
                {isLoading ? (
                  <LoaderCircle className="h-4 w-4 animate-spin" />
                ) : (
                  <RotateCw className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
        ) : (
          <h1 className="sr-only">Risk</h1>
        )}

        {isLoading ? (
          <StatusPanel
            message={
              demoMode
                ? "Loading demo risk signals and topic cards."
                : "Loading risk signals and topic cards."
            }
          />
        ) : error ? (
          <StatusPanel tone="error" message={`Risk metrics failed to load: ${error}`} />
        ) : !hasRiskInputs ? (
          <StatusPanel
            message={
              demoMode
                ? "No demo risk inputs are configured for this build."
                : "No risk inputs are available yet. Run the crawler locally or point the app at a populated API."
            }
          />
        ) : (
          <div className="space-y-5 sm:space-y-6">
            {selectedTopic ? (
              <RiskTopicDetailView topic={selectedTopic} onBack={() => setSelectedTopicId(null)} />
            ) : (
              <section className="space-y-3">
                <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
                  {riskTopics.map((topic) => (
                    <RiskTopicCard
                      key={topic.id}
                      topic={topic}
                      onSelect={() => setSelectedTopicId(topic.id)}
                    />
                  ))}
                </div>
              </section>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function buildRiskTopics({
  asnConcentrationPct,
  decentralizationScore,
  eclipseExposureScore,
  leadAsn,
  observationConfidenceScore,
  transportDiversityScore,
  visibleVerifiedNodes,
}: {
  asnConcentrationPct: number | null;
  decentralizationScore: number;
  eclipseExposureScore: number;
  leadAsn: LastRunAsnCountItem | null;
  observationConfidenceScore: number;
  transportDiversityScore: number;
  visibleVerifiedNodes: number;
}): RiskTopic[] {
  return [
    {
      id: "identity-concentration",
      title: "Identity Concentration Signals",
      category: "Sybil-oriented evidence",
      status: "planned",
      summary:
        "Tracks endpoint concentration and software uniformity as crawler-visible review signals. It does not prove operator identity or shared control.",
      highlight:
        asnConcentrationPct === null
          ? "Needs verified ASN distribution"
          : `${asnConcentrationPct.toFixed(1)}% top ASN share`,
      metrics: [
        {
          label: "Top ASN share",
          value: asnConcentrationPct === null ? "Pending" : `${asnConcentrationPct.toFixed(1)}%`,
          detail: leadAsn
            ? `${leadAsn.asnOrganization ?? "Unknown ASN"} leads ${visibleVerifiedNodes.toLocaleString()} visible verified nodes.`
            : "Needs verified ASN distribution.",
        },
        {
          label: "Prefix density",
          value: "BNDD-0016",
          detail: "Planned from run-scoped prefix aggregation.",
        },
        {
          label: "Fingerprint uniformity",
          value: "BNDD-0016",
          detail: "Planned from protocol version, services, user agent, and relay tuple.",
        },
      ],
      limitations: [
        "NAT, VPN, Tor, and hosting providers can create benign concentration.",
        "Crawler data cannot prove real-world operator identity.",
      ],
      sections: [
        {
          id: "read",
          label: "Current read",
          title: "What this card is watching",
          body: [
            "This mocked detail page treats ASN share, prefix density, and fingerprint uniformity as review prompts. The crawler can expose visible clustering, but it cannot identify who operates endpoints.",
            leadAsn
              ? `${leadAsn.asnOrganization ?? "Unknown ASN"} is the current leading ASN in this sample, with ${visibleVerifiedNodes.toLocaleString()} visible verified nodes behind the calculation.`
              : "No verified ASN leader is available yet, so this card stays in planning mode until the data contract fills in.",
          ],
          bullets: [
            "Compare top ASN share against historical runs before escalating.",
            "Pair concentration with user-agent and service-bit diversity.",
            "Treat hosting-provider clusters as ambiguous until corroborated.",
          ],
        },
        {
          id: "mocked-data",
          label: "Mocked data",
          title: "Example analyst notes",
          body: [
            "Mock signal: three prefixes carry repeated protocol fingerprints over a six-hour window. This is example content for the expanded card flow, not a live finding.",
          ],
          bullets: [
            "Prefix cluster A: 14 endpoints, 92% matching service tuple.",
            "Prefix cluster B: 8 endpoints, same user agent and start height band.",
            "Review action: compare against next crawler run before labeling risk movement.",
          ],
        },
      ],
    },
    {
      id: "eclipse-exposure",
      title: "Eclipse Exposure Proxy",
      category: "Connectivity risk",
      status: "ready",
      summary:
        "Combines concentration, transport skew, failed verification, and uncovered frontier pressure into one operational proxy.",
      highlight: `${Math.round(eclipseExposureScore)} exposure proxy`,
      metrics: [
        {
          label: "Exposure proxy",
          value: `${Math.round(eclipseExposureScore)}`,
          detail: "Higher values mean more visible exposure in current crawler inputs.",
        },
        {
          label: "Transport diversity",
          value: `${Math.round(transportDiversityScore)}`,
          detail: "Higher values mean observed network types are less concentrated.",
        },
      ],
      limitations: [
        "This is a proxy, not a direct attack measurement.",
        "Crawler coverage is incomplete and time-dependent.",
      ],
      sections: [
        {
          id: "read",
          label: "Current read",
          title: "How to read the proxy",
          body: [
            "The proxy is meant to rank review urgency. It folds concentration, transport skew, verification failure, and frontier gap into one score so an operator can decide where to inspect next.",
            "High movement should start a data-quality check before any security claim. Failed visits and uncovered peers can reflect crawler reachability as much as network behavior.",
          ],
          bullets: [
            `Current mocked proxy: ${Math.round(eclipseExposureScore)}.`,
            `Transport diversity score: ${Math.round(transportDiversityScore)}.`,
            "Best next click: inspect transports and failures for the same run.",
          ],
        },
        {
          id: "mocked-data",
          label: "Mocked data",
          title: "Example expanded evidence",
          body: [
            "Mock signal: IPv4 accounts for most verified endpoints while uncovered frontier remains elevated. The card shows how a blog-style detail page can explain the score without crowding the card grid.",
          ],
          bullets: [
            "Transport mix: IPv4 dominant, IPv6 secondary, Tor sparse.",
            "Frontier pressure: unscheduled peers remain visible after run close.",
            "Review action: compare against next snapshot and ASN spread.",
          ],
        },
      ],
    },
    {
      id: "observation-confidence",
      title: "Observation Confidence",
      category: "Measurement quality",
      status: "ready",
      summary:
        "Shows how much trust to place in current public read-only analytics before interpreting risk signals.",
      highlight: `${Math.round(observationConfidenceScore)} confidence score`,
      metrics: [
        {
          label: "Confidence score",
          value: `${Math.round(observationConfidenceScore)}`,
          detail: "Built from visit success, scheduled coverage, and persistence coverage.",
        },
      ],
      limitations: [
        "Failed observations can reflect network conditions.",
        "Freshness and crawler reachability shape every downstream metric.",
      ],
      sections: [
        {
          id: "read",
          label: "Current read",
          title: "Why confidence gates the rest",
          body: [
            "Risk movement is only useful when the crawler reached enough of the visible network. This card keeps measurement quality separate from risk interpretation.",
            "The score combines visit success, scheduled coverage, and persistence coverage. It should be read first when other cards look noisy.",
          ],
          bullets: [
            `Current mocked confidence: ${Math.round(observationConfidenceScore)}.`,
            "Low confidence means avoid strong language in reports.",
            "Recovered confidence can justify comparing current risk cards against older snapshots.",
          ],
        },
        {
          id: "mocked-data",
          label: "Mocked data",
          title: "Example run notes",
          body: [
            "Mock signal: visit success improved, but persistence coverage still lags. The detail page leaves room for run notes, caveats, and reviewer links without stuffing those into each card.",
          ],
          bullets: [
            "Crawler path: latest finished run only.",
            "Known caveat: intermittent peers can depress success rate.",
            "Review action: confirm crawler health before interpreting concentration movement.",
          ],
        },
      ],
    },
    {
      id: "decentralization-review",
      title: "Decentralization Review",
      category: "Network shape",
      status: "ready",
      summary:
        "Summarizes concentration, transport spread, and frontier coverage as a clean review entry point for network-shape changes.",
      highlight: `${Math.round(decentralizationScore)} health score`,
      metrics: [
        {
          label: "Health score",
          value: `${Math.round(decentralizationScore)}`,
          detail: "Higher values mean less visible concentration in current crawler inputs.",
        },
        {
          label: "Visible verified nodes",
          value: visibleVerifiedNodes.toLocaleString(),
          detail: "Run-scoped ASN rows currently available to the page.",
        },
      ],
      limitations: [
        "This view is shaped by crawler reach and read-only analytics.",
        "It should guide review, not replace protocol-level investigation.",
      ],
      sections: [
        {
          id: "read",
          label: "Current read",
          title: "Network-shape summary",
          body: [
            "This mocked card is a cleaner replacement for the old score deck. It keeps the headline value available but moves explanation into the expanded article view.",
            "The score uses concentration, transport spread, and frontier pressure. It favors quick triage over deep causal claims.",
          ],
          bullets: [
            `Current mocked health score: ${Math.round(decentralizationScore)}.`,
            `Visible verified nodes in ASN rows: ${visibleVerifiedNodes.toLocaleString()}.`,
            "Review action: open ASN and transport pages when this card changes materially.",
          ],
        },
        {
          id: "mocked-data",
          label: "Mocked data",
          title: "Example report copy",
          body: [
            "Mock signal: network-shape health stayed below target because top-ASN share outweighed transport diversity. This is placeholder copy for future report-style cards.",
          ],
          bullets: [
            "Driver: concentration pressure.",
            "Offset: moderate transport diversity.",
            "Reviewer note: confirm next run before changing status.",
          ],
        },
      ],
    },
  ];
}

function RiskTopicCard({
  topic,
  onSelect,
}: {
  topic: RiskTopic;
  onSelect: () => void;
}) {
  const Icon = topic.status === "ready" ? ShieldAlert : BookOpenText;
  const previewMetrics = topic.metrics.slice(0, 2);

  return (
    <button
      type="button"
      className="group flex min-h-[17rem] cursor-pointer flex-col rounded-[10px] border border-border/80 bg-background/70 p-3 text-left shadow-[0_12px_22px_rgba(0,0,0,0.12)] transition-colors hover:border-primary/45 hover:bg-background/86 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring sm:p-4"
      onClick={onSelect}
      aria-label={`Open ${topic.title}`}
    >
      <span className="flex items-start justify-between gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[8px] border border-primary/20 bg-primary/10 text-primary">
          <Icon className="h-4 w-4" />
        </span>
        <Badge variant={topic.status === "ready" ? "muted" : "default"}>
          {topic.status === "ready" ? "Available" : "Mocked"}
        </Badge>
      </span>
      <span className="mt-4 min-w-0">
        <span className="block font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
          {topic.category}
        </span>
        <span className="mt-2 block text-base font-semibold text-foreground">{topic.title}</span>
        <span className="mt-2 block text-sm leading-6 text-muted-foreground">
          {topic.summary}
        </span>
      </span>
      <span className="mt-4 grid gap-2">
        {previewMetrics.map((metric) => (
          <span
            key={metric.label}
            className="flex items-center justify-between gap-3 border-t border-border/70 pt-2"
          >
            <span className="min-w-0 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
              {metric.label}
            </span>
            <span className="shrink-0 font-mono text-xs text-foreground">{metric.value}</span>
          </span>
        ))}
      </span>
      <span className="mt-auto flex items-center justify-between gap-3 pt-4">
        <span className="text-xs text-muted-foreground">{topic.highlight}</span>
        <span className="inline-flex items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-primary">
          Details
          <ChevronRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
        </span>
      </span>
    </button>
  );
}

function RiskTopicDetailView({
  topic,
  onBack,
}: {
  topic: RiskTopic;
  onBack: () => void;
}) {
  const Icon = topic.status === "ready" ? ShieldAlert : BookOpenText;

  return (
    <article className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 pb-4">
        <Button type="button" variant="ghost" size="sm" className="h-8 rounded-md px-2" onClick={onBack}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Cards
        </Button>
        <Badge variant={topic.status === "ready" ? "muted" : "default"}>
          {topic.status === "ready" ? "Available card" : "Mocked card"}
        </Badge>
      </div>

      <div className="grid gap-5 lg:grid-cols-[14rem_minmax(0,1fr)]">
        <nav
          aria-label={`${topic.title} detail menu`}
          className="h-max rounded-[10px] border border-border/80 bg-background/70 p-3 lg:sticky lg:top-4"
        >
          <div className="flex items-center gap-2">
            <span className="flex h-8 w-8 items-center justify-center rounded-[8px] border border-primary/20 bg-primary/10 text-primary">
              <Icon className="h-4 w-4" />
            </span>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
              Menu
            </p>
          </div>
          <div className="mt-3 grid gap-1">
            {topic.sections.map((section) => (
              <a
                key={section.id}
                href={`#${section.id}`}
                className="rounded-[8px] px-2 py-2 text-sm text-muted-foreground transition-colors hover:bg-primary/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {section.label}
              </a>
            ))}
            <a
              href="#metrics"
              className="rounded-[8px] px-2 py-2 text-sm text-muted-foreground transition-colors hover:bg-primary/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              Metrics
            </a>
            <a
              href="#limits"
              className="rounded-[8px] px-2 py-2 text-sm text-muted-foreground transition-colors hover:bg-primary/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              Limits
            </a>
          </div>
        </nav>

        <div className="min-w-0 space-y-6">
          <header>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
              {topic.category}
            </p>
            <h2 className="mt-2 text-2xl font-semibold text-foreground sm:text-3xl">
              {topic.title}
            </h2>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-muted-foreground">
              {topic.summary}
            </p>
          </header>

          {topic.sections.map((section) => (
            <section key={section.id} id={section.id} className="scroll-mt-6 space-y-3">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
                {section.label}
              </p>
              <h3 className="text-lg font-semibold text-foreground">{section.title}</h3>
              {section.body.map((paragraph) => (
                <p key={paragraph} className="text-sm leading-7 text-muted-foreground">
                  {paragraph}
                </p>
              ))}
              {section.bullets ? (
                <ul className="grid gap-2 text-sm leading-6 text-muted-foreground">
                  {section.bullets.map((bullet) => (
                    <li key={bullet} className="border-l border-primary/35 pl-3">
                      {bullet}
                    </li>
                  ))}
                </ul>
              ) : null}
            </section>
          ))}

          <section id="metrics" className="scroll-mt-6 space-y-3">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
              Metrics
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              {topic.metrics.map((metric) => (
                <div key={metric.label} className="rounded-[10px] border border-border/70 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <p className="min-w-0 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                      {metric.label}
                    </p>
                    <p className="shrink-0 font-mono text-xs text-foreground">{metric.value}</p>
                  </div>
                  <p className="mt-2 text-xs leading-5 text-muted-foreground">{metric.detail}</p>
                </div>
              ))}
            </div>
          </section>

          <section id="limits" className="scroll-mt-6 space-y-3">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
              Limits
            </p>
            <ul className="grid gap-2 text-sm leading-6 text-muted-foreground">
              {topic.limitations.map((limitation) => (
                <li key={limitation} className="border-l border-primary/35 pl-3">
                  {limitation}
                </li>
              ))}
            </ul>
          </section>
        </div>
      </div>
    </article>
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
