import {
  ArrowLeft,
  ChevronRight,
  CircleHelp,
  LoaderCircle,
  RotateCw,
  Search,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { TextInput } from "@/components/ui/text-input";
import {
  identityConcentrationArticle,
  type RiskArticleBlock,
  type RiskArticleDocument,
  type RiskArticleSection,
} from "@/content/risk/article-registry";
import type { BtcAppClient } from "@/lib/api/client";
import type {
  CrawlRunDetail,
  CrawlRunListItem,
  LastRunAsnCountItem,
  LastRunNetworkTypeCountItem,
} from "@/lib/api/types";
import { isDemoModeEnabled } from "@/lib/runtime-config";
import { RiskArticleWidget } from "./risk-article-widgets";

type RiskPageProps = {
  client: BtcAppClient;
  showHeader?: boolean;
  topicFilter?: string;
  onTopicFilterChange?: (value: string) => void;
};

type RiskTopic = {
  id: string;
  title: string;
  category: string;
  status: "ready" | "planned";
  isInteractive: boolean;
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

export function RiskPage({
  client,
  showHeader = true,
  topicFilter: controlledTopicFilter,
  onTopicFilterChange,
}: RiskPageProps) {
  const demoMode = isDemoModeEnabled();
  const [lastRunAsns, setLastRunAsns] = useState<LastRunAsnCountItem[]>([]);
  const [lastRunNetworkTypes, setLastRunNetworkTypes] = useState<LastRunNetworkTypeCountItem[]>([]);
  const [latestRun, setLatestRun] = useState<CrawlRunListItem | null>(null);
  const [latestDetail, setLatestDetail] = useState<CrawlRunDetail | null>(null);
  const [selectedTopicId, setSelectedTopicId] = useState<string | null>(null);
  const [uncontrolledTopicFilter, setUncontrolledTopicFilter] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const hasControlledTopicFilter = controlledTopicFilter !== undefined && onTopicFilterChange !== undefined;
  const topicFilter = controlledTopicFilter ?? uncontrolledTopicFilter;
  const setTopicFilter = onTopicFilterChange ?? setUncontrolledTopicFilter;

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
  const normalizedTopicFilter = topicFilter.trim().toLowerCase();
  const filteredRiskTopics =
    normalizedTopicFilter.length === 0
      ? riskTopics
      : riskTopics.filter((topic) =>
          [
            topic.title,
            topic.category,
            topic.summary,
            topic.highlight,
            topic.status,
            topic.isInteractive ? "expandable article draft" : "coming soon",
            ...topic.metrics.flatMap((metric) => [metric.label, metric.value, metric.detail]),
          ]
            .join(" ")
            .toLowerCase()
            .includes(normalizedTopicFilter),
        );
  const hasRiskInputs =
    latestRun !== null ||
    lastRunAsns.length > 0 ||
    lastRunNetworkTypes.length > 0 ||
    networkOutcomes.length > 0;
  const topicFilterControl = (
    <div className="relative min-w-0 flex-1 sm:w-72 sm:flex-none">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
      <TextInput
        aria-label="Filter risk topics"
        className="h-9 rounded-[8px] pl-9 pr-3 text-xs"
        placeholder="Filter topics"
        value={topicFilter}
        onChange={(event) => setTopicFilter(event.target.value)}
      />
    </div>
  );

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
                {riskTopics.length} evidence topics; filter by signal, category, or status
              </p>
            </div>
            <div className="flex w-full flex-wrap items-center justify-start gap-2 sm:w-auto sm:justify-end">
              {topicFilterControl}
              <div className="flex flex-wrap items-center justify-end gap-2">
                <Badge variant="muted">Crawler-visible</Badge>
                <Badge variant="muted">Evidence topics</Badge>
                <Badge variant="muted">No verdict claims</Badge>
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
          </div>
        ) : (
          <div
            className={
              hasControlledTopicFilter
                ? "sr-only"
                : "flex flex-wrap items-center justify-between gap-3 border-b border-border/80 pb-4 sm:pb-5"
            }
          >
            <h1 className="sr-only">Risk</h1>
            <p className="min-w-0 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-primary">
              {riskTopics.length} evidence topics
            </p>
            {hasControlledTopicFilter ? null : topicFilterControl}
          </div>
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
                {filteredRiskTopics.length > 0 ? (
                  <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
                    {filteredRiskTopics.map((topic) => (
                      <RiskTopicCard
                        key={topic.id}
                        topic={topic}
                        onSelect={
                          topic.isInteractive ? () => setSelectedTopicId(topic.id) : undefined
                        }
                      />
                    ))}
                  </div>
                ) : (
                  <StatusPanel message={`No risk topics match "${topicFilter.trim()}".`} />
                )}
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
      title: identityConcentrationArticle.title,
      category: identityConcentrationArticle.category,
      status: "planned",
      isInteractive: true,
      summary: identityConcentrationArticle.summary,
      highlight: "Open article notes",
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
      status: "planned",
      isInteractive: false,
      summary:
        "Combines concentration, transport skew, failed verification, and uncovered frontier pressure into one operational proxy.",
      highlight: "Not available yet",
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
        "This is a proxy, not a direct security finding.",
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
      status: "planned",
      isInteractive: false,
      summary:
        "Shows how much trust to place in current public read-only analytics before interpreting risk signals.",
      highlight: "Not available yet",
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
      status: "planned",
      isInteractive: false,
      summary:
        "Summarizes concentration, transport spread, and frontier coverage as a clean review entry point for network-shape changes.",
      highlight: "Not available yet",
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
  onSelect?: () => void;
}) {
  const baseClassName =
    "group flex min-h-[12rem] flex-col rounded-[10px] border p-3 text-left shadow-[0_12px_22px_rgba(0,0,0,0.12)] transition-colors sm:p-4";
  const interactiveClassName =
    "cursor-pointer border-border/80 bg-background/70 hover:border-primary/45 hover:bg-background/86 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
  const unavailableClassName =
    "cursor-not-allowed border-border/55 bg-muted/20 opacity-70";
  const body = (
    <>
      <span className="flex items-start justify-between gap-3">
        <span className="min-w-0 text-base font-semibold leading-6 text-foreground">{topic.title}</span>
        <Badge variant={topic.isInteractive ? "default" : "muted"}>
          {topic.isInteractive ? "Draft article" : "Coming soon"}
        </Badge>
      </span>
      <span className="mt-3 min-w-0">
        <span
          className={
            topic.isInteractive
              ? "block font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary"
              : "block font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground"
          }
        >
          {topic.category}
        </span>
        {topic.isInteractive ? (
          <span className="mt-2 block text-sm leading-6 text-muted-foreground">
            {topic.summary}
          </span>
        ) : null}
      </span>
      <span className="mt-auto flex items-center justify-between gap-3 pt-4">
        <span className="text-xs text-muted-foreground">{topic.highlight}</span>
        {topic.isInteractive ? (
          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-primary">
            Open
            <ChevronRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
          </span>
        ) : null}
      </span>
    </>
  );

  if (!topic.isInteractive) {
    return (
      <div className={`${baseClassName} ${unavailableClassName}`} aria-label={`${topic.title} is not available yet`}>
        {body}
      </div>
    );
  }

  return (
    <button
      type="button"
      className={`${baseClassName} ${interactiveClassName}`}
      onClick={onSelect}
      aria-label={`Open ${topic.title}`}
    >
      {body}
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
  const isSybilTopic = topic.id === "identity-concentration";
  const [isSectionMenuOpen, setIsSectionMenuOpen] = useState(false);
  const [activeSectionId, setActiveSectionId] = useState(() => {
    return isSybilTopic ? identityConcentrationArticle.navItems[0].id : topic.sections[0]?.id ?? "metrics";
  });
  const [headerActionsElement, setHeaderActionsElement] = useState<HTMLElement | null>(null);
  const menuItems = useMemo(
    () =>
      isSybilTopic
        ? identityConcentrationArticle.navItems
        : [
            ...topic.sections.map((section) => ({
              id: section.id,
              label: section.label,
            })),
            { id: "metrics", label: "Metrics" },
            { id: "limits", label: "Limits" },
          ],
    [isSybilTopic, topic.sections],
  );

  useEffect(() => {
    setHeaderActionsElement(document.getElementById("risk-header-actions"));
  }, []);

  useEffect(() => {
    const firstSectionId = isSybilTopic ? identityConcentrationArticle.navItems[0].id : topic.sections[0]?.id ?? "metrics";
    setActiveSectionId(firstSectionId);
  }, [isSybilTopic, topic.id, topic.sections]);

  useEffect(() => {
    const sectionPrefix = `risk-topic-${topic.id}-`;
    let animationFrame = 0;

    function updateActiveSection() {
      window.cancelAnimationFrame(animationFrame);
      animationFrame = window.requestAnimationFrame(() => {
        const readingAnchor = 180;
        let nextActiveSectionId = "";
        let closestSectionId = nextActiveSectionId;
        let closestSectionDistance = Number.POSITIVE_INFINITY;
        let hasMeasuredSection = false;

        for (const item of menuItems) {
          const element = document.getElementById(`${sectionPrefix}${item.id}`);

          if (!element) {
            continue;
          }

          const rect = element.getBoundingClientRect();

          if (rect.height === 0 && rect.top === 0) {
            continue;
          }

          hasMeasuredSection = true;
          const sectionDistance = Math.abs(rect.top - readingAnchor);

          if (sectionDistance < closestSectionDistance) {
            closestSectionDistance = sectionDistance;
            closestSectionId = item.id;
          }

          if (rect.top <= readingAnchor && rect.bottom > readingAnchor) {
            nextActiveSectionId = item.id;
            break;
          }

          if (rect.top <= readingAnchor) {
            nextActiveSectionId = item.id;
          }
        }

        if (hasMeasuredSection) {
          const resolvedSectionId = (nextActiveSectionId || closestSectionId || menuItems[0]?.id) ?? "";
          setActiveSectionId((current) =>
            current === resolvedSectionId ? current : resolvedSectionId,
          );
        }
      });
    }

    updateActiveSection();
    window.addEventListener("scroll", updateActiveSection, { passive: true });
    window.addEventListener("resize", updateActiveSection);
    document.addEventListener("scroll", updateActiveSection, { capture: true, passive: true });

    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener("scroll", updateActiveSection);
      window.removeEventListener("resize", updateActiveSection);
      document.removeEventListener("scroll", updateActiveSection, { capture: true });
    };
  }, [menuItems, topic.id]);

  useEffect(() => {
    if (!isSectionMenuOpen) {
      return;
    }

    function closeSectionMenuOnOutsidePointer(event: PointerEvent) {
      if (event.target instanceof Element && event.target.closest("[data-risk-section-menu]")) {
        return;
      }

      setIsSectionMenuOpen(false);
    }

    document.addEventListener("pointerdown", closeSectionMenuOnOutsidePointer);

    return () => {
      document.removeEventListener("pointerdown", closeSectionMenuOnOutsidePointer);
    };
  }, [isSectionMenuOpen]);

  function sectionDomId(sectionId: string) {
    return `risk-topic-${topic.id}-${sectionId}`;
  }

  function scrollToSection(sectionId: string) {
    document.getElementById(sectionDomId(sectionId))?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
    setIsSectionMenuOpen(false);
  }

  return (
    <article className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 pb-4">
        <Button type="button" variant="ghost" size="sm" className="h-8 rounded-md px-2" onClick={onBack}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Cards
        </Button>
        <Badge variant={topic.status === "ready" ? "muted" : "default"}>
          {topic.status === "ready" ? "Available card" : "Evidence article"}
        </Badge>
      </div>

      <div className="grid gap-7 xl:grid-cols-[minmax(0,1fr)_13rem]">
        <div className="min-w-0 space-y-6 pb-[45vh]">
          <header>
            <h2 className="text-2xl font-semibold text-foreground sm:text-3xl">
              {topic.title}
            </h2>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-muted-foreground">
              {topic.summary}
            </p>
          </header>

          <CompactSectionMenu
            isOpen={isSectionMenuOpen}
            activeItemId={activeSectionId}
            items={menuItems}
            label={topic.title}
            onSelect={scrollToSection}
            onToggle={() => setIsSectionMenuOpen((current) => !current)}
            portalElement={headerActionsElement}
          />

          {isSybilTopic ? (
            <RiskArticleContent article={identityConcentrationArticle} sectionDomId={sectionDomId} />
          ) : (
            <>
              {topic.sections.map((section) => (
                <section key={section.id} id={sectionDomId(section.id)} className="scroll-mt-6 space-y-3">
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

              <section id={sectionDomId("metrics")} className="scroll-mt-6 space-y-3">
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

              <section id={sectionDomId("limits")} className="scroll-mt-6 space-y-3">
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
            </>
          )}
        </div>

        <OnThisPageMenu
          activeItemId={activeSectionId}
          items={menuItems}
          label={topic.title}
          onSelect={scrollToSection}
        />
      </div>
    </article>
  );
}

function OnThisPageMenu({
  activeItemId,
  items,
  label,
  onSelect,
}: {
  activeItemId: string;
  items: { id: string; label: string }[];
  label: string;
  onSelect: (sectionId: string) => void;
}) {
  return (
    <aside className="hidden xl:block">
      <nav
        aria-label={`${label} on this page`}
        className="fixed right-6 top-[11rem] z-[8] w-56 max-h-[calc(100vh-12.5rem)] overflow-y-auto"
      >
        <div className="pb-2">
          <p className="text-sm font-semibold text-foreground">On this page</p>
          <p className="mt-0.5 text-xs text-muted-foreground">Article sections</p>
        </div>
        <div className="mt-3 grid gap-0.5 border-l border-border/80">
          {items.map((item) => {
            const isActive = item.id === activeItemId;

            return (
              <button
                key={item.id}
                type="button"
                aria-current={isActive ? "true" : undefined}
                className={
                  isActive
                    ? "-ml-px cursor-pointer rounded-r-[8px] border-l-2 border-primary bg-primary/10 py-1.5 pl-3 pr-2 text-left text-sm font-medium text-primary transition-colors"
                    : "-ml-px cursor-pointer rounded-r-[8px] border-l-2 border-transparent py-1.5 pl-3 pr-2 text-left text-sm text-muted-foreground transition-colors hover:border-border hover:bg-muted/40 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                }
                onClick={() => onSelect(item.id)}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      </nav>
    </aside>
  );
}

function CompactSectionMenu({
  activeItemId,
  isOpen,
  items,
  label,
  onSelect,
  onToggle,
  portalElement,
}: {
  activeItemId: string;
  isOpen: boolean;
  items: { id: string; label: string }[];
  label: string;
  onSelect: (sectionId: string) => void;
  onToggle: () => void;
  portalElement: HTMLElement | null;
}) {
  const activeItemLabel = items.find((item) => item.id === activeItemId)?.label ?? "Overview";
  const menu = (
    <nav
      aria-label={`${label} compact section menu`}
      data-risk-section-menu=""
      className={portalElement ? "relative xl:hidden" : "sticky top-[4.75rem] z-[2] xl:hidden"}
    >
      <button
        type="button"
        className="inline-flex h-9 cursor-pointer items-center gap-2 rounded-[8px] border border-border/80 bg-card px-3 text-xs font-medium text-foreground transition-colors hover:border-primary/40 hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-expanded={isOpen}
        onClick={onToggle}
      >
        <span>Sections</span>
        <span className="hidden max-w-28 truncate text-muted-foreground sm:inline">
          {activeItemLabel}
        </span>
        <ChevronRight
          className={
            isOpen
              ? "h-4 w-4 rotate-90 text-primary transition-transform"
              : "h-4 w-4 text-primary transition-transform"
          }
        />
      </button>
      {isOpen ? (
        <div className="absolute right-0 top-[calc(100%+0.5rem)] z-30 grid max-h-[calc(100vh-6rem)] w-[min(calc(100vw-2rem),18rem)] gap-1 overflow-y-auto rounded-[10px] border border-border/80 bg-card/98 p-2 shadow-[0_18px_42px_rgba(0,0,0,0.34)] backdrop-blur">
          {items.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-current={item.id === activeItemId ? "true" : undefined}
              className={
                item.id === activeItemId
                  ? "cursor-pointer rounded-[8px] bg-primary/10 px-3 py-2 text-left text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  : "cursor-pointer rounded-[8px] px-3 py-2 text-left text-sm text-muted-foreground transition-colors hover:bg-primary/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              }
              onClick={() => onSelect(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
    </nav>
  );

  if (portalElement) {
    return createPortal(menu, portalElement);
  }

  return menu;
}

function RiskArticleContent({
  article,
  sectionDomId,
}: {
  article: RiskArticleDocument;
  sectionDomId: (sectionId: string) => string;
}) {
  return (
    <div className="space-y-8">
      {article.sections.map((section) => (
        <RiskArticleSectionView
          key={section.id}
          section={section}
          sectionDomId={sectionDomId}
        />
      ))}
    </div>
  );
}

function RiskArticleSectionView({
  section,
  sectionDomId,
}: {
  section: RiskArticleSection;
  sectionDomId: (sectionId: string) => string;
}) {
  return (
    <section id={sectionDomId(section.id)} className="scroll-mt-6 space-y-4">
      <h3
        className={
          section.id === "dashboard" || section.id === "references"
            ? "text-lg font-semibold text-primary"
            : "text-lg font-semibold text-foreground"
        }
      >
        {section.label}
      </h3>
      <div className="space-y-3">
        {section.blocks.map((block, index) => (
          <RiskArticleBlockView key={`${section.id}-${index}`} block={block} />
        ))}
      </div>
    </section>
  );
}

function RiskArticleBlockView({ block }: { block: RiskArticleBlock }) {
  if (block.type === "paragraph") {
    return <p className="text-sm leading-7 text-muted-foreground">{block.text}</p>;
  }

  if (block.type === "list") {
    return (
      <ul className="grid gap-2 text-sm leading-6 text-muted-foreground">
        {block.items.map((item) => (
          <li key={item} className="border-l border-primary/35 pl-3">
            {item}
          </li>
        ))}
      </ul>
    );
  }

  return <RiskArticleWidget widgetType={block.widgetType} props={block.props} />;
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
