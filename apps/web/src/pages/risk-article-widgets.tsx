import type { ReactElement } from "react";

import { Badge } from "@/components/ui/badge";

type RiskArticleWidgetProps = {
  widgetType: string;
  props: Record<string, string>;
};

type SybilSignalLevel = "info" | "review" | "watch";

type SybilSignal = {
  level: SybilSignalLevel;
  kind: string;
  clusterType: string;
  clusterKey: string;
  label: string;
  nodeCount: number;
  share: number;
  threshold: number;
  note: string;
};

const SYBIL_DASHBOARD = {
  stats: [
    { label: "Verified nodes", value: "1,284", detail: "latest finished crawler run" },
    { label: "Top ASN share", value: "9.7%", detail: "watch threshold: 8%" },
    { label: "Top prefix uniformity", value: "86%", detail: "review threshold: 80%" },
  ],
  prefixClusters: [
    { prefix: "203.0.113.0/24", nodes: 18, uniformity: 86 },
    { prefix: "198.51.100.0/24", nodes: 11, uniformity: 73 },
    { prefix: "2001:db8:1200::/48", nodes: 7, uniformity: 64 },
  ],
  readingGuide: [
    "Concentration asks whether too many visible peers come from the same network area, such as one ASN or one IP prefix.",
    "Uniformity asks whether those peers also look operationally similar: same user agent, services, relay behavior, or height band.",
    "Repetition matters. A one-run cluster is a review prompt; repeated clusters across runs are stronger evidence of coordinated deployment.",
  ],
};

const SYBIL_SIGNALS: SybilSignal[] = [
  {
    level: "watch",
    kind: "Top ASN share",
    clusterType: "ASN",
    clusterKey: "AS64512",
    label: "Example Hosting ASN",
    nodeCount: 125,
    share: 9.7,
    threshold: 8,
    note: "A single network provider contributes a larger-than-usual slice of reachable identities.",
  },
  {
    level: "review",
    kind: "Fingerprint uniformity",
    clusterType: "Prefix",
    clusterKey: "203.0.113.0/24",
    label: "Dense IPv4 prefix",
    nodeCount: 18,
    share: 86,
    threshold: 80,
    note: "Most nodes in the prefix expose the same protocol version, services bitfield, user agent, and relay setting.",
  },
  {
    level: "info",
    kind: "Country concentration",
    clusterType: "Country",
    clusterKey: "US",
    label: "United States",
    nodeCount: 412,
    share: 32.1,
    threshold: 30,
    note: "Country-level concentration is broad context only; it is too coarse for direct review by itself.",
  },
];

const SYBIL_BOUNDARIES = [
  "A crawler observes reachable endpoints, not people, companies, wallets, miners, or hash power.",
  "NAT, VPNs, Tor, cloud hosting, and stale enrichment can make benign peers look concentrated.",
  "Popular node software can make honest independent peers look uniform.",
  "This view does not observe mempool behavior, transaction propagation, mining strategy, or consensus influence.",
];

const SYBIL_REFERENCES = [
  {
    label: "BNDD-0016",
    title: "Sybil-oriented crawler metrics",
    href: "https://github.com/iamseki/btc-network/blob/main/docs/design_docs/BNDD-0016/BNDD-0016.md",
    detail: "Project design boundary for these signals and the read-only API direction.",
  },
  {
    label: "PDF",
    title: "The Sybil Attack - John R. Douceur",
    href: "https://users.ece.cmu.edu/~adrian/731-sp04/readings/Douceur-sybil.pdf",
    detail: "The core distributed-systems paper behind identity inflation risk.",
  },
  {
    label: "IEEE",
    title: "Preventing Sybil Attack in Blockchain using Distributed Behavior Monitoring of Miners",
    href: "https://ieeexplore.ieee.org/document/8944507",
    detail: "Behavior-monitoring paper cited by BNDD-0016; canonical IEEE record.",
  },
  {
    label: "PDF",
    title: "Bitcoin: A Peer-to-Peer Electronic Cash System",
    href: "https://bitcoin.org/bitcoin.pdf",
    detail: "Bitcoin's peer-to-peer context and proof-of-work resource-cost model.",
  },
];

export function RiskArticleWidget({ widgetType, props }: RiskArticleWidgetProps) {
  const Widget = riskArticleWidgets[widgetType];

  if (!Widget) {
    return <UnknownRiskArticleWidget widgetType={widgetType} />;
  }

  return <Widget props={props} />;
}

const riskArticleWidgets: Record<
  string,
  (input: { props: Record<string, string> }) => ReactElement
> = {
  "sybil-dashboard": SybilDashboardWidget,
  "sybil-signals": SybilSignalsWidget,
  "sybil-boundaries": SybilBoundariesWidget,
  "sybil-references": SybilReferencesWidget,
};

function SybilDashboardWidget() {
  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-3">
        {SYBIL_DASHBOARD.stats.map((stat) => (
          <SybilStatCard
            key={stat.label}
            label={stat.label}
            value={stat.value}
            detail={stat.detail}
          />
        ))}
      </div>
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.8fr)]">
        <div className="rounded-[10px] border border-border/80 bg-background/70 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h4 className="text-base font-semibold text-foreground">Top clusters to review</h4>
            <Badge variant="muted">Latest run</Badge>
          </div>
          <div className="mt-4 grid gap-3">
            {SYBIL_DASHBOARD.prefixClusters.map((prefix) => (
              <div key={prefix.prefix} className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <p className="font-mono text-xs text-foreground">{prefix.prefix}</p>
                  <p className="text-xs text-muted-foreground">
                    {prefix.nodes} nodes / {prefix.uniformity}% uniform
                  </p>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary"
                    style={{ width: `${prefix.uniformity}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="rounded-[10px] border border-border/80 bg-background/70 p-4">
          <h4 className="text-base font-semibold text-foreground">How to read it</h4>
          <ul className="mt-3 grid gap-3 text-sm leading-6 text-muted-foreground">
            {SYBIL_DASHBOARD.readingGuide.map((bullet) => (
              <li key={bullet} className="border-l border-primary/35 pl-3">
                {bullet}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function SybilSignalsWidget() {
  return (
    <div className="grid gap-3">
      {SYBIL_SIGNALS.map((signal) => (
        <div key={`${signal.kind}-${signal.clusterKey}`} className="rounded-[10px] border border-border/80 bg-background/70 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={signal.level === "review" ? "default" : "muted"}>
                  {signal.level}
                </Badge>
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-primary">
                  {signal.kind}
                </p>
              </div>
              <h4 className="mt-2 text-base font-semibold text-foreground">
                {signal.clusterType} {signal.clusterKey}: {signal.label}
              </h4>
            </div>
            <div className="text-right font-mono text-xs text-muted-foreground">
              <p>{signal.nodeCount} nodes</p>
              <p>{signal.share}% / {signal.threshold}% threshold</p>
            </div>
          </div>
          <p className="mt-3 text-sm leading-6 text-muted-foreground">{signal.note}</p>
        </div>
      ))}
    </div>
  );
}

function SybilBoundariesWidget() {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {SYBIL_BOUNDARIES.map((boundary) => (
        <div key={boundary} className="rounded-[10px] border border-border/70 bg-muted/20 p-3 text-sm leading-6 text-muted-foreground">
          {boundary}
        </div>
      ))}
    </div>
  );
}

function SybilReferencesWidget() {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {SYBIL_REFERENCES.map((reference) => (
        <a
          key={reference.href}
          href={reference.href}
          target="_blank"
          rel="noreferrer"
          className="block rounded-[10px] border border-border/80 bg-background/70 p-4 transition-colors hover:border-primary/45 hover:bg-background/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <div className="grid gap-2">
            <Badge variant="muted">{reference.label}</Badge>
            <h4 className="text-sm font-semibold leading-6 text-foreground">{reference.title}</h4>
          </div>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{reference.detail}</p>
        </a>
      ))}
    </div>
  );
}

function SybilStatCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-[10px] border border-border/80 bg-background/70 p-4">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-2 font-mono text-2xl font-semibold text-foreground">{value}</p>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
}

function UnknownRiskArticleWidget({ widgetType }: { widgetType: string }) {
  return (
    <div className="rounded-[10px] border border-dashed border-primary/45 bg-primary/8 p-4">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-primary">
        Widget not implemented
      </p>
      <p className="mt-2 text-sm text-muted-foreground">
        The article requested the widget <span className="font-mono text-foreground">{widgetType}</span>.
      </p>
    </div>
  );
}
