import { CircleHelp } from "lucide-react";
import { memo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import type {
  LastRunAsnCountItem,
  LastRunCountryCountItem,
  LastRunNetworkTypeCountItem,
  LastRunStartHeightCountItem,
} from "@/lib/api/types";

type LastRunDashboardProps = {
  asns: LastRunAsnCountItem[];
  countries: LastRunCountryCountItem[];
  runId: string | null;
};

type LastRunSidebarChartsProps = {
  networkTypes: LastRunNetworkTypeCountItem[];
  startHeights: LastRunStartHeightCountItem[];
};

const PIE_COLORS = ["#f5b301", "#d7921d", "#a56b20", "#70514e", "#445b62"];
const BAR_COLOR = "#f5b301";
const BAR_MUTED_COLOR = "rgba(245, 239, 226, 0.18)";

export const LastRunSidebarCharts = memo(function LastRunSidebarCharts({
  networkTypes,
  startHeights,
}: LastRunSidebarChartsProps) {
  const consensusHeights = startHeights.slice(0, 5);

  return (
    <div className="space-y-6">
      <AnalyticsCard
        title="Network Type Distribution"
        subtitle="Latest finished run transport mix"
        tooltip="Shows which transport families verified nodes used in the last finished crawl. Larger slices mean a bigger share of reachable peers on that transport."
        badge={`${networkTypes.length} buckets`}
      >
        {networkTypes.length === 0 ? (
          <DashboardEmpty message="No verified network-type buckets were returned for the latest finished run." />
        ) : (
          <NetworkTypePieChart rows={networkTypes} />
        )}
      </AnalyticsCard>

      <AnalyticsCard
        title="Height Consensus"
        subtitle="Top 5 advertised start heights"
        tooltip="Shows how tightly verified peers cluster around one announced chain height. A dominant ring suggests strong height agreement; a spread suggests lag or mixed views."
        badge={`${consensusHeights.length} heights`}
      >
        {consensusHeights.length === 0 ? (
          <DashboardEmpty message="No start-height buckets were returned for the latest finished run." />
        ) : (
          <StartHeightRadarChart rows={consensusHeights} />
        )}
      </AnalyticsCard>
    </div>
  );
});

export const LastRunDashboard = memo(function LastRunDashboard({
  asns,
  countries,
  runId,
}: LastRunDashboardProps) {
  const topAsns = asns.slice(0, 10);
  const topCountries = countries.slice(0, 10);

  return (
    <section className="space-y-6">
      <div className="grid gap-6 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
        <AnalyticsCard
          title="Top ASN Distribution"
          subtitle="Verified nodes by network operator"
          tooltip="Highlights which networks host the most verified peers in the latest finished run. Higher bars mean more concentration inside one operator footprint."
          badge={runId ?? "Latest finished run"}
        >
          {topAsns.length === 0 ? (
            <DashboardEmpty message="No ASN buckets were returned for the latest finished run." />
          ) : (
            <AsnHorizontalBarChart rows={topAsns} />
          )}
        </AnalyticsCard>

        <AnalyticsCard
          title="Top Country Distribution"
          subtitle="Verified nodes by country code"
          tooltip="Shows where the latest finished run found verified nodes. Hover or tap a bar to compare top countries and read exact counts quickly."
          badge={`${topCountries.length} countries`}
        >
          {topCountries.length === 0 ? (
            <DashboardEmpty message="No country buckets were returned for the latest finished run." />
          ) : (
            <CountryInteractiveBarChart rows={topCountries} />
          )}
        </AnalyticsCard>
      </div>
    </section>
  );
});

function NetworkTypePieChart({ rows }: { rows: LastRunNetworkTypeCountItem[] }) {
  const chartRows = rows.map((row, index) => ({
    ...row,
    fill: PIE_COLORS[index % PIE_COLORS.length],
  }));

  return (
    <ChartContainer
      config={Object.fromEntries(
        chartRows.map((row) => [
          row.networkType,
          {
            label: row.networkType,
            color: row.fill,
          },
        ]),
      )}
      className="h-[290px]"
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <ChartTooltip
            content={
              <ChartTooltipContent
                formatter={(value, _name, entry) => [
                  String(entry.payload?.networkType ?? ""),
                  formatCount(value),
                ]}
              />
            }
          />
          <Pie
            data={chartRows}
            dataKey="nodeCount"
            nameKey="networkType"
            innerRadius={42}
            outerRadius={96}
            paddingAngle={3}
            stroke="rgba(8,8,8,0.72)"
            strokeWidth={2}
            isAnimationActive={false}
          >
            {chartRows.map((row) => (
              <Cell key={row.networkType} fill={row.fill} />
            ))}
            <LabelList
              dataKey="networkType"
              position="outside"
              className="font-mono text-[10px] uppercase"
            />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

function AsnHorizontalBarChart({ rows }: { rows: LastRunAsnCountItem[] }) {
  const chartRows = [...rows]
    .reverse()
    .map((row) => ({
      ...row,
      label: row.asnOrganization ?? `AS${row.asn}`,
    }));

  return (
    <ChartContainer
      config={{
        nodeCount: {
          label: "Nodes",
          color: BAR_COLOR,
        },
      }}
      className="h-[320px]"
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartRows} layout="vertical" margin={{ left: 12, right: 18 }}>
          <CartesianGrid horizontal={false} stroke="rgba(245,239,226,0.08)" />
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="label"
            width={132}
            tickLine={false}
            axisLine={false}
            tickFormatter={(value) => truncateLabel(String(value), 20)}
          />
          <ChartTooltip
            cursor={false}
            content={
              <ChartTooltipContent
                formatter={(value, _name, entry) => [
                  String(entry.payload?.label ?? ""),
                  formatCount(value),
                ]}
              />
            }
          />
          <Bar dataKey="nodeCount" radius={5} fill={BAR_COLOR} isAnimationActive={false}>
            <LabelList
              dataKey="nodeCount"
              position="right"
              offset={10}
              className="fill-foreground font-mono text-[11px]"
              formatter={(value: unknown) => formatCount(value)}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

function CountryInteractiveBarChart({ rows }: { rows: LastRunCountryCountItem[] }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const activeCountry = rows[activeIndex] ?? null;

  return (
    <div className="space-y-4">
      <div className="rounded-[10px] border border-border/70 bg-background/55 px-3 py-3">
        <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Focus Country
        </p>
        <div className="mt-2 flex items-end justify-between gap-3">
          <div>
            <p className="font-serif text-[1.8rem] text-foreground">
              {activeCountry?.country ?? "n/a"}
            </p>
            <p className="text-sm text-muted-foreground">
              {activeCountry ? `${formatCount(activeCountry.nodeCount)} verified nodes` : "No active country"}
            </p>
          </div>
          <Badge variant="muted">{activeIndex + 1} / {rows.length}</Badge>
        </div>
      </div>

      <ChartContainer
        config={{
          nodeCount: {
            label: "Nodes",
            color: BAR_COLOR,
          },
        }}
        className="h-[280px]"
      >
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 18, left: 12, right: 18 }} onMouseMove={(state) => {
            if (typeof state?.activeTooltipIndex === "number") {
              setActiveIndex(state.activeTooltipIndex);
            }
          }}>
            <CartesianGrid vertical={false} stroke="rgba(245,239,226,0.08)" />
            <XAxis dataKey="country" tickLine={false} axisLine={false} />
            <YAxis hide />
            <ChartTooltip
              cursor={{ fill: "rgba(245,179,1,0.08)" }}
              content={
                <ChartTooltipContent
                  formatter={(value, _name, entry) => [
                    String(entry.payload?.country ?? ""),
                    formatCount(value),
                  ]}
                />
              }
            />
            <Bar dataKey="nodeCount" radius={[6, 6, 0, 0]} isAnimationActive={false}>
              <LabelList
                dataKey="nodeCount"
                position="top"
                className="fill-foreground font-mono text-[11px]"
                formatter={(value: unknown) => formatCount(value)}
              />
              {rows.map((row, index) => (
                <Cell
                  key={row.country}
                  fill={index === activeIndex ? BAR_COLOR : BAR_MUTED_COLOR}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </ChartContainer>
    </div>
  );
}

function StartHeightRadarChart({ rows }: { rows: LastRunStartHeightCountItem[] }) {
  const chartRows = rows.map((row) => ({
    heightLabel: formatHeightLabel(row.startHeight),
    nodeCount: row.nodeCount,
  }));

  return (
    <ChartContainer
      config={{
        nodeCount: {
          label: "Nodes",
          color: BAR_COLOR,
        },
      }}
      className="h-[300px]"
    >
      <ResponsiveContainer width="100%" height="100%">
        <RadarChart data={chartRows} outerRadius="72%">
          <ChartTooltip
            content={
              <ChartTooltipContent
                formatter={(value, _name, entry) => [
                  String(entry.payload?.heightLabel ?? ""),
                  `${formatCount(value)} nodes`,
                ]}
              />
            }
          />
          <PolarGrid gridType="circle" stroke="rgba(245,239,226,0.12)" />
          <PolarAngleAxis dataKey="heightLabel" tickLine={false} />
          <PolarRadiusAxis axisLine={false} tick={false} tickLine={false} />
          <Radar
            dataKey="nodeCount"
            stroke={BAR_COLOR}
            fill={BAR_COLOR}
            fillOpacity={0.24}
            strokeWidth={2}
            isAnimationActive={false}
            dot={{
              r: 4,
              fill: "#ffd04f",
              stroke: "#080808",
              strokeWidth: 1.5,
            }}
          />
        </RadarChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

function AnalyticsCard({
  title,
  subtitle,
  tooltip,
  badge,
  children,
}: {
  title: string;
  subtitle: string;
  tooltip: string;
  badge: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-[14px] border border-border/80 bg-background/72 p-4 shadow-[0_16px_28px_rgba(0,0,0,0.16)]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">
              {title}
            </p>
            <InfoTooltip label={title} tooltip={tooltip} />
          </div>
          <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
        </div>
        <Badge variant="muted">{badge}</Badge>
      </div>
      <div className="mt-4">{children}</div>
    </div>
  );
}

function InfoTooltip({ label, tooltip }: { label: string; tooltip: string }) {
  return (
    <span className="group/tooltip relative mt-0.5 inline-flex">
      <button
        type="button"
        aria-label={`${label} explanation`}
        className="inline-flex h-4 w-4 items-center justify-center rounded-full text-muted-foreground/80 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <CircleHelp className="h-3.5 w-3.5" />
      </button>
      <span
        role="tooltip"
        className="pointer-events-none absolute right-0 top-[calc(100%+0.45rem)] z-10 w-56 rounded-[8px] border border-border/80 bg-popover/96 px-2.5 py-2 text-[11px] leading-4 text-popover-foreground opacity-0 shadow-[0_14px_28px_rgba(0,0,0,0.3)] transition-all duration-150 group-hover/tooltip:translate-y-0.5 group-hover/tooltip:opacity-100 group-focus-within/tooltip:translate-y-0.5 group-focus-within/tooltip:opacity-100"
      >
        {tooltip}
      </span>
    </span>
  );
}

function DashboardEmpty({ message }: { message: string }) {
  return (
    <div className="rounded-[10px] border border-border/70 bg-background/55 px-4 py-6 text-sm text-muted-foreground">
      {message}
    </div>
  );
}

function formatCount(value: unknown): string {
  if (typeof value !== "number") {
    return String(value ?? "");
  }

  return value.toLocaleString();
}

function truncateLabel(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength - 1)}…`;
}

function formatHeightLabel(value: number): string {
  return value.toLocaleString();
}
