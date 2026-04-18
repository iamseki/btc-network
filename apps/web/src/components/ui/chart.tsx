"use client";

import * as React from "react";
import * as RechartsPrimitive from "recharts";

import { cn } from "@/lib/utils";

export type ChartConfig = Record<
  string,
  {
    label: string;
    color?: string;
  }
>;

const ChartContext = React.createContext<ChartConfig | null>(null);

export function useChart() {
  const context = React.useContext(ChartContext);

  if (!context) {
    throw new Error("useChart must be used within a <ChartContainer />");
  }

  return context;
}

export function ChartContainer({
  id,
  className,
  config,
  children,
}: React.ComponentProps<"div"> & {
  config: ChartConfig;
}) {
  const style = {
    ...Object.fromEntries(
      Object.entries(config).map(([key, value]) => [`--color-${key}`, value.color ?? "currentColor"]),
    ),
  } as React.CSSProperties;

  return (
    <ChartContext.Provider value={config}>
      <div
        data-slot="chart"
        data-chart={id}
        className={cn(
          "flex h-[260px] w-full items-center justify-center text-xs",
          "[&_.recharts-cartesian-axis-tick_text]:fill-[rgba(245,239,226,0.68)]",
          "[&_.recharts-polar-angle-axis-tick_text]:fill-[rgba(245,239,226,0.68)]",
          "[&_.recharts-polar-radius-axis-tick_text]:fill-[rgba(245,239,226,0.48)]",
          "[&_.recharts-layer.recharts-pie-labels_text]:fill-[rgba(245,239,226,0.88)]",
          "[&_.recharts-reference-line_line]:stroke-border",
          "[&_.recharts-tooltip-cursor]:stroke-border",
          className,
        )}
        style={style}
      >
        {children}
      </div>
    </ChartContext.Provider>
  );
}

export const ChartTooltip = RechartsPrimitive.Tooltip;

export function ChartTooltipContent({
  active,
  payload,
  label,
  labelFormatter,
  formatter,
  className,
}: {
  active?: boolean;
  payload?: Array<{
    color?: string;
    dataKey?: string | number;
    name?: string;
    value?: number | string;
    payload?: Record<string, unknown>;
  }>;
  label?: string | number;
  labelFormatter?: (label: string | number | undefined, payload: unknown) => React.ReactNode;
  formatter?: (
    value: number | string | undefined,
    name: string | undefined,
    entry: {
      color?: string;
      dataKey?: string | number;
      name?: string;
      value?: number | string;
      payload?: Record<string, unknown>;
    },
  ) => React.ReactNode | [React.ReactNode, React.ReactNode];
  className?: string;
}) {
  const config = useChart();

  if (!active || !payload?.length) {
    return null;
  }

  const computedLabel =
    typeof labelFormatter === "function" ? labelFormatter(label, payload) : label;

  return (
    <div
      className={cn(
        "min-w-[12rem] rounded-[10px] border border-border/80 bg-popover/96 px-3 py-2 text-[11px] text-popover-foreground shadow-[0_14px_28px_rgba(0,0,0,0.28)]",
        className,
      )}
    >
      {computedLabel ? (
        <p className="mb-1 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          {String(computedLabel)}
        </p>
      ) : null}
      <div className="space-y-1.5">
        {payload.map((entry) => {
          const key = entry.dataKey ? String(entry.dataKey) : entry.name ? String(entry.name) : "value";
          const item = config[key];
          const color = entry.color ?? item?.color ?? "currentColor";
          const rendered =
            typeof formatter === "function"
              ? formatter(entry.value, entry.name, entry)
              : entry.value;

          if (Array.isArray(rendered)) {
            return (
              <div key={key} className="flex items-center justify-between gap-3">
                <span className="inline-flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
                  <span>{rendered[0]}</span>
                </span>
                <span className="font-mono text-foreground">{rendered[1]}</span>
              </div>
            );
          }

          return (
            <div key={key} className="flex items-center justify-between gap-3">
              <span className="inline-flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
                <span>{item?.label ?? entry.name ?? key}</span>
              </span>
              <span className="font-mono text-foreground">{String(rendered ?? "")}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
