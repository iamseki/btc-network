import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export type DataListItem = {
  label: string;
  value: ReactNode;
};

export function DataList({
  items,
  className,
}: {
  items: DataListItem[];
  className?: string;
}) {
  return (
    <dl className={cn("grid gap-3", className)}>
      {items.map((item) => (
        <div
          key={item.label}
          className="grid gap-1 rounded-[6px] border border-border/70 bg-muted/40 px-4 py-3 sm:grid-cols-[180px_1fr] sm:items-start sm:gap-4"
        >
          <dt className="font-mono text-[11px] font-medium uppercase tracking-[0.2em] text-muted-foreground">
            {item.label}
          </dt>
          <dd className="min-w-0 break-all font-mono text-sm text-foreground">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
