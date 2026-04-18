import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export function SectionHeading({
  eyebrow,
  title,
  titleAccessory,
  description,
  actions,
  className,
}: {
  eyebrow?: string;
  title: string;
  titleAccessory?: ReactNode;
  description?: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col gap-4 border-b border-border/80 pb-5 sm:flex-row sm:items-end sm:justify-between",
        className,
      )}
    >
      <div className="space-y-2">
        {eyebrow ? (
          <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.28em] text-primary">
            {eyebrow}
          </p>
        ) : null}
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h1 className="font-serif text-3xl uppercase tracking-[0.12em] text-foreground">
              {title}
            </h1>
            {titleAccessory}
          </div>
          {description ? (
            <p className="max-w-3xl text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap gap-3">{actions}</div> : null}
    </div>
  );
}
