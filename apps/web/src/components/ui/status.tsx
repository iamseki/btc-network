import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const statusVariants = cva(
  "inline-flex items-center gap-2 rounded-[6px] border px-2.5 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.14em]",
  {
    variants: {
      variant: {
        online:
          "border-[rgba(112,145,100,0.38)] bg-[rgba(112,145,100,0.13)] text-[rgb(177,214,164)]",
        offline:
          "border-[rgba(176,88,63,0.5)] bg-[rgba(176,88,63,0.14)] text-[rgb(241,171,149)]",
        degraded:
          "border-primary/42 bg-primary/12 text-[color:var(--color-primary-strong)]",
        maintenance: "border-border bg-muted text-muted-foreground",
      },
    },
    defaultVariants: {
      variant: "maintenance",
    },
  },
);

const dotVariants = cva("relative inline-flex h-2.5 w-2.5 rounded-full", {
  variants: {
    variant: {
      online: "bg-[rgb(112,145,100)]",
      offline: "bg-[rgb(176,88,63)]",
      degraded: "bg-primary",
      maintenance: "bg-muted-foreground",
    },
  },
  defaultVariants: {
    variant: "maintenance",
  },
});

export interface StatusProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof statusVariants> {
  pulse?: boolean;
  showIndicator?: boolean;
}

export function Status({
  className,
  children,
  pulse = true,
  showIndicator = true,
  variant,
  ...props
}: StatusProps) {
  return (
    <span className={cn(statusVariants({ variant, className }))} {...props}>
      {showIndicator ? (
        <span className={cn(dotVariants({ variant }))} aria-hidden="true">
          {pulse ? <span className="absolute inset-0 rounded-full bg-current opacity-35 animate-ping" /> : null}
        </span>
      ) : null}
      {children}
    </span>
  );
}
