import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-[8px] border border-primary/20 bg-card/92 shadow-[0_0_0_1px_rgba(245,179,1,0.05),0_16px_42px_rgba(0,0,0,0.45)] before:pointer-events-none before:absolute before:inset-0 before:bg-[linear-gradient(180deg,rgba(245,179,1,0.04),transparent_22%,transparent_78%,rgba(245,179,1,0.03))] before:opacity-70",
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("space-y-2 p-6", className)} {...props} />;
}

export function CardTitle({
  className,
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h2
      className={cn("font-serif text-2xl uppercase tracking-[0.12em] text-foreground", className)}
      {...props}
    />
  );
}

export function CardDescription({
  className,
  ...props
}: HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p
      className={cn("max-w-3xl text-sm text-muted-foreground", className)}
      {...props}
    />
  );
}

export function CardContent({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-6 pb-6", className)} {...props} />;
}
