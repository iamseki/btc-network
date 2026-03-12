import { ChevronLeft, ChevronRight, ChevronUp, Settings2 } from "lucide-react";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/utils";

export function Sidebar({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <aside
      className={cn(
        "flex h-full flex-col border-r border-border bg-card/70 backdrop-blur-sm",
        className,
      )}
      {...props}
    />
  );
}

export function SidebarTrigger({
  collapsed = false,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { collapsed?: boolean }) {
  const Icon = collapsed ? ChevronRight : ChevronLeft;

  return (
    <button
      className={cn(
        "inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-md border border-border/70 bg-background/50 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring outline-none",
        className,
      )}
      {...props}
    >
      <Icon className="h-4 w-4" />
      <span className="sr-only">{collapsed ? "Expand sidebar" : "Collapse sidebar"}</span>
    </button>
  );
}

export function SidebarHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("border-b border-border px-3 py-3", className)}
      {...props}
    />
  );
}

export function SidebarContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("flex-1 px-2 py-3", className)} {...props} />;
}

export function SidebarGroup({
  className,
  label,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement> & { label?: string; children: ReactNode }) {
  return (
    <section className={cn("space-y-2", className)} {...props}>
      {label ? (
        <p className="px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          {label}
        </p>
      ) : null}
      {children}
    </section>
  );
}

export function SidebarFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("border-t border-border px-3 py-3", className)}
      {...props}
    />
  );
}

export function SidebarProfile({
  collapsed = false,
  name,
  role,
  ...props
}: HTMLAttributes<HTMLDivElement> & {
  collapsed?: boolean;
  name: string;
  role: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center rounded-lg border border-border/80 bg-background/40",
        collapsed ? "justify-center px-0 py-3" : "justify-between px-3 py-3",
      )}
      {...props}
    >
      <div className={cn("flex items-center", collapsed ? "justify-center" : "gap-3")}>
        <div className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-muted/60 font-mono text-xs font-semibold uppercase tracking-[0.08em] text-foreground">
          OP
        </div>
        {collapsed ? null : (
          <div className="min-w-0">
            <p className="truncate font-mono text-xs font-semibold uppercase tracking-[0.08em] text-foreground">
              {name}
            </p>
            <p className="truncate text-xs text-muted-foreground">{role}</p>
          </div>
        )}
      </div>
      {collapsed ? null : (
        <div className="flex items-center gap-1 text-muted-foreground">
          <button
            type="button"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-transparent hover:bg-muted hover:text-foreground"
            title="Settings"
          >
            <Settings2 className="h-4 w-4" />
          </button>
          <button
            type="button"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-transparent hover:bg-muted hover:text-foreground"
            title="Open profile"
          >
            <ChevronUp className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
}

type SidebarNavButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  active?: boolean;
  collapsed?: boolean;
  icon?: ReactNode;
  title: string;
  description?: string;
  tooltip?: string;
};

export function SidebarNavButton({
  active = false,
  collapsed = false,
  className,
  icon,
  title,
  tooltip,
  ...props
}: SidebarNavButtonProps) {
  return (
    <button
      className={cn(
        "flex w-full cursor-pointer rounded-md border px-3 py-2.5 text-left transition-colors outline-none focus-visible:ring-2 focus-visible:ring-ring",
        collapsed ? "items-center justify-center" : "items-center gap-3",
        active
          ? "border-border bg-muted text-foreground"
          : "border-transparent bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground",
        className,
      )}
      title={collapsed ? tooltip ?? title : tooltip}
      {...props}
    >
      <span
        className={cn(
          "rounded-md border p-2",
          active
            ? "border-border bg-background text-foreground"
            : "border-border/70 bg-background/55 text-muted-foreground",
        )}
      >
        {icon}
      </span>
      {collapsed ? null : (
        <span className="min-w-0">
          <span className="block font-mono text-sm font-medium tracking-[0.02em] text-inherit">
            {title}
          </span>
        </span>
      )}
    </button>
  );
}
