import { ChevronDown, ChevronUp, Terminal, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { UiLogEvent } from "@/lib/api/types";

type SessionLogPanelProps = {
  events: UiLogEvent[];
  isOpen: boolean;
  onToggle: () => void;
  onClear: () => void;
};

const levelTone = {
  info: "default",
  warn: "muted",
  error: "muted",
} as const;

export function SessionLogPanel({
  events,
  isOpen,
  onToggle,
  onClear,
}: SessionLogPanelProps) {
  const latestEvent = events[0] ?? null;

  return (
    <section className="border-t border-border bg-card/92 shadow-[0_-10px_30px_rgba(0,0,0,0.25)] md:sticky md:bottom-0 md:z-10">
      <div className="px-3 py-3 md:px-4 lg:px-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            className="flex min-w-0 w-full cursor-pointer items-center gap-3 rounded-[6px] border border-border/80 bg-background/70 px-3 py-2 text-left transition-colors hover:border-primary/40 hover:bg-muted/40"
            aria-expanded={isOpen}
            aria-controls="session-log-panel"
            onClick={onToggle}
          >
            <div className="rounded-md border border-primary/30 bg-primary/10 p-2 text-primary">
              <Terminal className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                Session Log
              </p>
              <p className="truncate text-sm text-foreground">
                {latestEvent ? latestEvent.message : "No events captured for this session yet."}
              </p>
            </div>
            <div className="hidden items-center gap-2 sm:flex">
              <Badge variant="muted">{events.length} events</Badge>
              {latestEvent ? (
                <Badge
                  variant={levelTone[latestEvent.level]}
                  className={cn(
                    latestEvent.level === "error" && "border-red-500/40 text-red-300",
                    latestEvent.level === "warn" && "border-amber-500/40 text-amber-300",
                  )}
                >
                  {latestEvent.level}
                </Badge>
              ) : null}
            </div>
            {latestEvent ? (
              <Badge
                variant={levelTone[latestEvent.level]}
                className={cn(
                  "sm:hidden",
                  latestEvent.level === "error" && "border-red-500/40 text-red-300",
                  latestEvent.level === "warn" && "border-amber-500/40 text-amber-300",
                )}
              >
                {latestEvent.level}
              </Badge>
            ) : null}
            {isOpen ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronUp className="h-4 w-4 text-muted-foreground" />
            )}
          </button>

          <div className="ml-auto flex items-center justify-end gap-2 self-end sm:self-auto">
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={onClear}
              disabled={events.length === 0}
            >
              <Trash2 className="h-4 w-4" />
              Clear
            </Button>
            <Button type="button" size="sm" variant="secondary" onClick={onToggle}>
              {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
              {isOpen ? "Collapse" : "Expand"}
            </Button>
          </div>
        </div>

        {isOpen ? (
          <div
            id="session-log-panel"
            className="panel-scrollbar mt-3 max-h-[50vh] overflow-y-auto rounded-[8px] border border-border/80 bg-background/85 p-3 md:max-h-[22rem]"
          >
            <ul className="grid gap-3">
              {events.map((event) => (
                <li
                  key={`${event.at}-${event.message}`}
                  className="rounded-[6px] border border-border/70 bg-muted/30 px-4 py-3 text-sm"
                >
                  <div className="mb-1 flex flex-wrap items-center gap-2">
                    <Badge
                      variant={levelTone[event.level]}
                      className={cn(
                        event.level === "error" && "border-red-500/40 text-red-300",
                        event.level === "warn" && "border-amber-500/40 text-amber-300",
                      )}
                    >
                      {event.level}
                    </Badge>
                    <span className="font-mono text-[11px] text-muted-foreground">{event.at}</span>
                  </div>
                  <p className="text-foreground">{event.message}</p>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </section>
  );
}
