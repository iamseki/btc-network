import { AlertTriangle, HelpCircle, LoaderCircle, RotateCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { BtcAppClient } from "@/lib/api/client";
import type { NodeStatusHistoryItem, NodeStatusItem, NodeStatusValue } from "@/lib/api/types";

export const STATUS_POLL_INTERVAL_MS = 30_000;
export const STATUS_STALE_AFTER_MS = 5 * 60_000;
const MS_PER_DAY = 24 * 60 * 60_000;

const HISTORY_WINDOWS = [
  { id: "7d", label: "7d", days: 7 },
  { id: "30d", label: "30d", days: 30 },
  { id: "1y", label: "1y", days: 365 },
] as const;
const MAX_HISTORY_BUCKETS = 96;
const MAX_CELL_COLOR_SEGMENTS = 48;

type StatusPageProps = {
  client: BtcAppClient;
};

type DisplayStatus = NodeStatusValue | "stale";
type HistoryWindowId = (typeof HISTORY_WINDOWS)[number]["id"];
type HistoryCellStatus = NodeStatusValue | "none";

type HistoryCell = {
  startMs: number;
  endMs: number;
  status: HistoryCellStatus;
  count: number;
  lastEntry: NodeStatusHistoryItem | null;
  entries: NodeStatusHistoryItem[];
};

export function StatusPage({ client }: StatusPageProps) {
  const [rows, setRows] = useState<NodeStatusItem[]>([]);
  const [loadedAt, setLoadedAt] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [historyWindow, setHistoryWindow] = useState<HistoryWindowId>("7d");

  async function refreshStatus() {
    setError(null);

    try {
      const nextRows = await client.listNodeStatus();
      setRows(nextRows);
      setLoadedAt(new Date().toISOString());
    } catch (nextError) {
      setRows([]);
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void refreshStatus();
    const interval = window.setInterval(() => {
      void refreshStatus();
    }, STATUS_POLL_INTERVAL_MS);

    return () => {
      window.clearInterval(interval);
    };
  }, [client]);

  const summary = useMemo(() => summarizeRows(rows), [rows]);

  return (
    <div className="space-y-4">
      <h1 className="sr-only">Status</h1>

      <section className="grid gap-2 sm:grid-cols-4">
        <StatusBlock label="Healthy" value={summary.healthy} tone="healthy" />
        <StatusBlock label="Failed" value={summary.failed} tone="failed" />
        <StatusBlock label="Stale" value={summary.stale} tone="stale" />
        <StatusBlock label="Unknown" value={summary.unknown} tone="unknown" />
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-[8px] border border-border/70 bg-card/80 px-3 py-2 text-xs text-muted-foreground">
        <span>{loadedAt ? `Last API read ${formatRelativeTime(loadedAt)}` : "Waiting for first API read"}</span>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 rounded-[6px] border border-border/80 bg-background/54 p-0.5" aria-label="History window">
            {HISTORY_WINDOWS.map((windowOption) => (
              <button
                key={windowOption.id}
                type="button"
                onClick={() => setHistoryWindow(windowOption.id)}
                className={`rounded-[4px] px-2.5 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.12em] transition-colors ${
                  historyWindow === windowOption.id
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                }`}
              >
                Last {windowOption.label}
              </button>
            ))}
          </div>
          <Badge variant="muted">Polls every 30s</Badge>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 w-8 rounded-md px-0"
            aria-label="Refresh node status"
            title="Refresh node status"
            onClick={() => void refreshStatus()}
            disabled={isLoading}
          >
            {isLoading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <RotateCw className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {error ? (
        <StatusNotice tone="failed" message={`Node status failed to load: ${error}`} />
      ) : isLoading ? (
        <StatusNotice tone="unknown" message="Loading curated node status." />
      ) : rows.length === 0 ? (
        <StatusNotice tone="unknown" message="No node status rows are available yet." />
      ) : (
        <NodeStatusTable rows={rows} historyWindow={historyWindow} />
      )}
    </div>
  );
}

function NodeStatusTable({
  rows,
  historyWindow,
}: {
  rows: NodeStatusItem[];
  historyWindow: HistoryWindowId;
}) {
  return (
    <section className="overflow-hidden rounded-[8px] border border-border/80 bg-card/86">
      <div className="panel-scrollbar overflow-x-auto">
        <Table className="min-w-[940px]">
          <TableHeader>
            <TableRow className="border-t-0">
              <TableHead className="w-[30%]">Endpoint</TableHead>
              <TableHead className="w-[18%]">Current</TableHead>
              <TableHead className="w-[16%]">Last Check</TableHead>
              <TableHead>History</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <NodeStatusRow key={row.endpoint} row={row} historyWindow={historyWindow} />
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}

function NodeStatusRow({
  row,
  historyWindow,
}: {
  row: NodeStatusItem;
  historyWindow: HistoryWindowId;
}) {
  const displayStatus = classifyDisplayStatus(row);
  const statusText =
    displayStatus === "stale" ? "No fresh status check in the last 5 minutes" : row.message;

  return (
    <TableRow className={rowToneClass(displayStatus)}>
      <TableCell className="align-top">
        <div className="min-w-0 space-y-1.5">
          <div className="text-sm font-semibold text-foreground">{row.label}</div>
          <div className="break-all font-mono text-[11px] text-muted-foreground">{row.endpoint}</div>
          <p className="max-w-xl text-xs leading-5 text-muted-foreground">{row.description}</p>
        </div>
      </TableCell>
      <TableCell className="align-top">
        <div className="space-y-2">
          <Status variant={statusVariant(displayStatus)}>{statusLabel(displayStatus)}</Status>
          <p className="max-w-[14rem] text-xs leading-5 text-muted-foreground">{statusText}</p>
        </div>
      </TableCell>
      <TableCell className="align-top">
        <div className="space-y-1">
          <div className="text-sm text-foreground">{formatRelativeTime(row.checkedAt)}</div>
          <div className="font-mono text-[11px] text-muted-foreground">{formatClockTime(row.checkedAt)}</div>
        </div>
      </TableCell>
      <TableCell className="align-top">
        <StatusHistoryTimeline label={row.label} history={row.history} historyWindow={historyWindow} />
      </TableCell>
    </TableRow>
  );
}

function StatusBlock({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: DisplayStatus;
}) {
  return (
    <div className="rounded-[8px] border border-border/80 bg-card/82 p-3">
      <div className="flex items-center justify-between gap-2">
        <Status variant={statusVariant(tone)} showIndicator={false}>
          {label}
        </Status>
        <p className="font-serif text-2xl text-foreground">{value}</p>
      </div>
    </div>
  );
}

function StatusNotice({ message, tone }: { message: string; tone: DisplayStatus }) {
  const Icon = tone === "failed" ? AlertTriangle : HelpCircle;
  return (
    <div className={`flex items-center gap-2 rounded-[8px] border px-4 py-3 text-sm ${noticeToneClass(tone)}`}>
      <Icon className="h-4 w-4 shrink-0" />
      <span>{message}</span>
    </div>
  );
}

function StatusHistoryTimeline({
  label,
  history,
  historyWindow,
}: {
  label: string;
  history: NodeStatusHistoryItem[];
  historyWindow: HistoryWindowId;
}) {
  const cells = useMemo(
    () => buildHistoryCells(history, historyWindow),
    [history, historyWindow],
  );
  const [selectedCellIndex, setSelectedCellIndex] = useState(latestPopulatedHistoryCellIndex(cells));
  const config = getHistoryWindowConfig(historyWindow);
  const checkCount = cells.reduce((count, cell) => count + cell.count, 0);

  useEffect(() => {
    setSelectedCellIndex(latestPopulatedHistoryCellIndex(cells));
  }, [cells, historyWindow]);

  if (cells.length === 0 || checkCount === 0) {
    return <p className="text-xs text-muted-foreground">No status checks recorded.</p>;
  }

  const selectedCell = cells[Math.min(selectedCellIndex, cells.length - 1)];

  return (
    <div className="space-y-2" aria-label={`${label} status history`}>
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-muted-foreground">
        <span>{checkCount} checks in last {config.label}</span>
        <span className="font-mono uppercase tracking-[0.1em]">history buckets</span>
      </div>

      <div className="rounded-[6px] border border-border/70 bg-background/44 p-1">
        <div
          className="grid w-full gap-px"
          style={{ gridTemplateColumns: `repeat(${cells.length}, minmax(0, 1fr))` }}
        >
          {cells.map((cell, index) => (
            <button
              type="button"
              key={`${cell.startMs}-${index}`}
              aria-label={describeHistoryCell(cell)}
              onClick={() => {
                setSelectedCellIndex(index);
              }}
              className={`h-5 min-w-[2px] rounded-[2px] border outline-none transition-[border-color,filter] focus-visible:ring-2 focus-visible:ring-ring ${
                index === selectedCellIndex ? "border-foreground/80 brightness-125" : "border-background/70"
              } ${historyToneClass(cell.status)}`}
              style={cell.count > 0 ? { backgroundImage: historyCellBackground(cell) } : undefined}
            />
          ))}
        </div>
        <div className="mt-1 flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
          <span>Newest</span>
          <span>Oldest</span>
        </div>
      </div>

      <div className="grid gap-2 rounded-[6px] border border-border/70 bg-background/52 px-2.5 py-2">
        <div className="grid gap-2 sm:grid-cols-[minmax(0,0.36fr)_minmax(0,1fr)] sm:items-center">
          <Status variant={historyCellStatusVariant(selectedCell.status)} pulse={false}>
            {historyCellStatusLabel(selectedCell.status)}
          </Status>
          <div className="min-w-0 font-mono text-[11px] text-muted-foreground">
            <span className="text-foreground">{formatHistoryCellTime(selectedCell)}</span>
            <span className="mx-2 text-border">|</span>
            <span>
              {selectedCell.count === 0
                ? "no checks"
                : `${selectedCell.count} check${selectedCell.count === 1 ? "" : "s"}`}
            </span>
            {selectedCell.lastEntry ? (
              <>
                <span className="mx-2 text-border">|</span>
                <span>
                  latest {statusLabel(selectedCell.lastEntry.status)} at{" "}
                  {formatFullDateTime(selectedCell.lastEntry.checkedAt)}
                </span>
              </>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

export function classifyDisplayStatus(row: NodeStatusItem, nowMs = Date.now()): DisplayStatus {
  const checkedAtMs = Date.parse(row.checkedAt);
  if (!Number.isFinite(checkedAtMs) || nowMs - checkedAtMs > STATUS_STALE_AFTER_MS) {
    return "stale";
  }

  return row.status;
}

function summarizeRows(rows: NodeStatusItem[]) {
  return rows.reduce(
    (summary, row) => {
      const status = classifyDisplayStatus(row);
      summary[status] += 1;
      return summary;
    },
    { healthy: 0, failed: 0, stale: 0, unknown: 0 } satisfies Record<DisplayStatus, number>,
  );
}

function rowToneClass(status: DisplayStatus): string {
  if (status === "healthy") {
    return "bg-[rgba(112,145,100,0.035)]";
  }
  if (status === "failed") {
    return "bg-[rgba(176,88,63,0.055)]";
  }
  if (status === "stale") {
    return "bg-primary/5";
  }
  return "bg-muted/30";
}

function noticeToneClass(status: DisplayStatus): string {
  if (status === "failed") {
    return "border-[rgba(176,88,63,0.5)] bg-[rgba(176,88,63,0.14)] text-[rgb(241,171,149)]";
  }
  if (status === "stale") {
    return "border-primary/42 bg-primary/12 text-[color:var(--color-primary-strong)]";
  }
  return "border-border/80 bg-card/80 text-muted-foreground";
}

function statusVariant(status: DisplayStatus): "online" | "offline" | "degraded" | "maintenance" {
  if (status === "healthy") {
    return "online";
  }
  if (status === "failed") {
    return "offline";
  }
  if (status === "stale" || status === "unknown") {
    return "degraded";
  }
  return "maintenance";
}

function statusLabel(status: DisplayStatus | NodeStatusValue): string {
  if (status === "healthy") {
    return "healthy";
  }
  if (status === "failed") {
    return "failed";
  }
  if (status === "stale") {
    return "stale";
  }
  return "unknown";
}

function historyCellStatusVariant(status: HistoryCellStatus): "online" | "offline" | "degraded" | "maintenance" {
  if (status === "healthy") {
    return "online";
  }
  if (status === "failed") {
    return "offline";
  }
  if (status === "unknown") {
    return "degraded";
  }
  return "maintenance";
}

function historyCellStatusLabel(status: HistoryCellStatus): string {
  if (status === "none") {
    return "no data";
  }
  return statusLabel(status);
}

function historyToneClass(status: HistoryCellStatus): string {
  if (status === "healthy") {
    return "bg-[rgb(112,145,100)]";
  }
  if (status === "failed") {
    return "bg-[rgb(176,88,63)]";
  }
  if (status === "unknown") {
    return "bg-primary";
  }
  return "bg-[rgba(245,239,226,0.12)]";
}

function historyCellBackground(cell: HistoryCell): string {
  if (cell.entries.length <= 1) {
    return "none";
  }

  const visibleEntries =
    cell.entries.length <= MAX_CELL_COLOR_SEGMENTS
      ? cell.entries
      : Array.from({ length: MAX_CELL_COLOR_SEGMENTS }, (_, index) => {
          const sourceIndex = Math.floor((index / MAX_CELL_COLOR_SEGMENTS) * cell.entries.length);
          return cell.entries[sourceIndex];
        });
  const segmentPct = 100 / visibleEntries.length;
  const segments = visibleEntries.map((entry, index) => {
    const start = index * segmentPct;
    const end = (index + 1) * segmentPct;
    const color = statusColor(entry.status);
    return `${color} ${start.toFixed(2)}% ${end.toFixed(2)}%`;
  });

  return `linear-gradient(90deg, ${segments.join(", ")})`;
}

function statusColor(status: HistoryCellStatus): string {
  if (status === "healthy") {
    return "rgb(112,145,100)";
  }
  if (status === "failed") {
    return "rgb(176,88,63)";
  }
  if (status === "unknown") {
    return "rgb(245,179,1)";
  }
  return "rgba(245,239,226,0.12)";
}

function buildHistoryCells(history: NodeStatusHistoryItem[], historyWindow: HistoryWindowId): HistoryCell[] {
  const config = getHistoryWindowConfig(historyWindow);
  const endMs = Date.now();
  const startMs = endMs - config.days * MS_PER_DAY;
  const entries = history
    .map((entry) => ({ entry, checkedAtMs: Date.parse(entry.checkedAt) }))
    .filter(
      ({ checkedAtMs }) =>
        Number.isFinite(checkedAtMs) && checkedAtMs >= startMs && checkedAtMs <= endMs,
    )
    .sort((left, right) => left.checkedAtMs - right.checkedAtMs);

  if (entries.length === 0) {
    return [];
  }

  const bucketCount = Math.min(entries.length, MAX_HISTORY_BUCKETS);
  const cells: HistoryCell[] = Array.from({ length: bucketCount }, (_, index) => ({
    startMs: entries[Math.floor((index / bucketCount) * entries.length)].checkedAtMs,
    endMs: entries[Math.floor((index / bucketCount) * entries.length)].checkedAtMs,
    status: "none",
    count: 0,
    lastEntry: null,
    entries: [],
  }));

  entries.forEach(({ entry, checkedAtMs }, entryIndex) => {
    const index = Math.min(cells.length - 1, Math.floor((entryIndex / entries.length) * bucketCount));
    const cell = cells[index];
    cell.count += 1;
    cell.status = combineHistoryStatus(cell.status, entry.status);
    cell.lastEntry = entry;
    cell.entries.push(entry);
    cell.startMs = Math.min(cell.startMs, checkedAtMs);
    cell.endMs = Math.max(cell.endMs, checkedAtMs);
  });

  return cells.reverse();
}

function combineHistoryStatus(current: HistoryCellStatus, next: NodeStatusValue): NodeStatusValue {
  if (current === "failed" || next === "failed") {
    return "failed";
  }
  if (current === "unknown" || next === "unknown") {
    return "unknown";
  }
  return "healthy";
}

function getHistoryWindowConfig(historyWindow: HistoryWindowId) {
  return HISTORY_WINDOWS.find((windowOption) => windowOption.id === historyWindow) ?? HISTORY_WINDOWS[0];
}

function describeHistoryCell(cell: HistoryCell): string {
  if (cell.count === 0) {
    return `no data at ${formatHistoryCellTime(cell)}`;
  }

  return `${historyCellStatusLabel(cell.status)} at ${formatHistoryCellTime(cell)}, ${cell.count} check${
    cell.count === 1 ? "" : "s"
  }`;
}

function latestPopulatedHistoryCellIndex(cells: HistoryCell[]): number {
  for (let index = 0; index < cells.length; index += 1) {
    if (cells[index]?.count > 0) {
      return index;
    }
  }

  return 0;
}

function formatRelativeTime(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return "unknown time";
  }

  const elapsedMs = Math.max(0, Date.now() - timestamp);
  const minutes = Math.floor(elapsedMs / 60_000);
  if (minutes < 1) {
    return "less than 1 minute ago";
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatClockTime(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return "unknown";
  }

  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(timestamp);
}

function formatHistoryCellTime(cell: HistoryCell): string {
  if (cell.count <= 1 || cell.startMs === cell.endMs) {
    return formatFullDateTime(new Date(cell.startMs).toISOString());
  }

  return `${formatFullDateTime(new Date(cell.startMs).toISOString())} - ${formatFullDateTime(
    new Date(cell.endMs).toISOString(),
  )}`;
}

function formatFullDateTime(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return "unknown";
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(timestamp);
}
