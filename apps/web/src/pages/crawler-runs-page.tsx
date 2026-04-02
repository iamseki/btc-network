import { LoaderCircle, RotateCw } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  CrawlerLiveSignal,
  useCrawlerSignalPlayback,
} from "@/components/crawler-live-signal";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { BtcAppClient } from "@/lib/api/client";
import type { CrawlRunDetail, CrawlRunListItem } from "@/lib/api/types";
import { isDemoModeEnabled } from "@/lib/runtime-config";

export type CrawlerRunsPanel = "overview" | "checkpoints" | "failures" | "network";

type CrawlerRunsPageProps = {
  client: BtcAppClient;
  activePanel?: CrawlerRunsPanel;
  onPanelChange?: (panel: CrawlerRunsPanel) => void;
  autoExpandSignal?: boolean;
  onAutoExpandSignalApplied?: () => void;
  showPanelNav?: boolean;
};

export function CrawlerRunsPage({
  client,
  activePanel: controlledActivePanel,
  onPanelChange,
  autoExpandSignal = false,
  onAutoExpandSignalApplied,
  showPanelNav = true,
}: CrawlerRunsPageProps) {
  const demoMode = isDemoModeEnabled();
  const [runs, setRuns] = useState<CrawlRunListItem[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<CrawlRunDetail | null>(null);
  const [internalActivePanel, setInternalActivePanel] = useState<CrawlerRunsPanel>("overview");
  const [isLoadingRuns, setIsLoadingRuns] = useState(true);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [isSignalExpanded, setIsSignalExpanded] = useState(false);
  const [runsError, setRunsError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const activePanel = controlledActivePanel ?? internalActivePanel;
  const signalPlayback = useCrawlerSignalPlayback(selectedDetail);

  useEffect(() => {
    void refreshRuns();
  }, []);

  useEffect(() => {
    if (!autoExpandSignal || !selectedDetail) {
      return;
    }

    setIsSignalExpanded(true);
    onAutoExpandSignalApplied?.();
  }, [autoExpandSignal, onAutoExpandSignalApplied, selectedDetail]);

  function selectPanel(panel: CrawlerRunsPanel) {
    onPanelChange?.(panel);
    if (controlledActivePanel === undefined) {
      setInternalActivePanel(panel);
    }
  }

  async function refreshRuns(preferredRunId?: string) {
    setIsLoadingRuns(true);
    setRunsError(null);

    try {
      const nextRuns = await client.listCrawlRuns(10);
      setRuns(nextRuns);

      const nextSelectedRunId =
        preferredRunId && nextRuns.some((run) => run.runId === preferredRunId)
          ? preferredRunId
          : nextRuns[0]?.runId ?? null;

      setSelectedRunId(nextSelectedRunId);
      setSelectedDetail(null);
      setDetailError(null);
      setIsSignalExpanded(false);
      selectPanel("overview");

      if (nextSelectedRunId) {
        await loadRunDetail(nextSelectedRunId);
      }
    } catch (error) {
      setRuns([]);
      setSelectedRunId(null);
      setSelectedDetail(null);
      setRunsError(error instanceof Error ? error.message : String(error));
    } finally {
      setIsLoadingRuns(false);
    }
  }

  async function loadRunDetail(runId: string) {
    setIsLoadingDetail(true);
    setDetailError(null);
    setSelectedRunId(runId);
    setIsSignalExpanded(false);
    selectPanel("overview");

    try {
      const detail = await client.getCrawlRun(runId);
      setSelectedDetail(detail);
    } catch (error) {
      setSelectedDetail(null);
      setDetailError(error instanceof Error ? error.message : String(error));
    } finally {
      setIsLoadingDetail(false);
    }
  }

  const selectedRunSummary =
    selectedDetail?.run ?? runs.find((run) => run.runId === selectedRunId) ?? runs[0] ?? null;
  const panelDescription =
    activePanel === "overview"
      ? demoMode
        ? "Inspect the deterministic public snapshot set used in the hosted browser build."
        : "Inspect the latest public snapshot, then open the exact slice you want to review."
      : activePanel === "checkpoints"
        ? "Review recent checkpoint progression for the selected run."
        : activePanel === "failures"
          ? "Inspect the dominant failure mix for the selected run."
          : "Compare network-specific outcomes for the selected run.";
  const headerStats = [
    {
      label: "Selected Run",
      value: selectedRunSummary?.phase ?? "No run selected",
      detail: selectedRunSummary?.runId ?? "No run loaded",
    },
    {
      label: "Visit Success",
      value: selectedRunSummary ? `${selectedRunSummary.successPct.toFixed(2)}%` : "n/a",
      detail: selectedRunSummary
        ? `${selectedRunSummary.successfulHandshakes.toLocaleString()}/${selectedRunSummary.scheduledTasks.toLocaleString()} attempted`
        : "No run loaded",
    },
    {
      label: "Tracked",
      value: selectedRunSummary ? selectedRunSummary.uniqueNodes.toLocaleString() : "n/a",
      detail: selectedRunSummary
        ? `${selectedRunSummary.scheduledPct.toFixed(2)}% scheduled`
        : "No run loaded",
    },
    {
      label: "Backlog",
      value: selectedRunSummary ? selectedRunSummary.unscheduledGap.toLocaleString() : "n/a",
      detail: selectedRunSummary
        ? `${selectedRunSummary.persistedObservationRows.toLocaleString()} persisted rows`
        : "No run loaded",
    },
  ];

  return (
    <Card>
      <CardContent className="space-y-8 p-4 sm:p-6">
        <SectionHeading
          eyebrow="Network Analytics"
          title="Crawler Runs"
          description={panelDescription}
          actions={
            <div className="flex w-full flex-wrap items-center justify-end gap-2 sm:w-auto">
              {headerStats.map((stat) => (
                <HeaderStat
                  key={stat.label}
                  label={stat.label}
                  value={stat.value}
                  detail={stat.detail}
                />
              ))}
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 w-8 self-start rounded-md px-0 sm:self-auto"
                aria-label="Refresh crawler runs"
                title="Refresh crawler runs"
                onClick={() => void refreshRuns(selectedRunId ?? undefined)}
                disabled={isLoadingRuns || isLoadingDetail}
              >
                {isLoadingRuns || isLoadingDetail ? (
                  <LoaderCircle className="h-4 w-4 animate-spin" />
                ) : (
                  <RotateCw className="h-4 w-4" />
                )}
              </Button>
            </div>
          }
        />

        {selectedDetail ? (
          <div className="rounded-[10px] border border-border/80 bg-[linear-gradient(180deg,rgba(245,179,1,0.08),rgba(255,255,255,0.02))] p-4 sm:p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="space-y-2">
                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                  Latest Snapshot
                </p>
                <p className="max-w-2xl text-sm text-muted-foreground">
                  Replay the latest crawler snapshot here, then drop straight into checkpoints,
                  failures, and network outcome tables below.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant={isSignalExpanded ? "default" : "secondary"}
                  onClick={() => setIsSignalExpanded((current) => !current)}
                >
                  {isSignalExpanded ? "Hide Latest Snapshot" : "Open Latest Snapshot"}
                </Button>
              </div>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <MetricCard
                label="Snapshot Status"
                value={signalPlayback?.isLive ? "Live" : "Archived"}
                detail={
                  signalPlayback?.isLive
                    ? "The browser is replaying the current public snapshot cycle."
                    : "The last public snapshot is ready to inspect."
                }
              />
              <MetricCard
                label="Duration"
                value={formatRunDuration(selectedDetail.run.startedAt, selectedDetail.run.lastCheckpointedAt)}
                detail={`Started ${formatTimestamp(selectedDetail.run.startedAt)}`}
              />
              <MetricCard
                label="Tracked Nodes"
                value={selectedDetail.run.uniqueNodes.toLocaleString()}
                detail={`${selectedDetail.run.successfulHandshakes.toLocaleString()} verified observations in the last run`}
              />
            </div>

            {isSignalExpanded ? (
              <div className="mt-5">
                <CrawlerLiveSignal detail={selectedDetail} playback={signalPlayback} />
              </div>
            ) : null}
          </div>
        ) : null}

        <div className="grid gap-6 xl:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
          <section className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Latest Runs
              </p>
              <Badge variant="muted">{runs.length} loaded</Badge>
            </div>

            {isLoadingRuns ? (
              <StatusPanel
                message={
                  demoMode
                    ? "Loading recent crawler runs from the embedded demo dataset."
                    : "Loading recent crawler runs from the analytics API."
                }
              />
            ) : runsError ? (
              <StatusPanel tone="error" message={`Crawler runs failed to load: ${runsError}`} />
            ) : runs.length === 0 ? (
              <StatusPanel
                message={
                  demoMode ? "No demo crawler runs are configured." : "No crawler runs persisted yet."
                }
              />
            ) : (
              <div className="space-y-2">
                {runs.map((run) => {
                  const isSelected = run.runId === selectedRunId;

                  return (
                    <button
                      key={run.runId}
                      type="button"
                      aria-label={`Select run ${run.runId}`}
                      className={
                        isSelected
                          ? "block w-full rounded-[8px] border border-primary/30 bg-primary/10 p-3 text-left shadow-[0_0_0_1px_rgba(245,179,1,0.08)] outline-none focus-visible:ring-2 focus-visible:ring-ring"
                          : "block w-full rounded-[8px] border border-border/80 bg-background/70 p-3 text-left transition-colors outline-none hover:border-primary/20 hover:bg-muted/35 focus-visible:ring-2 focus-visible:ring-ring"
                      }
                      onClick={() => void loadRunDetail(run.runId)}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="truncate font-mono text-xs text-foreground">{run.runId}</p>
                          <p className="mt-1 text-[11px] text-muted-foreground">
                            {formatTimestamp(run.lastCheckpointedAt)}
                          </p>
                        </div>
                        <Badge variant={phaseBadgeVariant(run.phase)}>{run.phase}</Badge>
                      </div>
                      <div className="mt-3 grid grid-cols-3 gap-2">
                        <RunMetric label="Tracked" value={run.uniqueNodes.toLocaleString()} />
                        <RunMetric label="Attempted" value={run.scheduledTasks.toLocaleString()} />
                        <RunMetric label="Success" value={`${run.successPct.toFixed(2)}%`} />
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </section>

          <section className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Selected Run
              </p>
              <Badge variant="muted">
                {selectedRunSummary ? selectedRunSummary.phase : "No run selected"}
              </Badge>
            </div>

            {isLoadingDetail ? (
              <StatusPanel message="Loading run detail and checkpoint history." />
            ) : detailError ? (
              <StatusPanel tone="error" message={`Run detail failed to load: ${detailError}`} />
            ) : selectedDetail ? (
              <div className="space-y-6">
                <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
                  <div className="flex flex-wrap items-center gap-3">
                    <p className="break-all font-mono text-sm text-foreground">
                      {selectedDetail.run.runId}
                    </p>
                    <Badge variant="muted">
                      {formatTimestamp(selectedDetail.run.lastCheckpointedAt)}
                    </Badge>
                  </div>
                  <p className="mt-3 text-sm text-muted-foreground">
                    Review the latest public result and open only the slices you need.
                  </p>
                </div>

                {showPanelNav ? (
                  <div className="flex flex-wrap gap-2">
                    <PanelButton
                      label="Overview"
                      selected={activePanel === "overview"}
                      onClick={() => selectPanel("overview")}
                    />
                    <PanelButton
                      label="Checkpoints"
                      selected={activePanel === "checkpoints"}
                      onClick={() => selectPanel("checkpoints")}
                    />
                    <PanelButton
                      label="Failures"
                      selected={activePanel === "failures"}
                      onClick={() => selectPanel("failures")}
                    />
                    <PanelButton
                      label="Network"
                      selected={activePanel === "network"}
                      onClick={() => selectPanel("network")}
                    />
                  </div>
                ) : null}

                {activePanel === "overview" ? (
                  <DataList
                    items={[
                      { label: "Started", value: formatTimestamp(selectedDetail.run.startedAt) },
                      {
                        label: "Last checkpoint",
                        value: formatTimestamp(selectedDetail.run.lastCheckpointedAt),
                      },
                      {
                        label: "Stop reason",
                        value: selectedDetail.run.stopReason ?? "Run still active or not set",
                      },
                      {
                        label: "Failure reason",
                        value: selectedDetail.run.failureReason ?? "No terminal failure recorded",
                      },
                      {
                        label: "Attempted nodes",
                        value: selectedDetail.run.scheduledTasks.toLocaleString(),
                      },
                      {
                        label: "Successful visits",
                        value: selectedDetail.run.successfulHandshakes.toLocaleString(),
                      },
                      {
                        label: "Failed visits",
                        value: selectedDetail.run.failedTasks.toLocaleString(),
                      },
                      {
                        label: "Unscheduled gap",
                        value: selectedDetail.run.unscheduledGap.toLocaleString(),
                      },
                    ]}
                  />
                ) : null}

                {activePanel === "checkpoints" ? (
                  <DetailTable
                    title="Recent Checkpoints"
                    columns={["Phase", "Checkpointed", "Scheduled", "Failed"]}
                    rows={selectedDetail.checkpoints.map((checkpoint) => [
                      checkpoint.phase,
                      formatTimestamp(checkpoint.checkpointedAt),
                      checkpoint.scheduledTasks.toLocaleString(),
                      checkpoint.failedTasks.toLocaleString(),
                    ])}
                    emptyMessage="No checkpoints were returned for this run."
                  />
                ) : null}

                {activePanel === "failures" ? (
                  <DetailTable
                    title="Failure Mix"
                    columns={["Classification", "Observations"]}
                    rows={selectedDetail.failureCounts.map((entry) => [
                      entry.classification,
                      entry.observations.toLocaleString(),
                    ])}
                    emptyMessage="No classified failures were recorded."
                  />
                ) : null}

                {activePanel === "network" ? (
                  <DetailTable
                    title="Network Outcomes"
                    columns={["Network", "Observed", "Verified", "Verified %"]}
                    rows={selectedDetail.networkOutcomes.map((entry) => [
                      entry.networkType,
                      entry.observations.toLocaleString(),
                      entry.verifiedNodes.toLocaleString(),
                      `${entry.verifiedPct.toFixed(2)}%`,
                    ])}
                    emptyMessage="No network outcome rows were recorded."
                  />
                ) : null}
              </div>
            ) : (
              <StatusPanel message="Select a run to inspect its checkpoints and outcome mix." />
            )}
          </section>
        </div>
      </CardContent>
    </Card>
  );
}

function PanelButton({
  label,
  selected,
  onClick,
}: {
  label: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <Button type="button" variant={selected ? "default" : "secondary"} size="sm" onClick={onClick}>
      {label}
    </Button>
  );
}

function RunMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[6px] border border-border/70 bg-background/65 px-2.5 py-2">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 font-mono text-xs text-foreground">{value}</p>
    </div>
  );
}

function HeaderStat({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="min-w-[8rem] rounded-[8px] border border-border/70 bg-background/75 px-2.5 py-2 text-left sm:min-w-[8.75rem]">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 font-mono text-[13px] text-foreground">{value}</p>
      <p className="mt-1 truncate text-[11px] text-muted-foreground">{detail}</p>
    </div>
  );
}

function MetricCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-3 break-all font-mono text-base text-foreground">{value}</p>
      <p className="mt-2 text-sm text-muted-foreground">{detail}</p>
    </div>
  );
}

function DetailTable({
  title,
  columns,
  rows,
  emptyMessage,
}: {
  title: string;
  columns: string[];
  rows: string[][];
  emptyMessage: string;
}) {
  return (
    <div className="space-y-3">
      <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">{title}</p>
      {rows.length === 0 ? (
        <StatusPanel message={emptyMessage} />
      ) : (
        <div className="overflow-hidden rounded-[8px] border border-border/80 bg-background/70">
          <Table>
            <TableHeader>
              <TableRow>
                {columns.map((column) => (
                  <TableHead key={column}>{column}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row, index) => (
                <TableRow key={`${title}-${index}`}>
                  {row.map((value, valueIndex) => (
                    <TableCell key={`${title}-${index}-${valueIndex}`} className="font-mono">
                      {value}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

function StatusPanel({
  message,
  tone = "neutral",
}: {
  message: string;
  tone?: "neutral" | "error";
}) {
  return (
    <div
      className={
        tone === "error"
          ? "rounded-[8px] border border-red-500/30 bg-red-500/8 px-4 py-3 text-sm text-red-200"
          : "rounded-[8px] border border-border/80 bg-background/80 px-4 py-3 text-sm text-muted-foreground"
      }
    >
      {message}
    </div>
  );
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}

function formatRunDuration(startedAt: string, completedAt: string): string {
  const start = new Date(startedAt).getTime();
  const end = new Date(completedAt).getTime();

  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return "n/a";
  }

  const totalSeconds = Math.round((end - start) / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  return `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

function phaseBadgeVariant(phase: string): "default" | "muted" {
  return phase === "completed" ? "default" : "muted";
}
