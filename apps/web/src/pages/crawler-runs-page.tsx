import { LoaderCircle, RotateCw } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { BtcAppClient } from "@/lib/api/client";
import type { CrawlRunDetail, CrawlRunListItem } from "@/lib/api/types";

export type CrawlerRunsPanel = "overview" | "checkpoints" | "failures" | "network";

type CrawlerRunsPageProps = {
  client: BtcAppClient;
  activePanel?: CrawlerRunsPanel;
  onPanelChange?: (panel: CrawlerRunsPanel) => void;
  showPanelNav?: boolean;
};

export function CrawlerRunsPage({
  client,
  activePanel: controlledActivePanel,
  onPanelChange,
  showPanelNav = true,
}: CrawlerRunsPageProps) {
  const [runs, setRuns] = useState<CrawlRunListItem[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<CrawlRunDetail | null>(null);
  const [internalActivePanel, setInternalActivePanel] = useState<CrawlerRunsPanel>("overview");
  const [isLoadingRuns, setIsLoadingRuns] = useState(true);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [runsError, setRunsError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const activePanel = controlledActivePanel ?? internalActivePanel;

  useEffect(() => {
    void refreshRuns();
  }, []);

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
  const latestCheckpoint = selectedDetail?.checkpoints[0] ?? null;
  const dominantFailure =
    [...(selectedDetail?.failureCounts ?? [])].sort((left, right) => right.observations - left.observations)[0] ??
    null;
  const strongestNetwork =
    [...(selectedDetail?.networkOutcomes ?? [])].sort((left, right) => right.verifiedPct - left.verifiedPct)[0] ??
    null;
  const panelDescription =
    activePanel === "overview"
      ? "Inspect recent runs without opening every breakdown at once. Pick one run, then choose the exact slice you want to see."
      : activePanel === "checkpoints"
        ? "Review recent checkpoint progression for the selected run."
        : activePanel === "failures"
          ? "Inspect the dominant failure mix for the selected run."
          : "Compare network-specific outcomes for the selected run.";
  const summaryCards =
    activePanel === "overview"
      ? [
          {
            label: "Selected Run",
            value: selectedRunSummary?.phase ?? "No run selected",
            detail: selectedRunSummary?.runId ?? "No run loaded",
          },
          {
            label: "Visit Success",
            value: selectedRunSummary ? `${selectedRunSummary.successPct.toFixed(2)}%` : "n/a",
            detail: selectedRunSummary
              ? `${selectedRunSummary.successfulHandshakes}/${selectedRunSummary.scheduledTasks} attempted`
              : "No run loaded",
          },
          {
            label: "Tracked",
            value: selectedRunSummary?.uniqueNodes ?? "n/a",
            detail: selectedRunSummary
              ? `${selectedRunSummary.scheduledPct.toFixed(2)}% scheduled`
              : "No run loaded",
          },
          {
            label: "Backlog",
            value: selectedRunSummary?.unscheduledGap ?? "n/a",
            detail: selectedRunSummary
              ? `${selectedRunSummary.persistedObservationRows} persisted rows`
              : "No run loaded",
          },
        ]
      : activePanel === "checkpoints"
        ? [
            {
              label: "Checkpoint Rows",
              value: selectedDetail?.checkpoints.length ?? 0,
              detail: "Recent checkpoints returned for this run",
            },
            {
              label: "Latest Phase",
              value: latestCheckpoint?.phase ?? "n/a",
              detail: latestCheckpoint
                ? formatTimestamp(latestCheckpoint.checkpointedAt)
                : "No checkpoint rows returned",
            },
            {
              label: "Scheduled",
              value: latestCheckpoint?.scheduledTasks ?? "n/a",
              detail: latestCheckpoint ? "Tasks attempted by the latest checkpoint" : "No checkpoint rows returned",
            },
            {
              label: "Failed",
              value: latestCheckpoint?.failedTasks ?? "n/a",
              detail: latestCheckpoint ? "Failed tasks at the latest checkpoint" : "No checkpoint rows returned",
            },
          ]
        : activePanel === "failures"
          ? [
              {
                label: "Failure Classes",
                value: selectedDetail?.failureCounts.length ?? 0,
                detail: "Distinct classified failure buckets",
              },
              {
                label: "Dominant Failure",
                value: dominantFailure?.classification ?? "n/a",
                detail: dominantFailure
                  ? `${dominantFailure.observations} observations`
                  : "No classified failures recorded",
              },
              {
                label: "Failed Visits",
                value: selectedRunSummary?.failedTasks ?? "n/a",
                detail: "Total failed visits for the selected run",
              },
              {
                label: "Failure Reason",
                value: selectedRunSummary?.failureReason ?? "No terminal failure",
                detail: "Terminal failure reason from the selected run",
              },
            ]
          : [
              {
                label: "Network Rows",
                value: selectedDetail?.networkOutcomes.length ?? 0,
                detail: "Network breakdown rows returned for this run",
              },
              {
                label: "Best Network",
                value: strongestNetwork?.networkType ?? "n/a",
                detail: strongestNetwork
                  ? `${strongestNetwork.verifiedPct.toFixed(2)}% verified`
                  : "No network rows recorded",
              },
              {
                label: "Observed",
                value: (selectedDetail?.networkOutcomes ?? []).reduce(
                  (sum, row) => sum + row.observations,
                  0,
                ),
                detail: "Observed nodes across the selected network breakdown",
              },
              {
                label: "Verified",
                value: (selectedDetail?.networkOutcomes ?? []).reduce(
                  (sum, row) => sum + row.verifiedNodes,
                  0,
                ),
                detail: "Verified nodes across the selected network breakdown",
              },
            ];

  return (
    <Card>
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Network Analytics"
          title="Crawler Runs"
          description={panelDescription}
          actions={
            <Button
              type="button"
              variant="secondary"
              onClick={() => void refreshRuns(selectedRunId ?? undefined)}
              disabled={isLoadingRuns || isLoadingDetail}
            >
              {isLoadingRuns || isLoadingDetail ? (
                <LoaderCircle className="h-4 w-4 animate-spin" />
              ) : (
                <RotateCw className="h-4 w-4" />
              )}
              Refresh
            </Button>
          }
        />

        {selectedRunSummary ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {summaryCards.map((card) => (
              <MetricCard
                key={card.label}
                label={card.label}
                value={card.value}
                detail={card.detail}
              />
            ))}
          </div>
        ) : null}

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)]">
          <section className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Latest Runs
              </p>
              <Badge variant="muted">{runs.length} loaded</Badge>
            </div>

            {isLoadingRuns ? (
              <StatusPanel message="Loading recent crawler runs from the analytics API." />
            ) : runsError ? (
              <StatusPanel tone="error" message={`Crawler runs failed to load: ${runsError}`} />
            ) : runs.length === 0 ? (
              <StatusPanel message="No crawler runs persisted yet." />
            ) : (
              <div className="overflow-hidden rounded-[8px] border border-border/80 bg-background/70">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Run</TableHead>
                      <TableHead>Phase</TableHead>
                      <TableHead className="text-right">Attempted</TableHead>
                      <TableHead className="text-right">Success</TableHead>
                      <TableHead className="text-right">Tracked</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {runs.map((run) => {
                      const isSelected = run.runId === selectedRunId;

                      return (
                        <TableRow
                          key={run.runId}
                          className={
                            isSelected
                              ? "bg-primary/8"
                              : "transition-colors hover:bg-muted/35"
                          }
                        >
                          <TableCell className="align-top">
                            <button
                              type="button"
                              className="grid w-full cursor-pointer gap-1 rounded-[6px] px-2 py-1 -mx-2 -my-1 text-left transition-colors outline-none hover:bg-primary/8 focus-visible:bg-primary/8 focus-visible:ring-2 focus-visible:ring-ring"
                              onClick={() => void loadRunDetail(run.runId)}
                            >
                              <span className="font-mono text-xs text-foreground">{run.runId}</span>
                              <span className="text-xs text-muted-foreground">
                                {formatTimestamp(run.lastCheckpointedAt)}
                              </span>
                            </button>
                          </TableCell>
                          <TableCell className="align-top">
                            <Badge variant={phaseBadgeVariant(run.phase)}>{run.phase}</Badge>
                          </TableCell>
                          <TableCell className="text-right font-mono">
                            {run.scheduledTasks}
                          </TableCell>
                          <TableCell className="text-right font-mono">
                            {run.successPct.toFixed(2)}%
                          </TableCell>
                          <TableCell className="text-right font-mono">{run.uniqueNodes}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
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
                    Choose one detail slice instead of rendering every table at once.
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
                        value: selectedDetail.run.scheduledTasks.toString(),
                      },
                      {
                        label: "Successful visits",
                        value: selectedDetail.run.successfulHandshakes.toString(),
                      },
                      { label: "Failed visits", value: selectedDetail.run.failedTasks.toString() },
                      {
                        label: "Unscheduled gap",
                        value: selectedDetail.run.unscheduledGap.toString(),
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
                      checkpoint.scheduledTasks.toString(),
                      checkpoint.failedTasks.toString(),
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
                      entry.observations.toString(),
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
                      entry.observations.toString(),
                      entry.verifiedNodes.toString(),
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

function phaseBadgeVariant(phase: string): "default" | "muted" {
  return phase === "completed" ? "default" : "muted";
}
