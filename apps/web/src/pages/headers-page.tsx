import { LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";

import type { LastBlockHeightProgress, LastBlockHeightResult } from "../lib/api/types";

export type HeadersPageProps = {
  node: string;
  lastBlockHeight: LastBlockHeightResult | null;
  lastBlockHeightProgress?: LastBlockHeightProgress | null;
  isLoadingLastBlockHeight?: boolean;
  onGetLastBlockHeight?: () => void;
};

export function HeadersPage({
  node,
  lastBlockHeight,
  lastBlockHeightProgress = null,
  isLoadingLastBlockHeight = false,
  onGetLastBlockHeight,
}: HeadersPageProps) {
  const [loadingElapsedMs, setLoadingElapsedMs] = useState(0);

  useEffect(() => {
    if (!isLoadingLastBlockHeight) {
      setLoadingElapsedMs(0);
      return;
    }

    const startedAt = Date.now();
    setLoadingElapsedMs(0);

    const intervalId = window.setInterval(() => {
      setLoadingElapsedMs(Date.now() - startedAt);
    }, 1000);

    return () => window.clearInterval(intervalId);
  }, [isLoadingLastBlockHeight]);

  const viewState = buildChainHeightViewState(
    lastBlockHeight,
    lastBlockHeightProgress,
    isLoadingLastBlockHeight,
    loadingElapsedMs,
  );

  return (
    <Card>
      <CardContent className="space-y-6 p-6">
        <SectionHeading
          eyebrow="Chain"
          title="Chain Height"
          description="Fetch the peer's current best-known block height and inspect the block hash that anchors it."
          actions={<Badge>Best Known Tip</Badge>}
        />

        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto]">
          <div className="rounded-[8px] border border-border/80 bg-background/80 px-4 py-3 font-mono text-sm text-foreground">
            {node}
          </div>
          <Button
            type="button"
            disabled={isLoadingLastBlockHeight}
            onClick={onGetLastBlockHeight}
            className="w-full sm:w-auto"
          >
            {isLoadingLastBlockHeight ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
            {isLoadingLastBlockHeight ? "Fetching..." : "Fetch Last Block Height"}
          </Button>
        </div>
        {isLoadingLastBlockHeight ? (
          <div className="rounded-[8px] border border-primary/20 bg-primary/8 px-4 py-3 text-sm text-muted-foreground">
            <p className="flex items-center gap-2 text-foreground">
              <LoaderCircle className="h-4 w-4 animate-spin text-primary" />
              Scanning the peer's best-known chain tip.
            </p>
            <p className="mt-2">
              {viewState.liveElapsedSeconds !== null
                ? `Active for ${viewState.liveElapsedSeconds}s. `
                : null}
              The workflow advances with repeated{" "}
              <code className="font-mono text-xs text-foreground">getheaders</code> requests and
              reports each processed batch back to the UI.
            </p>
            {lastBlockHeight ? (
              <p className="mt-2">
                Holding the last successful snapshot at height{" "}
                <code className="font-mono text-xs text-foreground">{lastBlockHeight.height}</code>{" "}
                while the current scan runs.
              </p>
            ) : null}
            <a
              className="mt-2 inline-flex text-xs font-medium text-primary underline-offset-4 hover:underline"
              href="https://btcinformation.org/en/developer-guide#headers-first"
              target="_blank"
              rel="noreferrer"
            >
              Read more: Bitcoin headers-first sync
            </a>
          </div>
        ) : null}

        <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Scan Summary
              </p>
              <Badge>{isLoadingLastBlockHeight ? "Updating" : "Ready"}</Badge>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <MetricPanel label="Status" value={viewState.statusLabel} />
              <MetricPanel label="Height" value={viewState.observedHeight ?? "n/a"} />
              <MetricPanel
                label="Elapsed"
                value={viewState.elapsedMs !== null ? `${viewState.elapsedMs} ms` : "n/a"}
              />
            </div>
            <p className="text-sm text-muted-foreground">
              {isLoadingLastBlockHeight && viewState.liveElapsedSeconds !== null
                ? `${viewState.liveElapsedSeconds}s into the current request.`
                : "Ready to query the peer again."}
            </p>
          </div>

          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Tip Snapshot
              </p>
              <Badge variant="muted">
                {viewState.observedHash ? "Hash available" : "Waiting"}
              </Badge>
            </div>

            {lastBlockHeight || lastBlockHeightProgress ? (
              <div className="space-y-4">
                <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                    Best block hash
                  </p>
                  <p className="mt-3 break-all font-mono text-sm text-foreground">
                    {viewState.observedHash ?? "n/a"}
                  </p>
                </div>

                <DataList
                  items={[
                    { label: "Rounds", value: viewState.observedRounds ?? "n/a" },
                    { label: "Last batch", value: viewState.lastBatchCount ?? "n/a" },
                  ]}
                />
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                Fetch the current chain height for this peer.
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function MetricPanel({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail?: string;
}) {
  return (
    <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-3 font-mono text-base text-foreground">{value}</p>
      {detail ? <p className="mt-2 text-sm text-muted-foreground">{detail}</p> : null}
    </div>
  );
}

type ChainHeightViewState = {
  liveElapsedSeconds: number | null;
  statusLabel: string;
  observedHeight: number | null;
  observedHash: string | null;
  observedRounds: number | null;
  lastBatchCount: number | null;
  elapsedMs: number | null;
};

function buildChainHeightViewState(
  lastBlockHeight: LastBlockHeightResult | null,
  lastBlockHeightProgress: LastBlockHeightProgress | null,
  isLoadingLastBlockHeight: boolean,
  loadingElapsedMs: number,
): ChainHeightViewState {
  const elapsedMs = lastBlockHeightProgress?.elapsedMs ?? lastBlockHeight?.elapsedMs ?? null;

  return {
    liveElapsedSeconds: isLoadingLastBlockHeight
      ? Math.max(1, Math.floor((lastBlockHeightProgress?.elapsedMs ?? loadingElapsedMs) / 1000))
      : null,
    statusLabel: describeChainHeightPhase(
      lastBlockHeightProgress?.phase,
      isLoadingLastBlockHeight,
    ),
    observedHeight: lastBlockHeightProgress?.headersSeen ?? lastBlockHeight?.height ?? null,
    observedHash:
      lastBlockHeightProgress?.bestBlockHash ?? lastBlockHeight?.bestBlockHash ?? null,
    observedRounds: lastBlockHeightProgress?.roundsCompleted ?? lastBlockHeight?.rounds ?? null,
    lastBatchCount: lastBlockHeightProgress?.lastBatchCount ?? null,
    elapsedMs,
  };
}

function describeChainHeightPhase(
  phase: LastBlockHeightProgress["phase"] | undefined,
  isLoadingLastBlockHeight: boolean,
): string {
  switch (phase) {
    case "connecting":
      return "Connecting to peer";
    case "handshaking":
      return "Negotiating handshake";
    case "requesting_headers":
      return "Scanning headers";
    case "completed":
      return "Completed";
    default:
      return isLoadingLastBlockHeight ? "Starting scan" : "Standing by";
  }
}
