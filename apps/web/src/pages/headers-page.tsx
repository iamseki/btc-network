import { LoaderCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";

import type { LastBlockHeightResult } from "../lib/api/types";

export type HeadersPageProps = {
  node: string;
  lastBlockHeight: LastBlockHeightResult | null;
  isLoadingLastBlockHeight?: boolean;
  onGetLastBlockHeight?: () => void;
};

export function HeadersPage({
  node,
  lastBlockHeight,
  isLoadingLastBlockHeight = false,
  onGetLastBlockHeight,
}: HeadersPageProps) {
  return (
    <Card>
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Chain"
          title="Chain Height"
          description="Fetch the peer's current best-known block height and inspect the block hash that anchors it."
          actions={<Badge>Best Known Tip</Badge>}
        />

        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
          <div className="rounded-[20px] border border-border/80 bg-background/80 px-4 py-3 font-mono text-sm text-foreground">
            {node}
          </div>
          <Button
            type="button"
            disabled={isLoadingLastBlockHeight}
            onClick={onGetLastBlockHeight}
          >
            {isLoadingLastBlockHeight ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
            {isLoadingLastBlockHeight ? "Fetching..." : "Fetch Last Block Height"}
          </Button>
        </div>
        {isLoadingLastBlockHeight ? (
          <div className="rounded-[20px] border border-primary/20 bg-primary/8 px-4 py-3 text-sm text-muted-foreground">
            <p className="flex items-center gap-2 text-foreground">
              <LoaderCircle className="h-4 w-4 animate-spin text-primary" />
              Fetching the best-known height from this peer.
            </p>
            <p className="mt-2">
              This can take a while because the workflow walks forward from the genesis block using
              repeated <code className="font-mono text-xs text-foreground">getheaders</code>{" "}
              requests.
            </p>
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

        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
              Chain Height
            </p>
            <Badge>{isLoadingLastBlockHeight ? "Updating" : "Ready"}</Badge>
          </div>
          {lastBlockHeight ? (
            <DataList
              items={[
                { label: "Last block height", value: lastBlockHeight.height },
                { label: "Best block hash", value: lastBlockHeight.bestBlockHash ?? "n/a" },
                { label: "Rounds", value: lastBlockHeight.rounds },
                { label: "Elapsed (ms)", value: lastBlockHeight.elapsedMs },
              ]}
            />
          ) : (
            <p className="text-sm text-muted-foreground">
              Fetch the current chain height for this peer.
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
