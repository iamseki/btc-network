import { LoaderCircle } from "lucide-react";
import type { FormEvent } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";
import { TextInput } from "@/components/ui/text-input";

import type { BlockDownloadResult, BlockSummary } from "../lib/api/types";

export type BlocksPageProps = {
  node: string;
  blockHash: string;
  downloadPath: string;
  blockSummary: BlockSummary | null;
  downloadResult: BlockDownloadResult | null;
  isLoadingBlock?: boolean;
  isDownloadingBlock?: boolean;
  onBlockHashChange?: (value: string) => void;
  onDownloadPathChange?: (value: string) => void;
  onGetBlock?: () => void | Promise<void>;
  onDownloadBlock?: () => void | Promise<void>;
};

export function BlocksPage({
  node,
  blockHash,
  downloadPath,
  blockSummary,
  downloadResult,
  isLoadingBlock = false,
  isDownloadingBlock = false,
  onBlockHashChange,
  onDownloadPathChange,
  onGetBlock,
  onDownloadBlock,
}: BlocksPageProps) {
  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void onGetBlock?.();
  }

  return (
    <Card>
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Block Data"
          title="Block Explorer"
          description="Request block details or write the raw Bitcoin `blk*.dat` record format without burying the file semantics."
          actions={<Badge>Witness-aware getdata</Badge>}
        />

        <form className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]" onSubmit={handleSubmit}>
          <div className="space-y-3 rounded-[8px] border border-border/80 bg-background/70 p-4">
            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-primary">
              Block Target
            </p>
            <TextInput
              id="block-hash"
              name="block-hash"
              aria-label="Block hash"
              value={blockHash}
              onChange={(event) => onBlockHashChange?.(event.target.value)}
            />
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">
              <Button type="submit" disabled={isLoadingBlock} className="w-full sm:w-auto">
                {isLoadingBlock ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
                {isLoadingBlock ? "Loading..." : "Fetch Block"}
              </Button>
              <Badge variant="muted" className="max-w-full break-all">
                {node}
              </Badge>
            </div>
          </div>

          <div className="space-y-3 rounded-[8px] border border-border/80 bg-background/70 p-4">
            <div className="flex items-center justify-between gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-primary">
                Host Download Path
              </p>
              <Badge>blk record</Badge>
            </div>
            <TextInput
              id="download-path"
              name="download-path"
              aria-label="Host download path"
              value={downloadPath}
              onChange={(event) => onDownloadPathChange?.(event.target.value)}
            />
            <Button
              type="button"
              variant="secondary"
              disabled={isDownloadingBlock}
              onClick={() => void onDownloadBlock?.()}
              className="w-full whitespace-normal text-center leading-tight sm:w-auto"
            >
              {isDownloadingBlock ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
              {isDownloadingBlock ? "Downloading..." : "Download to Host Path"}
            </Button>
          </div>
        </form>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Block Summary
              </p>
              <Badge variant="muted">Decoded</Badge>
            </div>
            {blockSummary ? (
              <div className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <MetricBlock label="Transactions" value={blockSummary.txCount} />
                  <MetricBlock label="Serialized size" value={blockSummary.serializedSize} />
                </div>
                <DataList
                  items={[
                    { label: "Hash", value: blockSummary.hash },
                    {
                      label: "Coinbase detected",
                      value: blockSummary.coinbaseTxDetected ? "yes" : "no",
                    },
                  ]}
                />
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No block loaded yet.</p>
            )}
          </div>

          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Download Result
              </p>
              <Badge>blk record</Badge>
            </div>
            {downloadResult ? (
              <div className="space-y-4">
                <MetricBlock label="Raw bytes" value={downloadResult.rawBytes} />
                <DataList items={[{ label: "Output path", value: downloadResult.outputPath }]} />
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No block downloaded yet.</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function MetricBlock({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-[8px] border border-border/80 bg-background/80 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-3 font-mono text-2xl text-foreground">{value}</p>
    </div>
  );
}
