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
  blockSummary: BlockSummary | null;
  downloadResult: BlockDownloadResult | null;
  isLoadingBlock?: boolean;
  isDownloadingBlock?: boolean;
  onBlockHashChange?: (value: string) => void;
  onGetBlock?: () => void | Promise<void>;
  onDownloadBlock?: () => void | Promise<void>;
};

export function BlocksPage({
  node,
  blockHash,
  blockSummary,
  downloadResult,
  isLoadingBlock = false,
  isDownloadingBlock = false,
  onBlockHashChange,
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

        <form
          className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto_auto]"
          onSubmit={handleSubmit}
        >
          <TextInput
            id="block-hash"
            name="block-hash"
            value={blockHash}
            onChange={(event) => onBlockHashChange?.(event.target.value)}
          />
          <Button type="submit" disabled={isLoadingBlock}>
            {isLoadingBlock ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
            {isLoadingBlock ? "Loading..." : `Fetch Block ${node}`}
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={isDownloadingBlock}
            onClick={() => void onDownloadBlock?.()}
          >
            {isDownloadingBlock ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
            {isDownloadingBlock ? "Downloading..." : `Download Block ${node}`}
          </Button>
        </form>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Block Summary
              </p>
              <Badge variant="muted">Decoded</Badge>
            </div>
            {blockSummary ? (
              <DataList
                items={[
                  { label: "Hash", value: blockSummary.hash },
                  { label: "Transactions", value: blockSummary.txCount },
                  { label: "Serialized size", value: blockSummary.serializedSize },
                  {
                    label: "Coinbase detected",
                    value: blockSummary.coinbaseTxDetected ? "yes" : "no",
                  },
                ]}
              />
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
              <DataList
                items={[
                  { label: "Output path", value: downloadResult.outputPath },
                  { label: "Raw bytes", value: downloadResult.rawBytes },
                ]}
              />
            ) : (
              <p className="text-sm text-muted-foreground">No block downloaded yet.</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
