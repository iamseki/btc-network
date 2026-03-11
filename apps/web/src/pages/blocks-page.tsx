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
};

export function BlocksPage({
  node,
  blockHash,
  blockSummary,
  downloadResult,
}: BlocksPageProps) {
  return (
    <Card>
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Block Data"
          title="Block Explorer"
          description="Request block details or write the raw Bitcoin `blk*.dat` record format without burying the file semantics."
          actions={<Badge>Witness-aware getdata</Badge>}
        />

        <form className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto_auto]">
          <TextInput id="block-hash" name="block-hash" defaultValue={blockHash} />
          <Button type="submit">GetBlock {node}</Button>
          <Button type="button" variant="secondary">
            DownloadBlock {node}
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
