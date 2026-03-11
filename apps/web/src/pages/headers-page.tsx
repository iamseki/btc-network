import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";

import type { HeaderFetchResult, HeaderSyncResult } from "../lib/api/types";

export type HeadersPageProps = {
  node: string;
  headersResult: HeaderFetchResult | null;
  syncResult: HeaderSyncResult | null;
};

export function HeadersPage({
  node,
  headersResult,
  syncResult,
}: HeadersPageProps) {
  return (
    <Card>
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Chain"
          title="Headers"
          description="Visualize both the one-shot `getheaders` response and the iterative sync-to-tip workflow already present in the CLI."
          actions={
            <>
              <Button type="button">GetHeaders {node}</Button>
              <Button type="button" variant="secondary">
                Sync To Tip {node}
              </Button>
            </>
          }
        />

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Latest Batch
              </p>
              <Badge variant="muted">GetHeaders</Badge>
            </div>
            {headersResult ? (
              <DataList
                items={[
                  { label: "Count", value: headersResult.count },
                  { label: "Last header hash", value: headersResult.lastHeaderHash ?? "n/a" },
                ]}
              />
            ) : (
              <p className="text-sm text-muted-foreground">No header batch fetched yet.</p>
            )}
          </div>

          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Sync Summary
              </p>
              <Badge>Tip Sync</Badge>
            </div>
            {syncResult ? (
              <DataList
                items={[
                  { label: "Total headers", value: syncResult.totalHeaders },
                  { label: "Rounds", value: syncResult.rounds },
                  { label: "Elapsed (ms)", value: syncResult.elapsedMs },
                  { label: "Most recent block", value: syncResult.mostRecentBlock ?? "n/a" },
                ]}
              />
            ) : (
              <p className="text-sm text-muted-foreground">No tip sync has been run yet.</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
