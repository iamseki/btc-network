import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";

import type { AddrResult, PingResult } from "../lib/api/types";

export type PeerToolsPageProps = {
  node: string;
  lastPing: PingResult | null;
  lastAddrResult: AddrResult | null;
};

export function PeerToolsPage({
  node,
  lastPing,
  lastAddrResult,
}: PeerToolsPageProps) {
  return (
    <Card>
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Diagnostics"
          title="Peer Tools"
          description="Use the current single-peer actions without burying the protocol under generic dashboard chrome."
          actions={
            <>
              <Button type="button">Ping {node}</Button>
              <Button type="button" variant="secondary">
                GetAddr {node}
              </Button>
            </>
          }
        />

        <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Ping
              </p>
              <Badge variant="muted">Keepalive</Badge>
            </div>
            {lastPing ? (
              <DataList
                items={[
                  { label: "Nonce", value: lastPing.nonce },
                  { label: "Echoed nonce", value: lastPing.echoedNonce },
                ]}
              />
            ) : (
              <p className="text-sm text-muted-foreground">No ping sent yet.</p>
            )}
          </div>

          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                Addresses
              </p>
              <Badge variant="muted">
                {lastAddrResult ? `${lastAddrResult.addresses.length} peers` : "No peers"}
              </Badge>
            </div>
            {lastAddrResult ? (
              <div className="overflow-hidden rounded-[24px] border border-border/80 bg-background/80">
                <table className="w-full border-collapse text-sm">
                  <thead className="bg-muted/50 text-left text-[11px] uppercase tracking-[0.22em] text-muted-foreground">
                    <tr>
                      <th className="px-4 py-3 font-medium">Network</th>
                      <th className="px-4 py-3 font-medium">Address</th>
                      <th className="px-4 py-3 font-medium">Port</th>
                    </tr>
                  </thead>
                  <tbody>
                    {lastAddrResult.addresses.map((entry) => (
                      <tr
                        key={`${entry.network}-${entry.address}-${entry.port}`}
                        className="border-t border-border/80"
                      >
                        <td className="px-4 py-3 text-muted-foreground">{entry.network}</td>
                        <td className="px-4 py-3 break-all text-foreground">{entry.address}</td>
                        <td className="px-4 py-3 text-foreground">{entry.port}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No address result yet.</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
