import { Activity, Blocks, Network, Radio, Waypoints } from "lucide-react";
import { useState } from "react";

import { appPages, type AppPageId } from "./app/page-registry";
import { Badge } from "./components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { BlocksPage } from "./pages/blocks-page";
import { ConnectionPage } from "./pages/connection-page";
import { HeadersPage } from "./pages/headers-page";
import { PeerToolsPage } from "./pages/peer-tools-page";
import { getAppClient } from "./lib/api";

const defaultNode = "seed.bitcoin.sipa.be:8333";
const sampleBlockHash =
  "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

export function App() {
  const [selectedPage, setSelectedPage] = useState<AppPageId>("connection");
  const client = getAppClient();
  const pageIcons = {
    connection: Radio,
    "peer-tools": Network,
    headers: Waypoints,
    blocks: Blocks,
  } satisfies Record<AppPageId, typeof Radio>;

  const [events] = useState(() => [
    {
      at: new Date().toISOString(),
      level: "info" as const,
      message: "Frontend scaffold loaded. Native Rust commands are the next integration step.",
    },
  ]);

  const [lastHandshake] = useState(() => ({
    node: defaultNode,
    protocolVersion: 70016,
    services: "0x0000000000000000",
    userAgent: "/btc-network:ui-placeholder/",
    startHeight: 0,
    relay: null,
  }));

  const [lastPing] = useState(() => ({
    node: defaultNode,
    nonce: "0xfeedfacecafebeef",
    echoedNonce: "0xfeedfacecafebeef",
  }));

  const [lastAddrResult] = useState(() => ({
    node: defaultNode,
    addresses: [
      { address: "127.0.0.1", port: 8333, network: "ipv4" as const },
      { address: "::1", port: 8333, network: "ipv6" as const },
    ],
  }));

  const [headersResult] = useState(() => ({
    count: 2000,
    lastHeaderHash:
      "0000000000000000000000000000000000000000000000000000000000000000",
  }));

  const [syncResult] = useState(() => ({
    totalHeaders: 938408,
    rounds: 470,
    elapsedMs: 545450,
    mostRecentBlock:
      "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
  }));

  const [blockSummary] = useState(() => ({
    hash: sampleBlockHash,
    txCount: 1,
    serializedSize: 285,
    coinbaseTxDetected: true,
  }));

  const [downloadResult] = useState(() => ({
    hash: sampleBlockHash,
    outputPath: "blk-00000000-8ce26f.dat",
    rawBytes: 285,
  }));

  const page = appPages.find((entry) => entry.id === selectedPage)!;

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="mx-auto grid min-h-screen w-full max-w-[1600px] gap-6 px-4 py-4 lg:grid-cols-[320px_minmax(0,1fr)] lg:px-6 lg:py-6">
        <Card className="overflow-hidden">
          <CardHeader className="gap-8 border-b border-primary/20 bg-[linear-gradient(180deg,rgba(245,179,1,0.07),rgba(0,0,0,0)_20%),linear-gradient(180deg,rgba(255,255,255,0.03),rgba(255,255,255,0))]">
            <div className="space-y-3">
              <Badge>btc-network</Badge>
              <div className="space-y-2">
                <CardTitle className="text-4xl">Protocol Workbench</CardTitle>
                <CardDescription>
                  Retro instrument panel for exploring the Rust Bitcoin P2P client without
                  dragging protocol rules into the frontend.
                </CardDescription>
              </div>
            </div>

            <div className="grid gap-3">
              <div className="rounded-[6px] border border-primary/20 bg-background/80 p-4">
                <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                  Aesthetic
                </p>
                <p className="mt-2 text-sm text-muted-foreground">
                  Black phosphor, amber signals, and a cleaner terminal-era feel.
                </p>
              </div>
              <div className="rounded-[6px] border border-border/80 bg-muted/40 p-4">
                <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
                  Adapter
                </p>
                <div className="mt-3 flex items-center gap-3">
                  <div className="rounded-[4px] border border-primary/20 bg-primary/10 p-2 text-primary">
                    <Activity className="h-4 w-4" />
                  </div>
                  <div>
                    <p className="font-mono text-sm font-semibold uppercase tracking-[0.14em] text-foreground">
                      Web Placeholder
                    </p>
                    <p className="font-mono text-xs text-muted-foreground">
                      {client.constructor.name || "web-client"}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </CardHeader>

          <CardContent className="p-4">
            <nav className="grid gap-2">
              {appPages.map((entry) => {
                const Icon = pageIcons[entry.id];
                return (
                  <button
                    key={entry.id}
                    type="button"
                    className={
                      entry.id === selectedPage
                        ? "group rounded-[6px] border border-primary/35 bg-primary/10 px-4 py-4 text-left transition-colors"
                        : "group rounded-[6px] border border-transparent bg-transparent px-4 py-4 text-left transition-colors hover:border-border hover:bg-muted/40"
                    }
                    onClick={() => setSelectedPage(entry.id)}
                  >
                    <div className="flex items-start gap-3">
                      <div className="rounded-[4px] border border-border/80 bg-background/80 p-2 text-primary">
                        <Icon className="h-4 w-4" />
                      </div>
                      <div className="space-y-1">
                        <p className="font-mono text-sm font-semibold uppercase tracking-[0.14em] text-foreground">
                          {entry.title}
                        </p>
                        <p className="text-sm text-muted-foreground">{entry.description}</p>
                      </div>
                    </div>
                  </button>
                );
              })}
            </nav>
          </CardContent>
        </Card>

        <main className="flex min-w-0 flex-col gap-6">
          <Card className="overflow-hidden">
            <CardContent className="flex flex-col gap-5 p-5 sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-2">
                <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.26em] text-primary">
                  Current page
                </p>
                <div>
                  <h2 className="font-serif text-3xl uppercase tracking-[0.12em] text-foreground">
                    {page.title}
                  </h2>
                  <p className="text-sm text-muted-foreground">{page.description}</p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <Badge variant="muted">Primary peer</Badge>
                <div className="rounded-[6px] border border-primary/50 bg-primary px-4 py-2 font-mono text-sm font-semibold text-primary-foreground shadow-[0_0_20px_rgba(245,179,1,0.15)]">
                  {defaultNode}
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-6">
            {selectedPage === "connection" ? (
              <ConnectionPage
                defaultNode={defaultNode}
                lastHandshake={lastHandshake}
                events={events}
              />
            ) : null}

            {selectedPage === "peer-tools" ? (
              <PeerToolsPage
                node={defaultNode}
                lastPing={lastPing}
                lastAddrResult={lastAddrResult}
              />
            ) : null}

            {selectedPage === "headers" ? (
              <HeadersPage
                node={defaultNode}
                headersResult={headersResult}
                syncResult={syncResult}
              />
            ) : null}

            {selectedPage === "blocks" ? (
              <BlocksPage
                node={defaultNode}
                blockHash={sampleBlockHash}
                blockSummary={blockSummary}
                downloadResult={downloadResult}
              />
            ) : null}
          </div>
        </main>
      </div>
    </div>
  );
}
