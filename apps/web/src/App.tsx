import { Blocks, Network, Radio, Waypoints } from "lucide-react";
import { useState } from "react";

import { appPages, type AppPageId } from "./app/page-registry";
import { prependLogEvent } from "./app/log-events";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarNavButton,
  SidebarProfile,
  SidebarTrigger,
} from "./components/ui/sidebar";
import { BlocksPage } from "./pages/blocks-page";
import { ConnectionPage } from "./pages/connection-page";
import { HeadersPage } from "./pages/headers-page";
import { PeerToolsPage } from "./pages/peer-tools-page";
import { getAppClient } from "./lib/api";
import type { HandshakeResult, PingResult, UiLogEvent } from "./lib/api/types";

const defaultNode = "seed.bitcoin.sipa.be:8333";
const sampleBlockHash =
  "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

export function App() {
  const [selectedPage, setSelectedPage] = useState<AppPageId>("peer-tools");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [client] = useState(() => getAppClient());
  const [node, setNode] = useState(defaultNode);
  const pageIcons = {
    connection: Radio,
    "peer-tools": Network,
    headers: Waypoints,
    blocks: Blocks,
  } satisfies Record<AppPageId, typeof Radio>;

  const [events, setEvents] = useState<UiLogEvent[]>(() => [
    {
      at: new Date().toISOString(),
      level: "info" as const,
      message: "Frontend scaffold loaded. Tauri-backed handshake and ping are available in desktop mode.",
    },
  ]);

  const [lastHandshake, setLastHandshake] = useState<HandshakeResult | null>(null);
  const [isHandshaking, setIsHandshaking] = useState(false);

  const [lastPing, setLastPing] = useState<PingResult | null>(null);
  const [isPinging, setIsPinging] = useState(false);

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
  const currentPageIcon = pageIcons[selectedPage];
  const runtimeLabel = client.constructor.name || "web-client";

  function pushEvent(level: "info" | "warn" | "error", message: string) {
    setEvents((current) =>
      prependLogEvent(current, {
        at: new Date().toISOString(),
        level,
        message,
      }),
    );
  }

  async function handleHandshake() {
    setIsHandshaking(true);
    setLastHandshake(null);
    pushEvent("info", `Running handshake against ${node}`);

    try {
      const result = await client.handshake({ node });
      setLastHandshake(result);
      pushEvent("info", `Handshake complete. Peer start height: ${result.startHeight}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      pushEvent("error", `Handshake failed: ${message}`);
    } finally {
      setIsHandshaking(false);
    }
  }

  async function handlePing() {
    setIsPinging(true);
    pushEvent("info", `Sending ping to ${node}`);

    try {
      const result = await client.ping(node);
      setLastPing(result);
      pushEvent("info", `Ping complete. Echoed nonce: ${result.echoedNonce}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      pushEvent("error", `Ping failed: ${message}`);
    } finally {
      setIsPinging(false);
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div
        className={`grid min-h-screen w-full ${
          sidebarCollapsed
            ? "lg:grid-cols-[72px_minmax(0,1fr)]"
            : "lg:grid-cols-[240px_minmax(0,1fr)]"
        }`}
      >
        <Sidebar className="min-h-screen">
          <SidebarContent className="space-y-3 py-2">
            <SidebarGroup label={undefined}>
              <div
                className={
                  sidebarCollapsed
                    ? "flex justify-center px-2"
                    : "flex items-center justify-between px-3"
                }
              >
                {sidebarCollapsed ? null : (
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                    Menu
                  </p>
                )}
                <SidebarTrigger
                  collapsed={sidebarCollapsed}
                  className="shrink-0"
                  onClick={() => setSidebarCollapsed((current) => !current)}
                />
              </div>
              <nav className="grid gap-1.5" aria-label="Primary">
                {appPages.map((entry) => {
                  const Icon = pageIcons[entry.id];
                  return (
                    <SidebarNavButton
                      key={entry.id}
                      type="button"
                      active={entry.id === selectedPage}
                      icon={<Icon className="h-4 w-4" />}
                      collapsed={sidebarCollapsed}
                      title={entry.title}
                      tooltip={entry.title}
                      onClick={() => setSelectedPage(entry.id)}
                    />
                  );
                })}
              </nav>
            </SidebarGroup>
          </SidebarContent>

          <SidebarFooter>
            <SidebarProfile collapsed={sidebarCollapsed} name="Operator Zero" role={runtimeLabel} />
          </SidebarFooter>
        </Sidebar>

        <main className="flex min-w-0 flex-col bg-background">
          <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b border-border bg-background/95 px-4 backdrop-blur">
            <div className="flex min-w-0 items-center gap-3">
              <div className="rounded-md border border-border bg-muted/60 p-2 text-muted-foreground">
                {(() => {
                  const PageIcon = currentPageIcon;
                  return <PageIcon className="h-4 w-4" />;
                })()}
              </div>
              <div className="min-w-0">
                <p className="truncate font-mono text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
                  Overview
                </p>
                <p className="truncate text-sm text-foreground">{page.title}</p>
              </div>
            </div>
            <div className="ml-auto flex items-center gap-3">
              <div className="rounded-md border border-border bg-card px-3 py-1.5 font-mono text-xs text-foreground">
                {node}
              </div>
            </div>
          </header>

          <div className="grid gap-6 p-4 lg:p-6">
            {selectedPage === "connection" ? (
              <ConnectionPage
                node={node}
                lastHandshake={lastHandshake}
                events={events}
                isRunning={isHandshaking}
                onNodeChange={setNode}
                onHandshake={handleHandshake}
              />
            ) : null}

            {selectedPage === "peer-tools" ? (
              <PeerToolsPage
                node={node}
                lastPing={lastPing}
                lastAddrResult={lastAddrResult}
                isPinging={isPinging}
                onPing={handlePing}
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
