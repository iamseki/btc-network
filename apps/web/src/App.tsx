import { Blocks, Network, Radio, Waypoints } from "lucide-react";
import { useEffect, useState } from "react";

import { appPages, type AppPageId } from "./app/page-registry";
import { prependLogEvent } from "./app/log-events";
import { SessionLogPanel } from "./components/session-log-panel";
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
import type {
  AddrResult,
  BlockDownloadResult,
  BlockSummary,
  HandshakeResult,
  LastBlockHeightProgress,
  LastBlockHeightResult,
  PingResult,
  UiLogEvent,
} from "./lib/api/types";

const defaultNode = "seed.bitnodes.io:8333";
const sampleBlockHash =
  "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

export function App() {
  const [selectedPage, setSelectedPage] = useState<AppPageId>("connection");
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
      message: "Frontend loaded. Desktop mode exposes real handshake, ping, and last block height flows.",
    },
  ]);
  const [isSessionLogOpen, setIsSessionLogOpen] = useState(false);

  const [lastHandshake, setLastHandshake] = useState<HandshakeResult | null>(null);
  const [isHandshaking, setIsHandshaking] = useState(false);

  const [lastPing, setLastPing] = useState<PingResult | null>(null);
  const [isPinging, setIsPinging] = useState(false);
  const [lastAddrResult, setLastAddrResult] = useState<AddrResult | null>(null);
  const [isGettingAddr, setIsGettingAddr] = useState(false);

  const [lastBlockHeight, setLastBlockHeight] = useState<LastBlockHeightResult | null>(null);
  const [lastBlockHeightProgress, setLastBlockHeightProgress] =
    useState<LastBlockHeightProgress | null>(null);
  const [isLoadingLastBlockHeight, setIsLoadingLastBlockHeight] = useState(false);

  const [blockHash, setBlockHash] = useState(sampleBlockHash);
  const [downloadPath, setDownloadPath] = useState("");
  const [blockSummary, setBlockSummary] = useState<BlockSummary | null>(null);
  const [downloadResult, setDownloadResult] = useState<BlockDownloadResult | null>(null);
  const [isLoadingBlock, setIsLoadingBlock] = useState(false);
  const [isDownloadingBlock, setIsDownloadingBlock] = useState(false);

  const page = appPages.find((entry) => entry.id === selectedPage)!;
  const currentPageIcon = pageIcons[selectedPage];
  const runtimeLabel = client.constructor.name || "web-client";
  const isMobileSidebarOpen = !sidebarCollapsed;
  const desktopShellClass = sidebarCollapsed
    ? "md:grid-cols-[72px_minmax(0,1fr)]"
    : "md:grid-cols-[252px_minmax(0,1fr)]";

  function pushEvent(level: "info" | "warn" | "error", message: string) {
    setEvents((current) =>
      prependLogEvent(current, {
        at: new Date().toISOString(),
        level,
        message,
      }),
    );
  }

  function clearEvents() {
    setEvents([]);
  }

  useEffect(() => {
    let cancelled = false;

    void client.getSuggestedBlockDownloadPath(blockHash).then((nextPath) => {
      if (!cancelled) {
        setDownloadPath(nextPath);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [blockHash, client]);

  async function handleHandshake() {
    setIsHandshaking(true);
    setLastHandshake(null);
    pushEvent("info", `Running handshake against ${node}`);

    try {
      const result = await client.handshake({ node });
      setLastHandshake(result);
      pushEvent(
        "info",
        `Handshake complete. Services: ${result.serviceNames.join(", ")}. Peer start height: ${result.startHeight}`,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      pushEvent("error", `Handshake failed: ${message}`);
    } finally {
      setIsHandshaking(false);
    }
  }

  async function handleGetLastBlockHeight() {
    setIsLoadingLastBlockHeight(true);
    setLastBlockHeightProgress(null);
    pushEvent("info", `Fetching last block height from ${node}`);

    try {
      const result = await client.getLastBlockHeight(node, (progress) => {
        setLastBlockHeightProgress(progress);
      });
      setLastBlockHeight(result);
      pushEvent(
        "info",
        `Last block height: ${result.height} (${result.rounds} rounds, ${result.elapsedMs}ms)`,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLastBlockHeightProgress(null);
      pushEvent("error", `Last block height failed: ${message}`);
    } finally {
      setIsLoadingLastBlockHeight(false);
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

  async function handleGetAddr() {
    setIsGettingAddr(true);
    pushEvent("info", `Fetching peer addresses from ${node}`);

    try {
      const result = await client.getAddr(node);
      setLastAddrResult(result);
      pushEvent("info", `Received ${result.addresses.length} peer addresses`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      pushEvent("error", `Peer address fetch failed: ${message}`);
    } finally {
      setIsGettingAddr(false);
    }
  }

  async function handleGetBlock() {
    setIsLoadingBlock(true);
    setBlockSummary(null);
    pushEvent("info", `Fetching block ${blockHash} from ${node}`);

    try {
      const result = await client.getBlock(node, blockHash);
      setBlockSummary(result);
      pushEvent("info", `Loaded block ${result.hash} with ${result.txCount} transactions`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      pushEvent("error", `Block fetch failed: ${message}`);
    } finally {
      setIsLoadingBlock(false);
    }
  }

  async function handleDownloadBlock() {
    setIsDownloadingBlock(true);
    setDownloadResult(null);
    pushEvent("info", `Downloading block ${blockHash} from ${node}`);

    try {
      const result = await client.downloadBlock({
        node,
        hash: blockHash,
        outputPath: downloadPath,
      });
      setDownloadResult(result);
      pushEvent("info", `Saved block record to ${result.outputPath}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      pushEvent("error", `Block download failed: ${message}`);
    } finally {
      setIsDownloadingBlock(false);
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className={`relative min-h-screen md:grid md:w-full ${desktopShellClass}`}>
        {isMobileSidebarOpen ? (
          <button
            type="button"
            aria-label="Close navigation overlay"
            className="fixed inset-0 z-10 bg-background/65 backdrop-blur-sm md:hidden"
            onClick={() => setSidebarCollapsed(true)}
          />
        ) : null}

        <Sidebar
          className={`fixed inset-y-0 left-0 z-20 w-[252px] transition-transform duration-200 ease-out ${
            isMobileSidebarOpen ? "translate-x-0" : "-translate-x-full"
          } shadow-[0_24px_48px_rgba(10,10,10,0.45)] md:relative md:w-auto md:translate-x-0 md:shadow-none`}
        >
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
                      onClick={() => {
                        setSelectedPage(entry.id);
                        if (window.innerWidth < 768) {
                          setSidebarCollapsed(true);
                        }
                      }}
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

        <main className="flex min-h-screen min-w-0 flex-col bg-background md:col-start-2">
          <header className="sticky top-0 z-10 border-b border-border bg-background/95 px-3 py-3 backdrop-blur md:px-4">
            <div className="flex flex-col gap-3 md:h-14 md:flex-row md:items-center">
              <div className="flex min-w-0 items-center gap-3">
                <SidebarTrigger
                  collapsed={sidebarCollapsed}
                  className="shrink-0 md:hidden"
                  aria-label={sidebarCollapsed ? "Open navigation" : "Close navigation"}
                  onClick={() => setSidebarCollapsed((current) => !current)}
                />
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
              <div className="md:ml-auto">
                <div className="rounded-md border border-border bg-card px-3 py-1.5 font-mono text-xs text-foreground break-all md:max-w-[24rem]">
                  {node}
                </div>
              </div>
            </div>
          </header>

          <div className="flex min-h-0 flex-1 flex-col">
            <div className="grid flex-1 gap-4 p-3 md:gap-6 md:p-4 lg:p-6">
              {selectedPage === "connection" ? (
                <ConnectionPage
                  node={node}
                  lastHandshake={lastHandshake}
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
                  isGettingAddr={isGettingAddr}
                  onPing={handlePing}
                  onGetAddr={handleGetAddr}
                />
              ) : null}

              {selectedPage === "headers" ? (
                <HeadersPage
                  node={node}
                  lastBlockHeight={lastBlockHeight}
                  lastBlockHeightProgress={lastBlockHeightProgress}
                  isLoadingLastBlockHeight={isLoadingLastBlockHeight}
                  onGetLastBlockHeight={handleGetLastBlockHeight}
                />
              ) : null}

              {selectedPage === "blocks" ? (
                <BlocksPage
                  node={node}
                  blockHash={blockHash}
                  downloadPath={downloadPath}
                  blockSummary={blockSummary}
                  downloadResult={downloadResult}
                  isLoadingBlock={isLoadingBlock}
                  isDownloadingBlock={isDownloadingBlock}
                  onBlockHashChange={setBlockHash}
                  onDownloadPathChange={setDownloadPath}
                  onGetBlock={handleGetBlock}
                  onDownloadBlock={handleDownloadBlock}
                />
              ) : null}
            </div>

            <SessionLogPanel
              events={events}
              isOpen={isSessionLogOpen}
              onToggle={() => setIsSessionLogOpen((current) => !current)}
              onClear={clearEvents}
            />
          </div>
        </main>
      </div>
    </div>
  );
}
