import {
  Activity,
  Blocks,
  ChartColumn,
  Coffee,
  Network,
  Radio,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import { useEffect, useState } from "react";

import { appPages, type AppPageId } from "./app/page-registry";
import { prependLogEvent } from "./app/log-events";
import {
  CrawlerLiveSignal,
  CrawlerPulseButton,
  useCrawlerSignalPlayback,
} from "./components/crawler-live-signal";
import { SessionLogPanel } from "./components/session-log-panel";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarNavButton,
  SidebarTrigger,
} from "./components/ui/sidebar";
import { BlocksPage } from "./pages/blocks-page";
import { ConnectionPage } from "./pages/connection-page";
import { CrawlerRunsPage, type CrawlerRunsPanel } from "./pages/crawler-runs-page";
import { HeadersPage } from "./pages/headers-page";
import {
  NetworkAnalyticsPage,
  type NetworkAnalyticsPanel,
} from "./pages/network-analytics-page";
import { PeerToolsPage } from "./pages/peer-tools-page";
import { ApiPage, type ApiPanel } from "./pages/api-page";
import { getAppClient } from "./lib/api";
import type {
  AddrResult,
  BlockDownloadResult,
  BlockSummary,
  CrawlRunDetail,
  HandshakeResult,
  LastBlockHeightProgress,
  LastBlockHeightResult,
  PingResult,
  UiLogEvent,
} from "./lib/api/types";
import { analyticsModeLabel } from "./lib/runtime-config";

const defaultNode = "seed.bitnodes.io:8333";
const sampleBlockHash =
  "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const DEFAULT_SUPPORT_URL = "https://buymeacoffee.com/chseki";
const supportUrl = import.meta.env.VITE_SUPPORT_URL?.trim() || DEFAULT_SUPPORT_URL;
const analyticsLabel = analyticsModeLabel();

export function App() {
  const [selectedPage, setSelectedPage] = useState<AppPageId>("network-analytics");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const [crawlerRunsPanel, setCrawlerRunsPanel] = useState<CrawlerRunsPanel>("overview");
  const [networkAnalyticsPanel, setNetworkAnalyticsPanel] =
    useState<NetworkAnalyticsPanel>("overview");
  const [apiPanel, setApiPanel] = useState<ApiPanel>("docs");
  const [client] = useState(() => getAppClient());
  const [node, setNode] = useState(defaultNode);
  const pageIcons = {
    api: ShieldCheck,
    "crawler-runs": Activity,
    "network-analytics": ChartColumn,
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
  const [latestCrawlerPreview, setLatestCrawlerPreview] = useState<CrawlRunDetail | null>(null);
  const [isLoadingCrawlerPreview, setIsLoadingCrawlerPreview] = useState(false);
  const [isCrawlerPreviewOpen, setIsCrawlerPreviewOpen] = useState(false);
  const [isCrawlerPreviewRendered, setIsCrawlerPreviewRendered] = useState(false);
  const [isCrawlerPreviewVisible, setIsCrawlerPreviewVisible] = useState(false);

  const page = appPages.find((entry) => entry.id === selectedPage)!;
  const currentPageIcon = pageIcons[selectedPage];
  const isMobileSidebarOpen = !sidebarCollapsed;
  const analyticsPages = appPages.filter((entry) => entry.group === "network-analytics");
  const peerPages = appPages.filter((entry) => entry.group === "peer-tools");
  const showsNodeContext = page.group === "peer-tools";
  const desktopShellClass = sidebarCollapsed
    ? "md:grid-cols-[72px_minmax(0,1fr)]"
    : "md:grid-cols-[252px_minmax(0,1fr)]";
  const currentSubnav =
    selectedPage === "network-analytics"
        ? {
            label: "Network Analytics Views",
            items: [
              { id: "overview", title: "Overview" },
              { id: "risk", title: "Risk" },
              { id: "asn", title: "Top ASNs" },
              { id: "verification", title: "Verification" },
            ] satisfies { id: NetworkAnalyticsPanel; title: string }[],
          activeItem: networkAnalyticsPanel,
          onSelect: (panel: string) => setNetworkAnalyticsPanel(panel as NetworkAnalyticsPanel),
        }
      : selectedPage === "crawler-runs"
        ? {
            label: "Crawler Runs Views",
            items: [
              { id: "overview", title: "Overview" },
              { id: "checkpoints", title: "Checkpoints" },
              { id: "failures", title: "Failures" },
              { id: "network", title: "Network" },
            ] satisfies { id: CrawlerRunsPanel; title: string }[],
            activeItem: crawlerRunsPanel,
            onSelect: (panel: string) => setCrawlerRunsPanel(panel as CrawlerRunsPanel),
          }
        : selectedPage === "api"
          ? {
              label: "API Views",
              items: [
                { id: "docs", title: "Docs" },
                { id: "overview", title: "Overview" },
                { id: "access", title: "Access" },
              ] satisfies { id: ApiPanel; title: string }[],
              activeItem: apiPanel,
              onSelect: (panel: string) => setApiPanel(panel as ApiPanel),
            }
        : null;
  const currentSubnavItemTitle =
    currentSubnav?.items.find((item) => item.id === currentSubnav.activeItem)?.title ?? "Overview";
  const crawlerPreviewPlayback = useCrawlerSignalPlayback(latestCrawlerPreview);

  function selectPage(nextPage: AppPageId) {
    setSelectedPage(nextPage);
    setIsCrawlerPreviewOpen(false);

    if (nextPage === "network-analytics") {
      setNetworkAnalyticsPanel("overview");
    }

    if (nextPage === "crawler-runs") {
      setCrawlerRunsPanel("overview");
    }

    if (nextPage === "api") {
      setApiPanel("docs");
    }

    if (window.innerWidth < 768) {
      setSidebarCollapsed(true);
    }
  }

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

  useEffect(() => {
    if (showsNodeContext) {
      setIsCrawlerPreviewOpen(false);
      return;
    }

    let cancelled = false;
    setIsLoadingCrawlerPreview(true);

    void (async () => {
      try {
        const runs = await client.listCrawlRuns(1);
        const latestRun = runs[0] ?? null;
        const nextDetail = latestRun ? await client.getCrawlRun(latestRun.runId) : null;

        if (!cancelled) {
          setLatestCrawlerPreview(nextDetail);
        }
      } catch {
        if (!cancelled) {
          setLatestCrawlerPreview(null);
        }
      } finally {
        if (!cancelled) {
          setIsLoadingCrawlerPreview(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [client, showsNodeContext]);

  useEffect(() => {
    if (isCrawlerPreviewOpen) {
      setIsCrawlerPreviewRendered(true);
      setIsCrawlerPreviewVisible(false);

      const timeout = window.setTimeout(() => {
        setIsCrawlerPreviewVisible(true);
      }, 24);

      return () => {
        window.clearTimeout(timeout);
      };
    }

    setIsCrawlerPreviewVisible(false);

    if (!isCrawlerPreviewRendered) {
      return;
    }

    const timeout = window.setTimeout(() => {
      setIsCrawlerPreviewRendered(false);
    }, 220);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [isCrawlerPreviewOpen, isCrawlerPreviewRendered]);

  function openNetworkAnalyticsFromPreview() {
    setIsCrawlerPreviewOpen(false);
    setSelectedPage("network-analytics");
    setNetworkAnalyticsPanel("overview");

    if (window.innerWidth < 768) {
      setSidebarCollapsed(true);
    }
  }

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
        {isCrawlerPreviewRendered && latestCrawlerPreview ? (
          <div className="fixed inset-0 z-30 flex items-center justify-center p-4 md:p-6">
            <button
              type="button"
              aria-label="Close latest snapshot preview"
              className={`absolute inset-0 bg-background/55 backdrop-blur-sm transition-opacity duration-300 ${
                isCrawlerPreviewVisible ? "opacity-100" : "opacity-0"
              }`}
              onClick={() => setIsCrawlerPreviewOpen(false)}
            />
            <div
              className={`relative z-10 w-full max-w-5xl rounded-[12px] border border-border/80 bg-card/96 p-2 shadow-[0_30px_80px_rgba(0,0,0,0.45)] transform-gpu transition-[opacity,transform,filter] duration-300 ease-out ${
                isCrawlerPreviewVisible
                  ? "translate-y-0 scale-100 opacity-100 blur-0"
                  : "translate-y-6 scale-[0.96] opacity-0 blur-[6px]"
              }`}
            >
              <CrawlerLiveSignal detail={latestCrawlerPreview} playback={crawlerPreviewPlayback} />
              <div className="flex justify-end px-2 pb-2">
                <button
                  type="button"
                  aria-label="Open network analytics from snapshot"
                  className="inline-flex h-10 items-center rounded-lg border border-primary/25 bg-primary/10 px-4 text-[11px] font-semibold uppercase tracking-[0.14em] text-primary shadow-[0_0_0_1px_rgba(245,158,11,0.10)] transition-colors hover:bg-primary/14"
                  onClick={openNetworkAnalyticsFromPreview}
                >
                  Open Network Analytics
                </button>
              </div>
            </div>
          </div>
        ) : null}

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
              <SidebarGroup label={sidebarCollapsed ? undefined : "Network Analytics"}>
                <nav className="grid gap-1.5" aria-label="Network analytics">
                  {analyticsPages.map((entry) => (
                    <PageNavButton
                      key={entry.id}
                      entry={entry}
                      collapsed={sidebarCollapsed}
                      selectedPage={selectedPage}
                      pageIcons={pageIcons}
                      onSelect={selectPage}
                    />
                  ))}
                </nav>
              </SidebarGroup>
              <SidebarGroup label={sidebarCollapsed ? undefined : "Peer Tools"}>
                <nav className="grid gap-1.5" aria-label="Peer tools">
                  {peerPages.map((entry) => (
                    <PageNavButton
                      key={entry.id}
                      entry={entry}
                      collapsed={sidebarCollapsed}
                      selectedPage={selectedPage}
                      pageIcons={pageIcons}
                      onSelect={selectPage}
                    />
                  ))}
                </nav>
              </SidebarGroup>
            </SidebarGroup>
          </SidebarContent>

          <SidebarFooter>
            {supportUrl ? (
              <a
                href={supportUrl}
                target="_blank"
                rel="noreferrer"
                className={
                  sidebarCollapsed
                    ? "flex h-10 items-center justify-center rounded-lg border border-border/80 bg-background/40 text-muted-foreground transition-colors hover:border-primary/30 hover:bg-muted hover:text-foreground"
                    : "flex items-center gap-3 rounded-lg border border-border/80 bg-background/40 px-3 py-3 text-left text-muted-foreground transition-colors hover:border-primary/30 hover:bg-muted hover:text-foreground"
                }
                aria-label="Buy Me a Coffee"
                title="Buy Me a Coffee and help fund analytics, research, and public infrastructure."
              >
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-muted/60 text-primary">
                  <Coffee className="h-4 w-4" />
                </span>
                {sidebarCollapsed ? null : (
                  <span className="min-w-0">
                    <span className="block font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-foreground">
                      Buy Me a Coffee
                    </span>
                    <span className="block text-xs leading-5 text-muted-foreground">
                      Help fund analytics, research, and public infrastructure.
                    </span>
                  </span>
                )}
              </a>
            ) : null}
          </SidebarFooter>
        </Sidebar>

        <main className="flex min-h-screen min-w-0 flex-col bg-background md:col-start-2">
          <header className="sticky top-0 z-10 border-b border-border bg-background/95 px-3 py-3 backdrop-blur md:px-4">
            <div className="flex flex-col gap-3 md:grid md:grid-cols-[minmax(0,max-content)_minmax(0,1fr)_max-content] md:items-center md:gap-4">
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
                    <p
                      data-testid="page-subview-label"
                      className="truncate font-mono text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground"
                    >
                      {currentSubnavItemTitle}
                    </p>
                    <p className="truncate text-sm text-foreground">{page.title}</p>
                  </div>
                </div>
              {currentSubnav ? (
                <nav
                  aria-label={currentSubnav.label}
                  className="min-w-0 overflow-x-auto md:flex md:justify-center"
                >
                  <div className="inline-flex min-w-max items-center gap-1.5 rounded-xl bg-card/80 p-1.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                    {currentSubnav.items.map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        className={
                          item.id === currentSubnav.activeItem
                            ? "inline-flex h-10 cursor-pointer items-center rounded-lg border border-primary/25 bg-primary/10 px-4 text-[11px] font-semibold uppercase tracking-[0.14em] text-primary shadow-[0_0_0_1px_rgba(245,158,11,0.10)]"
                            : "inline-flex h-10 cursor-pointer items-center rounded-lg border border-transparent px-4 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground transition-colors hover:border-border/70 hover:bg-muted/70 hover:text-primary"
                        }
                        onClick={() => currentSubnav.onSelect(item.id)}
                      >
                        {item.title}
                      </button>
                    ))}
                  </div>
                </nav>
              ) : null}
              <div className="md:ml-auto">
                {showsNodeContext ? (
                  <div className="rounded-md border border-border bg-card px-3 py-1.5 font-mono text-xs text-foreground break-all md:max-w-[24rem]">
                    {node}
                  </div>
                ) : latestCrawlerPreview || isLoadingCrawlerPreview ? (
                  <CrawlerPulseButton
                    summary={
                      crawlerPreviewPlayback?.currentSummary ??
                      crawlerPreviewPlayback?.finalSummary ??
                      latestCrawlerPreview?.run ??
                      null
                    }
                    live={crawlerPreviewPlayback?.isLive ?? false}
                    expanded={isCrawlerPreviewOpen}
                    disabled={!latestCrawlerPreview}
                    ariaLabel={
                      isCrawlerPreviewOpen
                        ? "Hide latest snapshot preview"
                        : "Show latest snapshot preview"
                    }
                    onClick={() => {
                      if (latestCrawlerPreview) {
                        setIsCrawlerPreviewOpen((current) => !current);
                      }
                    }}
                  />
                ) : (
                  <div className="rounded-md border border-border bg-card px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
                    {analyticsLabel}
                  </div>
                )}
              </div>
            </div>
          </header>

          <div className="flex min-h-0 flex-1 flex-col">
            <div className="grid flex-1 gap-4 p-3 md:gap-6 md:p-4 lg:p-6">
              {selectedPage === "crawler-runs" ? (
                <CrawlerRunsPage
                  client={client}
                  activePanel={crawlerRunsPanel}
                  onPanelChange={setCrawlerRunsPanel}
                  showPanelNav={false}
                />
              ) : null}

              {selectedPage === "network-analytics" ? (
                <NetworkAnalyticsPage
                  client={client}
                  activePanel={networkAnalyticsPanel}
                  onPanelChange={setNetworkAnalyticsPanel}
                  onOpenApiPage={() => selectPage("api")}
                  showPanelNav={false}
                />
              ) : null}

              {selectedPage === "api" ? (
                <ApiPage
                  client={client}
                  activePanel={apiPanel}
                  onPanelChange={setApiPanel}
                  showPanelNav={false}
                />
              ) : null}

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

            {showsNodeContext ? (
              <SessionLogPanel
                events={events}
                isOpen={isSessionLogOpen}
                onToggle={() => setIsSessionLogOpen((current) => !current)}
                onClear={clearEvents}
              />
            ) : null}
          </div>
        </main>
      </div>
    </div>
  );
}

function PageNavButton({
  entry,
  collapsed,
  selectedPage,
  pageIcons,
  onSelect,
}: {
  entry: (typeof appPages)[number];
  collapsed: boolean;
  selectedPage: AppPageId;
  pageIcons: Record<AppPageId, typeof Radio>;
  onSelect: (pageId: AppPageId) => void;
}) {
  const Icon = pageIcons[entry.id];

  return (
    <SidebarNavButton
      type="button"
      active={entry.id === selectedPage}
      icon={<Icon className="h-4 w-4" />}
      collapsed={collapsed}
      title={entry.title}
      tooltip={entry.title}
      onClick={() => onSelect(entry.id)}
    />
  );
}
