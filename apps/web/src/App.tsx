import { useState } from "react";

import { appPages, type AppPageId } from "./app/page-registry";
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
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <p className="eyebrow">btc-network</p>
          <h1>Protocol Workbench</h1>
          <p className="muted">
            Web-first UI scaffold for the Rust Bitcoin P2P client.
          </p>
        </div>

        <nav className="nav">
          {appPages.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className={entry.id === selectedPage ? "nav-item active" : "nav-item"}
              onClick={() => setSelectedPage(entry.id)}
            >
              <span>{entry.title}</span>
              <small>{entry.description}</small>
            </button>
          ))}
        </nav>

        <section className="status-card">
          <p className="eyebrow">Adapter</p>
          <h2>Web Placeholder</h2>
          <p className="muted">
            Current client is mock-backed so the interface can evolve before the Tauri bridge lands.
          </p>
          <code>{client.constructor.name || "web-client"}</code>
        </section>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">Current page</p>
            <h2>{page.title}</h2>
          </div>
          <div className="node-chip">{defaultNode}</div>
        </header>

        <section className="canvas">
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
        </section>
      </main>
    </div>
  );
}
