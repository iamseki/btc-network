export type AppPageId =
  | "crawler-runs"
  | "network-analytics"
  | "connection"
  | "peer-tools"
  | "headers"
  | "blocks";

export type AppPageGroupId = "network-analytics" | "peer-tools";

export type AppPage = {
  id: AppPageId;
  group: AppPageGroupId;
  title: string;
  description: string;
};

export const appPages: AppPage[] = [
  {
    id: "network-analytics",
    group: "network-analytics",
    title: "Network Analytics",
    description: "Summarize ASN concentration and recent verification outcomes from crawler data.",
  },
  {
    id: "crawler-runs",
    group: "network-analytics",
    title: "Crawler Runs",
    description: "Review recent crawl runs, compare outcomes, and inspect checkpoint progress.",
  },
  {
    id: "connection",
    group: "peer-tools",
    title: "Connection",
    description: "Connect to a peer, perform the handshake, and inspect version metadata.",
  },
  {
    id: "peer-tools",
    group: "peer-tools",
    title: "Peer Tools",
    description: "Run ping and address discovery against a single peer.",
  },
  {
    id: "headers",
    group: "peer-tools",
    title: "Chain Height",
    description: "Fetch the peer's latest known block height and inspect the best block hash.",
  },
  {
    id: "blocks",
    group: "peer-tools",
    title: "Block Explorer",
    description: "Request block details or download a raw block record by hash.",
  },
];
