export type AppPageId = "connection" | "peer-tools" | "headers" | "blocks";

export type AppPage = {
  id: AppPageId;
  title: string;
  description: string;
};

export const appPages: AppPage[] = [
  {
    id: "connection",
    title: "Connection",
    description: "Connect to a peer, perform the handshake, and inspect version metadata.",
  },
  {
    id: "peer-tools",
    title: "Peer Tools",
    description: "Run ping and address discovery against a single peer.",
  },
  {
    id: "headers",
    title: "Headers",
    description: "Fetch headers or sync forward to the peer tip with visible progress.",
  },
  {
    id: "blocks",
    title: "Block Explorer",
    description: "Request block details or download a raw block record by hash.",
  },
];
