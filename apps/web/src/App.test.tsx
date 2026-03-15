// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const mockHandshake = vi.fn();
const mockPing = vi.fn();
const mockGetAddr = vi.fn();
const mockGetLastBlockHeight = vi.fn();
const mockGetBlock = vi.fn();
const mockDownloadBlock = vi.fn();
const mockGetSuggestedBlockDownloadPath = vi.fn();
const mockGetRecentEvents = vi.fn();

vi.mock("./lib/api", () => ({
  getAppClient: () => ({
    handshake: mockHandshake,
    ping: mockPing,
    getAddr: mockGetAddr,
    getLastBlockHeight: mockGetLastBlockHeight,
    getBlock: mockGetBlock,
    downloadBlock: mockDownloadBlock,
    getSuggestedBlockDownloadPath: mockGetSuggestedBlockDownloadPath,
    getRecentEvents: mockGetRecentEvents,
  }),
}));

afterEach(() => {
  cleanup();
  mockHandshake.mockReset();
  mockPing.mockReset();
  mockGetAddr.mockReset();
  mockGetLastBlockHeight.mockReset();
  mockGetBlock.mockReset();
  mockDownloadBlock.mockReset();
  mockGetSuggestedBlockDownloadPath.mockReset();
  mockGetRecentEvents.mockReset();
  mockGetSuggestedBlockDownloadPath.mockResolvedValue(
    "downloads/blk-00000000-8ce26f.dat",
  );
});

beforeEach(() => {
  mockGetSuggestedBlockDownloadPath.mockResolvedValue(
    "downloads/blk-00000000-8ce26f.dat",
  );
});

describe("App sidebar shell", () => {
  it("renders collapsed by default", () => {
    render(<App />);

    expect(screen.queryByText("Menu")).toBeNull();
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Connection" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Connection" })).toBeTruthy();
    expect(screen.getByText("Session Log")).toBeTruthy();
    expect(screen.getByText(/Frontend loaded\./)).toBeTruthy();
  });

  it("expands the sidebar when the trigger is clicked", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Expand sidebar" }));

    expect(screen.getByText("Menu")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeTruthy();
  });

  it("switches the visible page from the sidebar", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Chain Height" }));

    expect(screen.getByRole("heading", { name: "Chain Height" })).toBeTruthy();
    expect(screen.getByText("Fetch the current chain height for this peer.")).toBeTruthy();
  });

  it("requests the last block height from the headers page", async () => {
    mockGetLastBlockHeight.mockImplementation(async (_node, onProgress) => {
      onProgress?.({
        operationId: "test-op",
        node: "seed.bitnodes.io:8333",
        phase: "requesting_headers",
        roundsCompleted: 470,
        headersSeen: 938408,
        lastBatchCount: 408,
        bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
        elapsedMs: 545450,
      });

      return {
        node: "seed.bitnodes.io:8333",
        height: 938408,
        rounds: 470,
        elapsedMs: 545450,
        bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
      };
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Chain Height" }));
    fireEvent.click(screen.getByRole("button", { name: /Fetch Last Block Height/i }));

    expect(mockGetLastBlockHeight).toHaveBeenCalledWith(
      "seed.bitnodes.io:8333",
      expect.any(Function),
    );
    expect(await screen.findByRole("heading", { name: "Chain Height" })).toBeTruthy();
    expect(await screen.findByText("Height")).toBeTruthy();
    expect(await screen.findByText("Best block hash")).toBeTruthy();
    expect(await screen.findByText("Rounds")).toBeTruthy();
  });

  it("fetches peer addresses from the peer tools page", async () => {
    mockGetAddr.mockResolvedValue({
      node: "seed.bitnodes.io:8333",
      addresses: [
        { address: "127.0.0.1", port: 8333, network: "ipv4" },
        { address: "::1", port: 8333, network: "ipv6" },
      ],
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Peer Tools" }));
    fireEvent.click(screen.getByRole("button", { name: /Fetch Peer Addresses/i }));

    expect(mockGetAddr).toHaveBeenCalledWith("seed.bitnodes.io:8333");
    expect(await screen.findByText("127.0.0.1")).toBeTruthy();
    expect(await screen.findByText("::1")).toBeTruthy();
  });

  it("fetches a block summary from the blocks page", async () => {
    mockGetBlock.mockResolvedValue({
      hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      txCount: 1,
      serializedSize: 285,
      coinbaseTxDetected: true,
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Block Explorer" }));
    fireEvent.click(screen.getByRole("button", { name: /Fetch Block/i }));

    expect(mockGetBlock).toHaveBeenCalledWith(
      "seed.bitnodes.io:8333",
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
    expect(await screen.findByText("Serialized size")).toBeTruthy();
    expect(await screen.findByText("285")).toBeTruthy();
  });

  it("downloads a block from the blocks page", async () => {
    mockDownloadBlock.mockResolvedValue({
      hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      outputPath: "blk-00000000-8ce26f.dat",
      rawBytes: 285,
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Block Explorer" }));
    await screen.findByDisplayValue("downloads/blk-00000000-8ce26f.dat");
    fireEvent.click(screen.getByRole("button", { name: /Download to Host Path/i }));

    expect(mockDownloadBlock).toHaveBeenCalledWith({
      node: "seed.bitnodes.io:8333",
      hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      outputPath: "downloads/blk-00000000-8ce26f.dat",
    });
    expect(await screen.findByText("blk-00000000-8ce26f.dat")).toBeTruthy();
  });

  it("logs human-readable services after a successful handshake", async () => {
    mockHandshake.mockResolvedValue({
      node: "seed.bitnodes.io:8333",
      protocolVersion: 70016,
      services: "0x0000000000000409",
      serviceNames: ["NODE_NETWORK", "NODE_WITNESS", "NODE_NETWORK_LIMITED"],
      userAgent: "/Satoshi:28.0.0/",
      startHeight: 938408,
      relay: true,
    });

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Run Handshake" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand" }));

    expect(
      await screen.findAllByText(
        /Handshake complete\. Services: NODE_NETWORK, NODE_WITNESS, NODE_NETWORK_LIMITED\./,
      ),
    ).toHaveLength(2);
  });

  it("refreshes the suggested host download path when the block hash changes", async () => {
    mockGetSuggestedBlockDownloadPath
      .mockResolvedValueOnce("downloads/blk-00000000-8ce26f.dat")
      .mockResolvedValueOnce("downloads/blk-ffffffff-abcdef.dat");

    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Block Explorer" }));
    const blockHashInput = await screen.findByRole("textbox", { name: "Block hash" });
    fireEvent.change(blockHashInput, {
      target: {
        value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffabcdef",
      },
    });

    expect(
      await screen.findByDisplayValue("downloads/blk-ffffffff-abcdef.dat"),
    ).toBeTruthy();
  });

  it("shows the session log on non-connection pages and can expand it", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Peer Tools" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand" }));

    expect(
      screen.getAllByText(/Frontend loaded\. Desktop mode exposes real handshake/),
    ).toHaveLength(2);
  });

  it("clears the session log from the global panel", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Expand" }));
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));

    expect(screen.getByText("No events captured for this session yet.")).toBeTruthy();
  });
});
