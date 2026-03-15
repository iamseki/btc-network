// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const mockHandshake = vi.fn();
const mockPing = vi.fn();
const mockGetAddr = vi.fn();
const mockGetLastBlockHeight = vi.fn();
const mockGetBlock = vi.fn();
const mockDownloadBlock = vi.fn();
const mockGetRecentEvents = vi.fn();

vi.mock("./lib/api", () => ({
  getAppClient: () => ({
    handshake: mockHandshake,
    ping: mockPing,
    getAddr: mockGetAddr,
    getLastBlockHeight: mockGetLastBlockHeight,
    getBlock: mockGetBlock,
    downloadBlock: mockDownloadBlock,
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
  mockGetRecentEvents.mockReset();
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
    expect(await screen.findByText("Last block height")).toBeTruthy();
    expect(await screen.findByText("Last observed height")).toBeTruthy();
    expect(await screen.findByText("Best block hash")).toBeTruthy();
    expect(await screen.findByText("Headers scanned")).toBeTruthy();
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
    fireEvent.click(screen.getByRole("button", { name: /Download Block/i }));

    expect(mockDownloadBlock).toHaveBeenCalledWith(
      "seed.bitnodes.io:8333",
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
    expect(await screen.findByText("blk-00000000-8ce26f.dat")).toBeTruthy();
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
