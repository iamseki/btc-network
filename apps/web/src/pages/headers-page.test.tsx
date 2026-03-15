// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { HeadersPage } from "./headers-page";

afterEach(() => {
  cleanup();
});

describe("HeadersPage", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows the loading guidance while fetching chain height", () => {
    render(
      <HeadersPage
        node="seed.bitcoin.sipa.be:8333"
        lastBlockHeight={null}
        isLoadingLastBlockHeight={true}
      />,
    );

    expect(screen.getByText("Scanning the peer's best-known chain tip.")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Bitcoin headers-first sync/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Fetching..." }).hasAttribute("disabled")).toBe(
      true,
    );
  });

  it("keeps the last successful snapshot visible while a new scan is running", () => {
    render(
      <HeadersPage
        node="seed.bitcoin.sipa.be:8333"
        lastBlockHeight={{
          height: 938408,
          rounds: 470,
          elapsedMs: 545450,
          bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
        }}
        lastBlockHeightProgress={{
          operationId: "op-1",
          node: "seed.bitcoin.sipa.be:8333",
          phase: "requesting_headers",
          roundsCompleted: 471,
          headersSeen: 940000,
          lastBatchCount: 1592,
          bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
          elapsedMs: 1000,
        }}
        isLoadingLastBlockHeight={true}
      />,
    );

    vi.advanceTimersByTime(1000);

    expect(
      screen.getByText((content) => content.includes("Holding the last successful snapshot")),
    ).toBeTruthy();
    expect(screen.getByText("Height")).toBeTruthy();
    expect(screen.getByText("Scanning headers")).toBeTruthy();
    expect(screen.getByText("Rounds")).toBeTruthy();
    expect(screen.getByText("1592")).toBeTruthy();
    expect(screen.getByText("1s into the current request.")).toBeTruthy();
    expect(
      screen.getByText("00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde"),
    ).toBeTruthy();
    expect(screen.getByText("Last batch")).toBeTruthy();
  });

  it("requests the last block height when the action is clicked", () => {
    const onGetLastBlockHeight = vi.fn();

    render(
      <HeadersPage
        node="seed.bitcoin.sipa.be:8333"
        lastBlockHeight={null}
        onGetLastBlockHeight={onGetLastBlockHeight}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Fetch Last Block Height" }));

    expect(onGetLastBlockHeight).toHaveBeenCalledTimes(1);
  });

  it("renders a completed status from the final progress snapshot", () => {
    render(
      <HeadersPage
        node="seed.bitcoin.sipa.be:8333"
        lastBlockHeight={{
          height: 938408,
          rounds: 470,
          elapsedMs: 545450,
          bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
        }}
        lastBlockHeightProgress={{
          operationId: "op-1",
          node: "seed.bitcoin.sipa.be:8333",
          phase: "completed",
          roundsCompleted: 470,
          headersSeen: 938408,
          lastBatchCount: 0,
          bestBlockHash: "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
          elapsedMs: 545450,
        }}
        isLoadingLastBlockHeight={false}
      />,
    );

    expect(screen.getByText("Completed")).toBeTruthy();
    expect(screen.getByText("Ready to query the peer again.")).toBeTruthy();
    expect(screen.getByText("Elapsed")).toBeTruthy();
  });
});
