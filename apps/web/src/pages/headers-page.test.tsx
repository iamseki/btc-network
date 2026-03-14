// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HeadersPage } from "./headers-page";

afterEach(() => {
  cleanup();
});

describe("HeadersPage", () => {
  it("shows the loading guidance while fetching chain height", () => {
    render(
      <HeadersPage
        node="seed.bitcoin.sipa.be:8333"
        lastBlockHeight={null}
        isLoadingLastBlockHeight={true}
      />,
    );

    expect(screen.getByText("Fetching the best-known height from this peer.")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Bitcoin headers-first sync/i })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Fetching..." }).hasAttribute("disabled")).toBe(
      true,
    );
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
});
