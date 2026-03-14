// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PeerToolsPage } from "./peer-tools-page";

afterEach(() => {
  cleanup();
});

describe("PeerToolsPage", () => {
  it("triggers ping and peer-address actions independently", () => {
    const onPing = vi.fn();
    const onGetAddr = vi.fn();

    render(
      <PeerToolsPage
        node="seed.bitcoin.sipa.be:8333"
        lastPing={null}
        lastAddrResult={null}
        isPinging={false}
        isGettingAddr={false}
        onPing={onPing}
        onGetAddr={onGetAddr}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Ping seed\.bitcoin\.sipa\.be:8333/i }));
    fireEvent.click(
      screen.getByRole("button", { name: /Fetch Peer Addresses seed\.bitcoin\.sipa\.be:8333/i }),
    );

    expect(onPing).toHaveBeenCalledTimes(1);
    expect(onGetAddr).toHaveBeenCalledTimes(1);
  });

  it("renders returned ping and peer address results", () => {
    render(
      <PeerToolsPage
        node="seed.bitcoin.sipa.be:8333"
        lastPing={{
          node: "seed.bitcoin.sipa.be:8333",
          nonce: "0xfeedfacecafebeef",
          echoedNonce: "0xfeedfacecafebeef",
        }}
        lastAddrResult={{
          node: "seed.bitcoin.sipa.be:8333",
          addresses: [
            { address: "1.2.3.4", port: 8333, network: "ipv4" },
            { address: "2001:db8::1", port: 8333, network: "ipv6" },
          ],
        }}
        isPinging={false}
        isGettingAddr={false}
        onPing={() => {}}
        onGetAddr={() => {}}
      />,
    );

    expect(screen.getByText("Echoed nonce")).toBeTruthy();
    expect(screen.getAllByText("0xfeedfacecafebeef")).toHaveLength(2);
    expect(screen.getByText("1.2.3.4")).toBeTruthy();
    expect(screen.getByText("2001:db8::1")).toBeTruthy();
    expect(screen.getByText("Showing 1-2 of 2")).toBeTruthy();
  });

  it("paginates peer addresses with a default page size of 10", () => {
    render(
      <PeerToolsPage
        node="seed.bitcoin.sipa.be:8333"
        lastPing={null}
        lastAddrResult={{
          node: "seed.bitcoin.sipa.be:8333",
          addresses: Array.from({ length: 12 }, (_, index) => ({
            address: `10.0.0.${index + 1}`,
            port: 8333,
            network: "ipv4" as const,
          })),
        }}
        isPinging={false}
        isGettingAddr={false}
        onPing={() => {}}
        onGetAddr={() => {}}
      />,
    );

    const rowsOnFirstPage = screen.getAllByRole("row");
    expect(rowsOnFirstPage).toHaveLength(11);
    expect(screen.getByText("10.0.0.1")).toBeTruthy();
    expect(screen.getByText("Showing 1-10 of 12")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    const rowsOnSecondPage = screen.getAllByRole("row");
    expect(rowsOnSecondPage).toHaveLength(3);
    expect(screen.queryByText("10.0.0.1")).toBeNull();
    expect(screen.getByText("Showing 11-12 of 12")).toBeTruthy();
  });

  it("allows the page size to be changed with the compact row selector", () => {
    render(
      <PeerToolsPage
        node="seed.bitcoin.sipa.be:8333"
        lastPing={null}
        lastAddrResult={{
          node: "seed.bitcoin.sipa.be:8333",
          addresses: Array.from({ length: 12 }, (_, index) => ({
            address: `172.16.0.${index + 1}`,
            port: 8333,
            network: "ipv4" as const,
          })),
        }}
        isPinging={false}
        isGettingAddr={false}
        onPing={() => {}}
        onGetAddr={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "25" }));

    expect(screen.getByText("172.16.0.12")).toBeTruthy();
    expect(screen.getByText("Showing 1-12 of 12")).toBeTruthy();
    expect(screen.getByText("Page 1 of 1")).toBeTruthy();
  });

  it("sorts the address table by clicking the column headers", () => {
    render(
      <PeerToolsPage
        node="seed.bitcoin.sipa.be:8333"
        lastPing={null}
        lastAddrResult={{
          node: "seed.bitcoin.sipa.be:8333",
          addresses: [
            { address: "10.0.0.9", port: 18333, network: "ipv4" },
            { address: "10.0.0.2", port: 8333, network: "ipv6" },
            { address: "10.0.0.5", port: 18444, network: "torv3" },
          ],
        }}
        isPinging={false}
        isGettingAddr={false}
        onPing={() => {}}
        onGetAddr={() => {}}
      />,
    );

    const rowsBeforeSort = screen
      .getAllByRole("row")
      .slice(1)
      .map((row) => row.textContent);
    expect(rowsBeforeSort[0]).toContain("10.0.0.2");

    fireEvent.click(screen.getByRole("button", { name: /sort by port/i }));

    const rowsAfterPortAsc = screen
      .getAllByRole("row")
      .slice(1)
      .map((row) => row.textContent);
    expect(rowsAfterPortAsc[0]).toContain("8333");
    expect(rowsAfterPortAsc[1]).toContain("18333");
    expect(rowsAfterPortAsc[2]).toContain("18444");

    fireEvent.click(screen.getByRole("button", { name: /sort by network/i }));

    const rowsAfterNetworkAsc = screen
      .getAllByRole("row")
      .slice(1)
      .map((row) => row.textContent);
    expect(rowsAfterNetworkAsc[0]).toContain("ipv4");
    expect(rowsAfterNetworkAsc[1]).toContain("ipv6");
    expect(rowsAfterNetworkAsc[2]).toContain("torv3");

    fireEvent.click(screen.getByRole("button", { name: /sort by network/i }));

    const rowsAfterNetworkDesc = screen
      .getAllByRole("row")
      .slice(1)
      .map((row) => row.textContent);
    expect(rowsAfterNetworkDesc[0]).toContain("torv3");
    expect(rowsAfterNetworkDesc[2]).toContain("ipv4");
  });

  it("shows the empty address state without rendering the table", () => {
    render(
      <PeerToolsPage
        node="seed.bitcoin.sipa.be:8333"
        lastPing={null}
        lastAddrResult={{
          node: "seed.bitcoin.sipa.be:8333",
          addresses: [],
        }}
        isPinging={false}
        isGettingAddr={false}
        onPing={() => {}}
        onGetAddr={() => {}}
      />,
    );

    expect(screen.getByText("No peer addresses yet.")).toBeTruthy();
    expect(screen.getByRole("button", { name: /previous/i }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByRole("button", { name: /next/i }).hasAttribute("disabled")).toBe(true);
  });
});
