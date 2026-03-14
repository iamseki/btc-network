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
  });
});
