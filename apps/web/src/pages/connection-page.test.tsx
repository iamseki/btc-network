// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ConnectionPage } from "./connection-page";

afterEach(() => {
  cleanup();
});

describe("ConnectionPage", () => {
  it("submits the handshake action from the form", () => {
    const onHandshake = vi.fn();

    render(
      <ConnectionPage
        node="seed.bitcoin.sipa.be:8333"
        lastHandshake={null}
        events={[]}
        isRunning={false}
        onNodeChange={() => {}}
        onHandshake={onHandshake}
      />,
    );

    fireEvent.submit(screen.getByRole("button", { name: "Run Handshake" }).closest("form")!);

    expect(onHandshake).toHaveBeenCalledTimes(1);
  });

  it("shows handshake results when available", () => {
    render(
      <ConnectionPage
        node="seed.bitcoin.sipa.be:8333"
        lastHandshake={{
          node: "seed.bitcoin.sipa.be:8333",
          protocolVersion: 70016,
          services: "0x0000000000000009",
          userAgent: "/Satoshi:28.0.0/",
          startHeight: 938408,
          relay: true,
        }}
        events={[]}
        isRunning={false}
        onNodeChange={() => {}}
        onHandshake={() => {}}
      />,
    );

    expect(screen.getByText("Protocol version")).toBeTruthy();
    expect(screen.getByText("70016")).toBeTruthy();
    expect(screen.getByText("/Satoshi:28.0.0/")).toBeTruthy();
  });
});
