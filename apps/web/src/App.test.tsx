// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

vi.mock("./lib/api", () => ({
  getAppClient: () => ({
    handshake: vi.fn(),
    ping: vi.fn(),
    getAddr: vi.fn(),
    getHeaders: vi.fn(),
    syncHeadersToTip: vi.fn(),
    getBlock: vi.fn(),
    downloadBlock: vi.fn(),
    getRecentEvents: vi.fn(),
  }),
}));

afterEach(() => {
  cleanup();
});

describe("App sidebar shell", () => {
  it("renders expanded by default", () => {
    render(<App />);

    expect(screen.getByText("Menu")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Peer Tools" })).toBeTruthy();
  });

  it("collapses the sidebar when the trigger is clicked", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Collapse sidebar" }));

    expect(screen.queryByText("Menu")).toBeNull();
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeTruthy();
  });

  it("switches the visible page from the sidebar", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: "Headers" }));

    expect(screen.getByText("Latest Batch")).toBeTruthy();
    expect(screen.getByText("Sync Summary")).toBeTruthy();
  });
});
