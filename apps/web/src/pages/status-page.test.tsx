// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";
import type { NodeStatusItem } from "@/lib/api/types";
import { STATUS_POLL_INTERVAL_MS, StatusPage, classifyDisplayStatus } from "./status-page";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("StatusPage", () => {
  it("marks rows stale after five minutes", () => {
    const row = makeStatusRow({
      checkedAt: new Date("2026-05-02T12:00:00Z").toISOString(),
      status: "healthy",
    });

    expect(classifyDisplayStatus(row, Date.parse("2026-05-02T12:06:00Z"))).toBe("stale");
  });

  it("renders node status rows", async () => {
    vi.spyOn(Date, "now").mockReturnValue(new Date(2026, 4, 2, 13, 0).getTime());
    const healthyAt = new Date(2026, 4, 2, 12, 4).toISOString();
    const failedAt = new Date(2026, 4, 2, 11, 3).toISOString();
    const client = makeClient([
      makeStatusRow({
        label: "Sipa DNS Seed",
        status: "healthy",
        checkedAt: new Date().toISOString(),
        history: [
          { status: "healthy", checkedAt: healthyAt },
          { status: "failed", checkedAt: failedAt },
        ],
      }),
    ]);

    render(<StatusPage client={client} />);

    expect(await screen.findByText("Sipa DNS Seed")).toBeTruthy();
    expect(screen.getByText("Handshake succeeded.")).toBeTruthy();
    expect(screen.getAllByText(/12:04/).length).toBeGreaterThan(0);
    expect(screen.getByLabelText(/failed at/i)).toBeTruthy();
    expect(screen.getByText("Oldest")).toBeTruthy();
    expect(screen.getByText("Newest")).toBeTruthy();
    const historyButtons = screen
      .getAllByRole("button")
      .filter((button) => button.getAttribute("aria-label")?.includes(" check"));
    expect(historyButtons).toHaveLength(2);
    expect(historyButtons[0]?.getAttribute("aria-label")).toMatch(/^healthy at /);
    expect(historyButtons[1]?.getAttribute("aria-label")).toMatch(/^failed at /);
  });

  it("shows bucketed history behind a global window control", async () => {
    vi.spyOn(Date, "now").mockReturnValue(new Date(2026, 4, 2, 18, 0).getTime());
    const history = Array.from({ length: 260 }, (_, index) => ({
      status: index >= 257 ? "unknown" as const : index % 3 === 0 ? "failed" as const : "healthy" as const,
      checkedAt: new Date(2026, 4, 2, 12, index).toISOString(),
    }));
    const client = makeClient([
      makeStatusRow({
        history,
      }),
    ]);

    render(<StatusPage client={client} />);

    expect(await screen.findByText("260 checks in last 7d")).toBeTruthy();
    expect(screen.getByText("history buckets")).toBeTruthy();
    const historyButtons = screen
      .getAllByRole("button")
      .filter((button) => button.getAttribute("aria-label")?.includes(" check"));
    expect(historyButtons).toHaveLength(96);
    expect(historyButtons[0]?.getAttribute("aria-label")).toMatch(/^unknown at /);

    fireEvent.click(screen.getByRole("button", { name: "Last 30d" }));
    expect(screen.getByText("260 checks in last 30d")).toBeTruthy();
    expect(screen.getByText("history buckets")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Last 1y" }));
    expect(screen.getByText("260 checks in last 1y")).toBeTruthy();
  });

  it("polls every thirty seconds", async () => {
    vi.useFakeTimers();
    const listNodeStatus = vi.fn().mockResolvedValue([
      makeStatusRow({
        checkedAt: new Date().toISOString(),
      }),
    ]);
    const client = { listNodeStatus } as unknown as BtcAppClient;

    render(<StatusPage client={client} />);
    await act(async () => {
      await Promise.resolve();
    });

    await act(async () => {
      vi.advanceTimersByTime(STATUS_POLL_INTERVAL_MS);
      await Promise.resolve();
    });

    expect(listNodeStatus).toHaveBeenCalledTimes(2);
  });
});

function makeClient(rows: NodeStatusItem[]): BtcAppClient {
  return {
    listNodeStatus: vi.fn().mockResolvedValue(rows),
  } as unknown as BtcAppClient;
}

function makeStatusRow(overrides: Partial<NodeStatusItem> = {}): NodeStatusItem {
  const checkedAt = overrides.checkedAt ?? new Date().toISOString();
  return {
    endpoint: "seed.bitcoin.sipa.be:8333",
    label: "Sipa DNS Seed",
    description: "Long-running Bitcoin Core mainnet DNS seed.",
    status: "healthy",
    checkedAt,
    message: "Handshake succeeded.",
    history: [{ status: "healthy", checkedAt }],
    ...overrides,
  };
}
