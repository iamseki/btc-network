// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";
import { getDocsUiConfig } from "@/lib/api/docs-http";

import { ApiPage } from "./api-page";

vi.mock("@/lib/api/docs-http", () => ({
  getDocsUiConfig: vi.fn().mockResolvedValue({
    title: "btc-network API",
    version: "0.1.0",
    description: "Generated docs",
    introduction: "Start with runs.",
    openapiUrl: "/api/openapi.json",
    openapiPath: "/api/openapi.json",
    scalarPath: "/docs",
    baseServerUrl: null,
  }),
}));

vi.mock("@scalar/api-reference-react", () => ({
  ApiReferenceReact: ({ configuration }: { configuration: { url: string } }) => (
    <div data-testid="scalar-api-reference">{configuration.url}</div>
  ),
}));

afterEach(() => {
  cleanup();
});

function makeClient(overrides: Partial<BtcAppClient> = {}): BtcAppClient {
  return {
    listCrawlRuns: vi.fn().mockResolvedValue([
      {
        runId: "crawl-9",
        phase: "completed",
        startedAt: "2026-03-30T12:00:00Z",
        lastCheckpointedAt: "2026-03-30T12:05:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 100,
        successfulHandshakes: 42,
        failedTasks: 58,
        uniqueNodes: 130,
        persistedObservationRows: 100,
        successPct: 42,
        scheduledPct: 76.92,
        unscheduledGap: 30,
      },
    ]),
    getCrawlRun: vi.fn().mockResolvedValue({
      run: {
        runId: "crawl-9",
        phase: "completed",
        startedAt: "2026-03-30T12:00:00Z",
        lastCheckpointedAt: "2026-03-30T12:05:00Z",
        stopReason: "idle timeout",
        failureReason: null,
        scheduledTasks: 100,
        successfulHandshakes: 42,
        failedTasks: 58,
        uniqueNodes: 130,
        persistedObservationRows: 100,
        successPct: 42,
        scheduledPct: 76.92,
        unscheduledGap: 30,
      },
      checkpoints: [],
      failureCounts: [],
      networkOutcomes: [
        {
          networkType: "ipv4",
          observations: 90,
          verifiedNodes: 42,
          failedNodes: 48,
          verifiedPct: 46.67,
        },
        {
          networkType: "torv3",
          observations: 10,
          verifiedNodes: 1,
          failedNodes: 9,
          verifiedPct: 10,
        },
      ],
    }),
    countNodesByAsn: vi.fn().mockResolvedValue([
      {
        asn: 64512,
        asnOrganization: "Example ASN",
        verifiedNodes: 18,
      },
      {
        asn: 64513,
        asnOrganization: "Second ASN",
        verifiedNodes: 12,
      },
    ]),
    listLastRunServices: vi.fn().mockResolvedValue([]),
    listLastRunProtocolVersions: vi.fn().mockResolvedValue([]),
    listLastRunUserAgents: vi.fn().mockResolvedValue([]),
    listLastRunNetworkTypes: vi.fn().mockResolvedValue([]),
    listLastRunCountries: vi.fn().mockResolvedValue([]),
    listLastRunAsns: vi.fn().mockResolvedValue([]),
    listLastRunStartHeights: vi.fn().mockResolvedValue([]),
    listLastRunAsnOrganizations: vi.fn().mockResolvedValue([]),
    listLastRunNodes: vi.fn().mockResolvedValue([]),
    handshake: vi.fn(),
    ping: vi.fn(),
    getAddr: vi.fn(),
    getLastBlockHeight: vi.fn().mockResolvedValue({
      node: "seed.bitnodes.io:8333",
      height: 892345,
      rounds: 2,
      elapsedMs: 184,
      bestBlockHash: "0000000000000000000123456789abcdef0123456789abcdef0123456789abcd",
    }),
    getBlock: vi.fn(),
    downloadBlock: vi.fn(),
    getSuggestedBlockDownloadPath: vi.fn().mockResolvedValue("downloads/block.dat"),
    getRecentEvents: vi.fn().mockResolvedValue([]),
    ...overrides,
  };
}

describe("ApiPage", () => {
  it("renders a compact commercial overview driven by current analytics inputs", async () => {
    render(<ApiPage client={makeClient()} />);

    expect(await screen.findByText("API")).toBeTruthy();
    expect(
      screen.getByText(
        /Resilient Bitcoin network analytics for teams that need faster answers on concentration/i,
      ),
    ).toBeTruthy();
    expect(screen.getByText("Early access")).toBeTruthy();
    expect(screen.getByText("Launch posture")).toBeTruthy();
    expect(screen.getByText("Why teams buy this")).toBeTruthy();
    expect(screen.getByText("Treasury and Custody")).toBeTruthy();
    expect(await screen.findByText(/Example ASN/i)).toBeTruthy();
    expect(screen.queryByText("Example Snapshot Contract")).toBeNull();
  });

  it("switches between overview, access, and docs panels", async () => {
    render(<ApiPage client={makeClient()} />);

    expect(await screen.findByText("Why teams buy this")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Access" }));
    expect(await screen.findByText("Access Flow")).toBeTruthy();
    expect(screen.getByText("Subscription Shape")).toBeTruthy();
    expect(screen.getByText("Get an API key")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Docs" }));
    expect(await screen.findByText("Documentation Direction")).toBeTruthy();
    expect(screen.getByText("Embedded Scalar")).toBeTruthy();
    expect(screen.getByText("Live API Reference")).toBeTruthy();
    await waitFor(() => {
      expect(getDocsUiConfig).toHaveBeenCalledTimes(1);
    });
  });

  it("falls back to commercial framing when live analytics loading fails", async () => {
    const client = makeClient({
      listCrawlRuns: vi.fn().mockRejectedValue(new Error("api unavailable")),
    });

    render(<ApiPage client={client} />);

    expect(await screen.findByText("Live analytics are temporarily unavailable")).toBeTruthy();
    expect(screen.getByText("early-access")).toBeTruthy();
    expect(screen.getByText("Early access")).toBeTruthy();
  });
});
