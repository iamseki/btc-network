// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BtcAppClient } from "@/lib/api/client";
import { getDocsUiConfig, getOpenApiDocument } from "@/lib/api/docs-http";

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
  getOpenApiDocument: vi.fn().mockResolvedValue({
    openapi: "3.1.0",
    info: { title: "btc-network API", version: "0.1.0" },
    paths: {},
  }),
}));

vi.mock("@scalar/api-reference-react", () => ({
  ApiReferenceReact: ({ configuration }: { configuration: { content?: { openapi?: string } } }) => (
    <div data-testid="scalar-api-reference">{configuration.content?.openapi}</div>
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
    listNodeStatus: vi.fn().mockResolvedValue([]),
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
  it("opens on docs first and loads the embedded reference config", async () => {
    render(<ApiPage client={makeClient()} />);

    await waitFor(() => {
      expect(getDocsUiConfig).toHaveBeenCalledTimes(1);
      expect(getOpenApiDocument).toHaveBeenCalledWith("/api/openapi.json");
    });
    expect((await screen.findByTestId("scalar-api-reference")).textContent).toContain("3.1.0");
    expect(screen.queryByText("Loading generated API reference.")).toBeNull();
  });

  it("renders a compact commercial overview driven by current analytics inputs", async () => {
    render(<ApiPage client={makeClient()} activePanel="overview" />);

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

  it("renders overview and access panels outside the docs-only surface", async () => {
    render(<ApiPage client={makeClient()} activePanel="overview" />);

    expect(await screen.findByText("Why teams buy this")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Docs" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Overview" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Access" })).toBeTruthy();

    cleanup();
    render(<ApiPage client={makeClient()} activePanel="access" />);

    expect(await screen.findByText("Access Flow")).toBeTruthy();
    expect(screen.getByText("Subscription Shape")).toBeTruthy();
    expect(screen.getByText("Get an API key")).toBeTruthy();
  });

  it("falls back to commercial framing when live analytics loading fails", async () => {
    const client = makeClient({
      listCrawlRuns: vi.fn().mockRejectedValue(new Error("api unavailable")),
    });

    render(<ApiPage client={client} activePanel="overview" />);

    expect(await screen.findByText("Live analytics are temporarily unavailable")).toBeTruthy();
    expect(screen.getByText("early-access")).toBeTruthy();
  });
});
