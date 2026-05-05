// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AgentGuidePage } from "./agent-guide-page";

const { mockGetAgentsGuideMarkdown } = vi.hoisted(() => ({
  mockGetAgentsGuideMarkdown: vi.fn(),
}));

vi.mock("@/lib/api/docs-http", () => ({
  getAgentsGuideMarkdown: mockGetAgentsGuideMarkdown,
  getAgentsGuideUrl: () => "http://127.0.0.1:8080/agents.md",
}));

afterEach(() => {
  cleanup();
  mockGetAgentsGuideMarkdown.mockReset();
  vi.unstubAllGlobals();
});

describe("AgentGuidePage", () => {
  it("renders markdown and copies it", async () => {
    const markdown = "# btc-network Agent Guide\n\nUse OpenAPI.";
    const writeText = vi.fn().mockResolvedValue(undefined);
    mockGetAgentsGuideMarkdown.mockResolvedValue(markdown);
    vi.stubGlobal("navigator", {
      clipboard: { writeText },
    });

    render(<AgentGuidePage />);

    expect(await screen.findByText(/Use OpenAPI/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Copy markdown" }));

    expect(writeText).toHaveBeenCalledWith(markdown);
    expect(await screen.findByRole("button", { name: "Copied" })).toBeTruthy();
  });

  it("shows an error when the guide cannot load", async () => {
    mockGetAgentsGuideMarkdown.mockRejectedValue(new Error("offline"));

    render(<AgentGuidePage />);

    expect(await screen.findByText("Could not load agents.md: offline")).toBeTruthy();
  });
});
