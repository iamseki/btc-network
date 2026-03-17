// @vitest-environment jsdom

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SessionLogPanel } from "./session-log-panel";

describe("SessionLogPanel", () => {
  it("keeps long summary and event content wrapped for narrow layouts", () => {
    const events = [
      {
        at: "2026-03-17T20:35:32.123456789Z",
        level: "warn" as const,
        message:
          "Long session log message for narrow layouts should wrap instead of colliding with badges or metadata in the header area.",
      },
    ];

    const { container } = render(
      <SessionLogPanel events={events} isOpen onToggle={vi.fn()} onClear={vi.fn()} />,
    );

    const summaryTrigger = container.querySelector('button[aria-controls="session-log-panel"]');
    expect(summaryTrigger).not.toBeNull();

    const summaryMessage = summaryTrigger?.querySelector("p.break-words");
    expect(summaryMessage).toBeNull();

    const truncatedSummaryMessage = summaryTrigger?.querySelector("p.truncate");
    expect(truncatedSummaryMessage).not.toBeNull();
    expect(truncatedSummaryMessage?.className).toContain("truncate");

    const timestamp = screen.getByText(events[0].at);
    expect(timestamp.className).toContain("break-all");

    const eventMessage = container.querySelector("#session-log-panel li p");
    expect(eventMessage).not.toBeNull();
    expect(eventMessage?.className).toContain("break-words");
  });
});
