import { describe, expect, it } from "vitest";

import { MAX_UI_LOG_EVENTS, prependLogEvent } from "./log-events";

describe("prependLogEvent", () => {
  it("adds new events to the front of the log", () => {
    const result = prependLogEvent(
      [{ at: "older", level: "info", message: "older" }],
      { at: "newer", level: "info", message: "newer" },
    );

    expect(result.map((event) => event.message)).toEqual(["newer", "older"]);
  });

  it("caps the session log to the configured size", () => {
    const current = Array.from({ length: MAX_UI_LOG_EVENTS }, (_, index) => ({
      at: `${index}`,
      level: "info" as const,
      message: `event-${index}`,
    }));

    const result = prependLogEvent(current, {
      at: "next",
      level: "warn",
      message: "next-event",
    });

    expect(result).toHaveLength(MAX_UI_LOG_EVENTS);
    expect(result[0]?.message).toBe("next-event");
    expect(result.at(-1)?.message).toBe(`event-${MAX_UI_LOG_EVENTS - 2}`);
  });
});
