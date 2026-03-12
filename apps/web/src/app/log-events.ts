import type { UiLogEvent } from "@/lib/api/types";

export const MAX_UI_LOG_EVENTS = 100;

export function prependLogEvent(
  current: UiLogEvent[],
  next: UiLogEvent,
  limit = MAX_UI_LOG_EVENTS,
): UiLogEvent[] {
  return [next, ...current].slice(0, limit);
}
