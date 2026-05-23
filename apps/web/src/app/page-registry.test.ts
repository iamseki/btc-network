import { describe, expect, it } from "vitest";

import { appPages } from "./page-registry";

describe("appPages", () => {
  it("lists analytics-first pages before the existing peer tools", () => {
    expect(appPages.map((page) => page.id)).toEqual([
      "network-analytics",
      "risk",
      "api",
      "status",
      "crawler-runs",
      "connection",
      "peer-tools",
      "headers",
      "blocks",
    ]);
  });

  it("provides titles, descriptions, and groups for navigation", () => {
    for (const page of appPages) {
      expect(page.title.length).toBeGreaterThan(0);
      expect(page.description.length).toBeGreaterThan(0);
      expect(page.group.length).toBeGreaterThan(0);
    }
  });

  it("keeps status and crawler runs out of the primary sidebar", () => {
    const hiddenPages = appPages
      .filter((page) => page.showInSidebar === false)
      .map((page) => page.id);

    expect(hiddenPages).toEqual(["status", "crawler-runs"]);
  });
});
