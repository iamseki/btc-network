import { describe, expect, it } from "vitest";

import { appPages } from "./page-registry";

describe("appPages", () => {
  it("lists the current CLI-aligned pages in order", () => {
    expect(appPages.map((page) => page.id)).toEqual([
      "connection",
      "peer-tools",
      "headers",
      "blocks",
    ]);
  });

  it("provides titles and descriptions for navigation", () => {
    for (const page of appPages) {
      expect(page.title.length).toBeGreaterThan(0);
      expect(page.description.length).toBeGreaterThan(0);
    }
  });
});
