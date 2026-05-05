import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

describe("sidebar scrollbar styling", () => {
  it("hides horizontal sidebar overflow artifacts while keeping overflow available for tooltips", () => {
    const styles = readFileSync(new URL("../../styles.css", import.meta.url), "utf8");

    expect(styles).toContain(".sidebar-scrollbar::-webkit-scrollbar:horizontal");
    expect(styles).toContain("height: 0");
    expect(styles).toContain(".sidebar-scrollbar");
    expect(styles).toContain("scrollbar-width: none");
  });
});
