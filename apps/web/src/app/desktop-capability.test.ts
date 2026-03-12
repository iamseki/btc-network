import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const capabilityPath = new URL("../../../desktop/src-tauri/capabilities/default.json", import.meta.url);

describe("desktop capability", () => {
  it("allows the local Vite dev origins used by tauri dev", () => {
    const capability = JSON.parse(readFileSync(capabilityPath, "utf8")) as {
      remote?: { urls?: string[] };
      permissions: string[];
    };

    expect(capability.permissions).toContain("default");
    expect(capability.remote?.urls).toEqual(
      expect.arrayContaining(["http://localhost:5173", "http://127.0.0.1:5173"]),
    );
  });
});
