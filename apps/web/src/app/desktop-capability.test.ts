import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const capabilityPath = new URL("../../../desktop/src-tauri/capabilities/default.json", import.meta.url);

describe("desktop capability", () => {
  it("allows the local Vite dev origins used by tauri dev", () => {
    const capability = JSON.parse(readFileSync(capabilityPath, "utf8")) as {
      remote?: { urls?: string[] };
      windows?: string[];
      permissions: string[];
    };

    expect([...capability.permissions].sort()).toEqual(
      ["allow-handshake", "allow-ping", "core:default"].sort(),
    );
    expect(capability.windows).toEqual(["*"]);
    expect([...((capability.remote?.urls ?? []) as string[])].sort()).toEqual(
      ["http://127.0.0.1:*", "http://localhost:*"].sort(),
    );
  });
});
