import { describe, expect, it } from "vitest";

import { getAppClient } from "./index";
import { tauriClient } from "./tauri-client";
import { webClient } from "./web-client";

describe("getAppClient", () => {
  it("uses the web client outside Tauri", () => {
    delete (globalThis as Record<string, unknown>).window;

    expect(getAppClient()).toBe(webClient);
  });

  it("uses the tauri client when the Tauri runtime marker is present", () => {
    (globalThis as Record<string, unknown>).window = {
      __TAURI_INTERNALS__: {},
    };

    expect(getAppClient()).toBe(tauriClient);
  });
});
