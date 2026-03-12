import type { BtcAppClient } from "./client";
import { tauriClient } from "./tauri-client";
import { webClient } from "./web-client";

function isTauriRuntime(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  return "__TAURI_INTERNALS__" in (window as unknown as Record<string, unknown>);
}

export function getAppClient(): BtcAppClient {
  return isTauriRuntime() ? tauriClient : webClient;
}
