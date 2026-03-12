import type { BtcAppClient } from "./client";
import type {
  ConnectionRequest,
  HandshakeResult,
  PingResult,
  UiLogEvent,
} from "./types";

async function invoke<T>(
  command: string,
  payload: Record<string, unknown>,
): Promise<T> {
  const mod = await import("@tauri-apps/api/core");
  return mod.invoke<T>(command, payload);
}

export const tauriClient: BtcAppClient = {
  handshake(request: ConnectionRequest): Promise<HandshakeResult> {
    return invoke<HandshakeResult>("handshake", { request });
  },
  ping(node: string): Promise<PingResult> {
    return invoke<PingResult>("ping", { request: { node } });
  },
  getAddr() {
    return Promise.reject(new Error("Tauri adapter not implemented yet: getAddr"));
  },
  getHeaders() {
    return Promise.reject(new Error("Tauri adapter not implemented yet: getHeaders"));
  },
  syncHeadersToTip() {
    return Promise.reject(new Error("Tauri adapter not implemented yet: syncHeadersToTip"));
  },
  getBlock() {
    return Promise.reject(new Error("Tauri adapter not implemented yet: getBlock"));
  },
  downloadBlock() {
    return Promise.reject(new Error("Tauri adapter not implemented yet: downloadBlock"));
  },
  getRecentEvents(): Promise<UiLogEvent[]> {
    return Promise.resolve([]);
  },
};
