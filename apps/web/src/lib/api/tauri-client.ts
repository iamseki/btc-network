import type { BtcAppClient } from "./client";

function unimplemented(name: string): never {
  throw new Error(`Tauri adapter not implemented yet: ${name}`);
}

export const tauriClient: BtcAppClient = {
  handshake() {
    return Promise.reject(unimplemented("handshake"));
  },
  ping() {
    return Promise.reject(unimplemented("ping"));
  },
  getAddr() {
    return Promise.reject(unimplemented("getAddr"));
  },
  getHeaders() {
    return Promise.reject(unimplemented("getHeaders"));
  },
  syncHeadersToTip() {
    return Promise.reject(unimplemented("syncHeadersToTip"));
  },
  getBlock() {
    return Promise.reject(unimplemented("getBlock"));
  },
  downloadBlock() {
    return Promise.reject(unimplemented("downloadBlock"));
  },
  getRecentEvents() {
    return Promise.reject(unimplemented("getRecentEvents"));
  },
};
