import type { BtcAppClient } from "./client";
import { webClient } from "./web-client";

export function getAppClient(): BtcAppClient {
  return webClient;
}
