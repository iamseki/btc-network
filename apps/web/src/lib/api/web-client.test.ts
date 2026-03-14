import { describe, expect, it } from "vitest";

import { webClient } from "./web-client";

describe("webClient", () => {
  it("returns a placeholder handshake response", async () => {
    const result = await webClient.handshake({ node: "seed.bitcoin.sipa.be:8333" });

    expect(result.node).toBe("seed.bitcoin.sipa.be:8333");
    expect(result.protocolVersion).toBe(70016);
  });

  it("returns placeholder peer addresses", async () => {
    const result = await webClient.getAddr("seed.bitcoin.sipa.be:8333");

    expect(result.node).toBe("seed.bitcoin.sipa.be:8333");
    expect(result.addresses).toEqual([
      { address: "127.0.0.1", port: 8333, network: "ipv4" },
      { address: "::1", port: 8333, network: "ipv6" },
    ]);
  });

  it("returns a placeholder last block height summary", async () => {
    const result = await webClient.getLastBlockHeight("seed.bitcoin.sipa.be:8333");

    expect(result.height).toBe(938408);
    expect(result.bestBlockHash).toBe(
      "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde",
    );
    expect(result.rounds).toBeGreaterThan(0);
  });

  it("returns a placeholder block summary for the requested hash", async () => {
    const hash =
      "00000000000000000000772e80a1e5c0df1bc935b5f5c2cad5533234e068afde";
    const result = await webClient.getBlock("seed.bitcoin.sipa.be:8333", hash);

    expect(result.hash).toBe(hash);
    expect(result.txCount).toBe(1);
    expect(result.coinbaseTxDetected).toBe(true);
  });

  it("derives the default output filename for block downloads", async () => {
    const hash =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const result = await webClient.downloadBlock("node", hash);

    expect(result.outputPath).toBe("blk-00000000-8ce26f.dat");
  });
});
