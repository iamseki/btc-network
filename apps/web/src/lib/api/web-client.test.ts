import { describe, expect, it } from "vitest";

import { webClient } from "./web-client";

describe("webClient", () => {
  it("returns a placeholder handshake response", async () => {
    const result = await webClient.handshake({ node: "seed.bitcoin.sipa.be:8333" });

    expect(result.node).toBe("seed.bitcoin.sipa.be:8333");
    expect(result.protocolVersion).toBe(70016);
  });

  it("derives the default output filename for block downloads", async () => {
    const hash =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const result = await webClient.downloadBlock("node", hash);

    expect(result.outputPath).toBe("blk-00000000-8ce26f.dat");
  });
});
