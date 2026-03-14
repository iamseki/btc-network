// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BlocksPage } from "./blocks-page";

afterEach(() => {
  cleanup();
});

describe("BlocksPage", () => {
  it("submits the fetch action from the block form", () => {
    const onGetBlock = vi.fn();

    render(
      <BlocksPage
        node="seed.bitcoin.sipa.be:8333"
        blockHash="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        blockSummary={null}
        downloadResult={null}
        onGetBlock={onGetBlock}
      />,
    );

    fireEvent.submit(screen.getByRole("button", { name: /Fetch Block/i }).closest("form")!);

    expect(onGetBlock).toHaveBeenCalledTimes(1);
  });

  it("triggers the download action independently", () => {
    const onDownloadBlock = vi.fn();

    render(
      <BlocksPage
        node="seed.bitcoin.sipa.be:8333"
        blockHash="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        blockSummary={null}
        downloadResult={null}
        onDownloadBlock={onDownloadBlock}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Download Block/i }));

    expect(onDownloadBlock).toHaveBeenCalledTimes(1);
  });
});
