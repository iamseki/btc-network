import type { BlockDownloadResult, BlockSummary } from "../lib/api/types";

export type BlocksPageProps = {
  node: string;
  blockHash: string;
  blockSummary: BlockSummary | null;
  downloadResult: BlockDownloadResult | null;
};

export function BlocksPage({
  node,
  blockHash,
  blockSummary,
  downloadResult,
}: BlocksPageProps) {
  return (
    <section>
      <header>
        <h1>Block Explorer</h1>
        <p>Request a block by hash or write a raw `blk*.dat` record from the network payload.</p>
      </header>

      <form>
        <label htmlFor="block-hash">Block hash</label>
        <input id="block-hash" name="block-hash" defaultValue={blockHash} />
        <button type="submit">GetBlock {node}</button>
        <button type="button">DownloadBlock {node}</button>
      </form>

      <section>
        <h2>Block Summary</h2>
        {blockSummary ? (
          <dl>
            <div>
              <dt>Hash</dt>
              <dd>{blockSummary.hash}</dd>
            </div>
            <div>
              <dt>Transactions</dt>
              <dd>{blockSummary.txCount}</dd>
            </div>
            <div>
              <dt>Serialized size</dt>
              <dd>{blockSummary.serializedSize}</dd>
            </div>
            <div>
              <dt>Coinbase detected</dt>
              <dd>{blockSummary.coinbaseTxDetected ? "yes" : "no"}</dd>
            </div>
          </dl>
        ) : (
          <p>No block loaded yet.</p>
        )}
      </section>

      <section>
        <h2>Download Result</h2>
        {downloadResult ? (
          <dl>
            <div>
              <dt>Output path</dt>
              <dd>{downloadResult.outputPath}</dd>
            </div>
            <div>
              <dt>Raw bytes</dt>
              <dd>{downloadResult.rawBytes}</dd>
            </div>
          </dl>
        ) : (
          <p>No block downloaded yet.</p>
        )}
      </section>
    </section>
  );
}
