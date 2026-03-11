import type { HeaderFetchResult, HeaderSyncResult } from "../lib/api/types";

export type HeadersPageProps = {
  node: string;
  headersResult: HeaderFetchResult | null;
  syncResult: HeaderSyncResult | null;
};

export function HeadersPage({
  node,
  headersResult,
  syncResult,
}: HeadersPageProps) {
  return (
    <section>
      <header>
        <h1>Headers</h1>
        <p>Inspect the one-shot header response or run the iterative sync-to-tip workflow.</p>
      </header>

      <div>
        <button type="button">GetHeaders {node}</button>
        <button type="button">Sync To Tip {node}</button>
      </div>

      <section>
        <h2>Latest GetHeaders Result</h2>
        {headersResult ? (
          <dl>
            <div>
              <dt>Count</dt>
              <dd>{headersResult.count}</dd>
            </div>
            <div>
              <dt>Last header hash</dt>
              <dd>{headersResult.lastHeaderHash ?? "n/a"}</dd>
            </div>
          </dl>
        ) : (
          <p>No header batch fetched yet.</p>
        )}
      </section>

      <section>
        <h2>Sync Summary</h2>
        {syncResult ? (
          <dl>
            <div>
              <dt>Total headers</dt>
              <dd>{syncResult.totalHeaders}</dd>
            </div>
            <div>
              <dt>Rounds</dt>
              <dd>{syncResult.rounds}</dd>
            </div>
            <div>
              <dt>Elapsed (ms)</dt>
              <dd>{syncResult.elapsedMs}</dd>
            </div>
            <div>
              <dt>Most recent block</dt>
              <dd>{syncResult.mostRecentBlock ?? "n/a"}</dd>
            </div>
          </dl>
        ) : (
          <p>No tip sync has been run yet.</p>
        )}
      </section>
    </section>
  );
}
