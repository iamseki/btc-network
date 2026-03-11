import type { AddrResult, PingResult } from "../lib/api/types";

export type PeerToolsPageProps = {
  node: string;
  lastPing: PingResult | null;
  lastAddrResult: AddrResult | null;
};

export function PeerToolsPage({
  node,
  lastPing,
  lastAddrResult,
}: PeerToolsPageProps) {
  return (
    <section>
      <header>
        <h1>Peer Tools</h1>
        <p>Run the current single-peer diagnostic flows implemented by the CLI.</p>
      </header>

      <div>
        <button type="button">Ping {node}</button>
        <button type="button">GetAddr {node}</button>
      </div>

      <section>
        <h2>Ping</h2>
        {lastPing ? (
          <dl>
            <div>
              <dt>Nonce</dt>
              <dd>{lastPing.nonce}</dd>
            </div>
            <div>
              <dt>Echoed nonce</dt>
              <dd>{lastPing.echoedNonce}</dd>
            </div>
          </dl>
        ) : (
          <p>No ping sent yet.</p>
        )}
      </section>

      <section>
        <h2>Addresses</h2>
        {lastAddrResult ? (
          <table>
            <thead>
              <tr>
                <th>Network</th>
                <th>Address</th>
                <th>Port</th>
              </tr>
            </thead>
            <tbody>
              {lastAddrResult.addresses.map((entry) => (
                <tr key={`${entry.network}-${entry.address}-${entry.port}`}>
                  <td>{entry.network}</td>
                  <td>{entry.address}</td>
                  <td>{entry.port}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No address result yet.</p>
        )}
      </section>
    </section>
  );
}
