import type { HandshakeResult, UiLogEvent } from "../lib/api/types";

export type ConnectionPageProps = {
  defaultNode: string;
  lastHandshake: HandshakeResult | null;
  events: UiLogEvent[];
};

export function ConnectionPage({
  defaultNode,
  lastHandshake,
  events,
}: ConnectionPageProps) {
  return (
    <section>
      <header>
        <h1>Connection</h1>
        <p>Start each session by connecting to a peer and completing the Bitcoin handshake.</p>
      </header>

      <form>
        <label htmlFor="node">Peer node</label>
        <input id="node" name="node" defaultValue={defaultNode} />
        <button type="submit">Handshake</button>
      </form>

      <section>
        <h2>Peer Summary</h2>
        {lastHandshake ? (
          <dl>
            <div>
              <dt>Node</dt>
              <dd>{lastHandshake.node}</dd>
            </div>
            <div>
              <dt>Protocol version</dt>
              <dd>{lastHandshake.protocolVersion}</dd>
            </div>
            <div>
              <dt>Services</dt>
              <dd>{lastHandshake.services}</dd>
            </div>
            <div>
              <dt>User agent</dt>
              <dd>{lastHandshake.userAgent}</dd>
            </div>
            <div>
              <dt>Start height</dt>
              <dd>{lastHandshake.startHeight}</dd>
            </div>
          </dl>
        ) : (
          <p>No handshake result yet.</p>
        )}
      </section>

      <section>
        <h2>Session Log</h2>
        <ul>
          {events.map((event) => (
            <li key={`${event.at}-${event.message}`}>
              <strong>{event.level}</strong> {event.at} {event.message}
            </li>
          ))}
        </ul>
      </section>
    </section>
  );
}
