import { LoaderCircle } from "lucide-react";
import type { FormEvent } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DataList } from "@/components/ui/data-list";
import { SectionHeading } from "@/components/ui/section-heading";
import { TextInput } from "@/components/ui/text-input";

import type { HandshakeResult, UiLogEvent } from "../lib/api/types";

export type ConnectionPageProps = {
  node: string;
  lastHandshake: HandshakeResult | null;
  events: UiLogEvent[];
  isRunning: boolean;
  onNodeChange: (value: string) => void;
  onHandshake: () => void | Promise<void>;
};

export function ConnectionPage({
  node,
  lastHandshake,
  events,
  isRunning,
  onNodeChange,
  onHandshake,
}: ConnectionPageProps) {
  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void onHandshake();
  }

  return (
    <Card>
      <CardContent className="space-y-8 p-6">
        <SectionHeading
          eyebrow="Session"
          title="Connection"
          description="Start each session by connecting to a peer and completing the Bitcoin handshake in the same order enforced by the Rust session layer."
          actions={<Badge>Handshake first</Badge>}
        />

        <form
          className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]"
          onSubmit={handleSubmit}
        >
          <TextInput
            id="node"
            name="node"
            value={node}
            onChange={(event) => onNodeChange(event.target.value)}
          />
          <Button type="submit" disabled={isRunning}>
            {isRunning ? <LoaderCircle className="h-4 w-4 animate-spin" /> : null}
            {isRunning ? "Handshaking..." : "Run Handshake"}
          </Button>
        </form>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
          <div className="space-y-4">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
              Peer Summary
            </p>
            {lastHandshake ? (
              <DataList
                items={[
                  { label: "Node", value: lastHandshake.node },
                  { label: "Protocol version", value: lastHandshake.protocolVersion },
                  { label: "Services", value: lastHandshake.services },
                  { label: "User agent", value: lastHandshake.userAgent },
                  { label: "Start height", value: lastHandshake.startHeight },
                ]}
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                {isRunning
                  ? "Waiting for the handshake summary from the Rust backend."
                  : "No handshake result yet."}
              </p>
            )}
          </div>

          <div className="space-y-4">
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-primary">
              Session Log
            </p>
            <div className="panel-scrollbar max-h-[30rem] overflow-y-auto rounded-[24px] border border-border/80 bg-background/80 p-4">
              <ul className="grid gap-3">
                {events.map((event) => (
                  <li
                    key={`${event.at}-${event.message}`}
                    className="rounded-2xl border border-border/70 bg-muted/40 px-4 py-3 text-sm"
                  >
                    <div className="mb-1 flex items-center gap-2">
                      <Badge variant={event.level === "info" ? "default" : "muted"}>
                        {event.level}
                      </Badge>
                      <span className="text-xs text-muted-foreground">{event.at}</span>
                    </div>
                    <p className="text-foreground">{event.message}</p>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
