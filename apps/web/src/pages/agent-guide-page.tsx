import { Check, Clipboard, ExternalLink, LoaderCircle, RotateCw } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { getAgentsGuideMarkdown, getAgentsGuideUrl } from "@/lib/api/docs-http";

export function AgentGuidePage() {
  const [markdown, setMarkdown] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const guideUrl = getAgentsGuideUrl();

  useEffect(() => {
    void refreshGuide();
  }, []);

  async function refreshGuide() {
    setIsLoading(true);
    setError(null);
    setCopied(false);

    try {
      setMarkdown(await getAgentsGuideMarkdown());
    } catch (nextError) {
      setMarkdown("");
      setError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setIsLoading(false);
    }
  }

  async function copyMarkdown() {
    await navigator.clipboard.writeText(markdown);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <Card>
      <CardContent className="space-y-5 p-3 sm:space-y-6 sm:p-6">
        <div className="flex flex-col gap-4 border-b border-border/80 pb-5 sm:flex-row sm:items-end sm:justify-between">
          <div className="space-y-2">
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.28em] text-primary">
              Agent Guide
            </p>
            <p className="max-w-3xl text-sm text-muted-foreground">
              Workflow-first Markdown for agents that need cheap API entry points, caching rules, and exact places to consult OpenAPI.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-9 w-9 px-0"
              aria-label="Refresh agent guide"
              title="Refresh agent guide"
              onClick={() => void refreshGuide()}
              disabled={isLoading}
            >
              {isLoading ? (
                <LoaderCircle className="h-4 w-4 animate-spin" />
              ) : (
                <RotateCw className="h-4 w-4" />
              )}
            </Button>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => void copyMarkdown()}
              disabled={!markdown}
            >
              {copied ? <Check className="h-4 w-4" /> : <Clipboard className="h-4 w-4" />}
              {copied ? "Copied" : "Copy markdown"}
            </Button>
            <a
              href={guideUrl}
              className="inline-flex h-9 items-center justify-center gap-2 rounded-[6px] border border-primary/25 bg-primary/10 px-4 text-[11px] font-semibold uppercase tracking-[0.18em] text-primary transition-colors hover:bg-primary/14"
            >
              <ExternalLink className="h-4 w-4" />
              Raw
            </a>
          </div>
        </div>

        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading agent guide markdown.</p>
        ) : error ? (
          <div className="rounded-[10px] border border-red-500/30 bg-background/70 p-4">
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-red-300">
              Guide unavailable
            </p>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              Could not load agents.md: {error}
            </p>
          </div>
        ) : (
          <pre className="panel-scrollbar max-h-[calc(100vh-13rem)] overflow-auto rounded-[12px] border border-border/80 bg-background/78 p-4 text-[12px] leading-6 text-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
            <code>{markdown}</code>
          </pre>
        )}
      </CardContent>
    </Card>
  );
}
