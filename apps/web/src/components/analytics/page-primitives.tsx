import { Button } from "@/components/ui/button";

export function AnalyticsPanelButton({
  label,
  selected,
  onClick,
}: {
  label: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <Button type="button" variant={selected ? "default" : "secondary"} size="sm" onClick={onClick}>
      {label}
    </Button>
  );
}

export function AnalyticsHeaderStat({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <div className="min-w-[8rem] rounded-[8px] border border-border/70 bg-background/75 px-2.5 py-2 text-left sm:min-w-[8.75rem]">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 break-all font-mono text-[13px] text-foreground">{value}</p>
      <p className="mt-1 truncate text-[11px] text-muted-foreground">{detail}</p>
    </div>
  );
}
