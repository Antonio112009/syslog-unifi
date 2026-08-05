"use client";

import { LogDetails } from "@/components/log-details";
import type { SyslogEntry, ParsedFirewall } from "@/types/syslog";

const ROW_HEIGHT = 36;

const ACTION_COLORS: Record<string, string> = {
  Allow: "text-emerald-400",
  Drop: "text-red-400",
  Reject: "text-amber-400",
  Alert: "text-amber-400",
};

const ACTION_BG: Record<string, string> = {
  Allow: "bg-emerald-500/10",
  Drop: "bg-red-500/10",
  Reject: "bg-amber-500/10",
  Alert: "bg-amber-500/10",
};

export { ROW_HEIGHT };

export function FirewallRow({
  log,
  fw,
  isExpanded,
  onToggle,
  showDate,
  index = 0,
}: {
  log: SyslogEntry;
  fw: ParsedFirewall;
  isExpanded: boolean;
  onToggle: () => void;
  showDate?: boolean;
  index?: number;
}) {
  const ts = showDate
    ? log.timestamp.replace("T", " ").slice(0, 19)
    : log.timestamp.slice(11, 19);

  const timeWidth = showDate ? "w-[180px]" : "w-[88px]";

  return (
    <div
      className="group border-b border-border/30 font-mono text-[13px] font-medium"
      style={{ minHeight: ROW_HEIGHT, backgroundColor: index % 2 === 1 ? "var(--row-stripe)" : undefined }}
    >
      <div
        className="flex cursor-pointer items-start transition-colors hover:bg-muted/45 focus-visible:bg-muted/45 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
        role="button"
        tabIndex={0}
        aria-expanded={isExpanded}
        aria-label={`${isExpanded ? "Collapse" : "Inspect"} ${fw.action} firewall event from ${fw.src}`}
        onClick={onToggle}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onToggle();
          }
        }}
      >
        <div className={`px-3 py-2 text-muted-foreground/70 whitespace-nowrap ${timeWidth} shrink-0 tabular-nums`}>
          {ts}
        </div>
        <div className={`px-3 py-2 w-[76px] shrink-0 font-semibold ${ACTION_COLORS[fw.action] || "text-foreground"}`}>
          <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs ${ACTION_BG[fw.action] || ""}`}>
            {fw.action}
          </span>
        </div>
        <div className="px-3 py-2 text-sky-400 w-64 shrink-0 truncate" title={fw.rule}>
          {fw.descr || fw.rule}
        </div>
        <div className="px-3 py-2 text-violet-400/80 w-20 shrink-0">{fw.iface}</div>
        <div className="px-3 py-2 text-blue-300/80 w-16 shrink-0 uppercase">{fw.proto}</div>
        <div className="px-3 py-2 w-48 shrink-0 truncate" title={`${fw.src}:${fw.spt}`}>
          <span className="text-foreground/90">{fw.src}</span>
          <span className="text-muted-foreground/60">{fw.spt ? `:${fw.spt}` : ""}</span>
        </div>
        <div className="px-3 py-2 w-48 shrink-0 truncate" title={`${fw.dst}:${fw.dpt}`}>
          <span className="text-foreground/90">{fw.dst}</span>
          <span className="text-muted-foreground/60">{fw.dpt ? `:${fw.dpt}` : ""}</span>
        </div>
        <div className="px-3 py-2 flex-1 min-w-0 overflow-hidden">
          <span className="truncate block text-muted-foreground/50 group-hover:text-muted-foreground/70 transition-colors">
            {fw.rule}
          </span>
        </div>
      </div>
      {isExpanded && <LogDetails log={log} firewall={fw} />}
    </div>
  );
}
