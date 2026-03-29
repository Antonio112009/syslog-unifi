"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";
import type { SyslogEntry, ParsedFirewall } from "@/types/syslog";

const ROW_HEIGHT = 36;

const ACTION_COLORS: Record<string, string> = {
  Allow: "text-emerald-400",
  Drop: "text-red-400",
  Reject: "text-amber-400",
};

const ACTION_BG: Record<string, string> = {
  Allow: "bg-emerald-500/10",
  Drop: "bg-red-500/10",
  Reject: "bg-amber-500/10",
};

export { ROW_HEIGHT };

export function FirewallRow({
  log,
  fw,
  isExpanded,
  onToggle,
  showDate,
}: {
  log: SyslogEntry;
  fw: ParsedFirewall;
  isExpanded: boolean;
  onToggle: () => void;
  showDate?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(log.raw);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const ts = showDate
    ? log.timestamp.replace("T", " ").slice(0, 19)
    : log.timestamp.slice(11, 19);

  const timeWidth = showDate ? "w-[148px]" : "w-[88px]";

  return (
    <div
      className="group flex items-start border-b border-border/30 hover:bg-muted/40 cursor-pointer font-mono text-[13px] transition-colors"
      style={{ minHeight: ROW_HEIGHT }}
      onClick={onToggle}
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
      <div className="px-3 py-2 flex-1 min-w-0">
        {isExpanded ? (
          <div className="space-y-2">
            <pre className="whitespace-pre-wrap break-all text-xs text-muted-foreground/70 leading-relaxed">
              {log.raw}
            </pre>
            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded border border-border/50 hover:bg-muted/50"
            >
              {copied ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
              {copied ? "Copied" : "Copy raw"}
            </button>
          </div>
        ) : (
          <span className="truncate block text-muted-foreground/50 group-hover:text-muted-foreground/70 transition-colors">
            {fw.rule}
          </span>
        )}
      </div>
    </div>
  );
}
