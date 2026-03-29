"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";
import type { SyslogEntry } from "@/types/syslog";

export const LOG_ROW_HEIGHT = 36;

const SEVERITY_COLORS: Record<string, string> = {
  emergency: "text-red-500 bg-red-500/10",
  alert: "text-red-400 bg-red-400/10",
  critical: "text-red-400 bg-red-400/10",
  error: "text-orange-400 bg-orange-400/10",
  warning: "text-amber-400 bg-amber-400/10",
  notice: "text-blue-400 bg-blue-400/10",
  info: "text-sky-400 bg-sky-400/10",
  debug: "text-gray-400 bg-gray-400/10",
};

export function LogRow({
  log,
  isExpanded,
  onToggle,
  showDate,
}: {
  log: SyslogEntry;
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

  const sevClass = SEVERITY_COLORS[log.severity] || "text-muted-foreground";

  return (
    <div
      className="group flex items-start border-b border-border/30 hover:bg-muted/40 cursor-pointer font-mono text-[13px] transition-colors"
      style={{ minHeight: LOG_ROW_HEIGHT }}
      onClick={onToggle}
    >
      <div className="px-3 py-2 text-muted-foreground/70 whitespace-nowrap w-[140px] shrink-0 tabular-nums">
        {ts}
      </div>
      <div className="px-3 py-2 w-[80px] shrink-0">
        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold ${sevClass}`}>
          {log.severity}
        </span>
      </div>
      <div className="px-3 py-2 text-violet-400/80 w-[140px] shrink-0 truncate" title={log.host}>
        {log.host}
      </div>
      <div className="px-3 py-2 text-sky-400/70 w-[100px] shrink-0 truncate" title={log.facility}>
        {log.facility}
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
          <span className="truncate block text-foreground/80 group-hover:text-foreground/90 transition-colors">
            {log.message}
          </span>
        )}
      </div>
    </div>
  );
}

export const ALL_LOG_COLUMNS = [
  { label: "Time", width: "w-[140px]" },
  { label: "Severity", width: "w-[80px]" },
  { label: "Host", width: "w-[140px]" },
  { label: "Facility", width: "w-[100px]" },
  { label: "Message", width: "flex-1" },
];
