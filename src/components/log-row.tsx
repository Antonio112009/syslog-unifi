"use client";

import { useMemo } from "react";
import { LogDetails } from "@/components/log-details";
import { parseCefMessage } from "@/lib/firewall-parser";
import type { SyslogEntry } from "@/types/syslog";

export const LOG_ROW_HEIGHT = 36;

// Kiwi-style bold filled badges — high contrast bg with readable text
const SEVERITY_BADGE_STYLES: Record<string, string> = {
  emergency: "bg-red-700 text-white",
  alert:     "bg-orange-600 text-white",
  critical:  "bg-red-600 text-white",
  error:     "bg-rose-600 text-white",
  warning:   "bg-amber-600 text-white",
  notice:    "bg-sky-600 text-white",
  info:      "bg-blue-600 text-white",
  debug:     "bg-zinc-600 text-white",
};

const DEFAULT_BADGE = "bg-muted text-muted-foreground";

// Subtle row background tints for "row" color mode
const SEVERITY_ROW_BG: Record<string, string> = {
  emergency: "rgba(220, 38, 38, 0.12)",
  alert:     "rgba(249, 115, 22, 0.10)",
  critical:  "rgba(239, 68, 68, 0.10)",
  error:     "rgba(244, 63, 94, 0.08)",
  warning:   "rgba(245, 158, 11, 0.08)",
  notice:    "rgba(14, 165, 233, 0.06)",
  info:      "rgba(59, 130, 246, 0.05)",
  debug:     "rgba(113, 113, 122, 0.05)",
};


export function LogRow({
  log,
  isExpanded,
  onToggle,
  showDate,
  colorMode = "badge",
  index = 0,
}: {
  log: SyslogEntry;
  isExpanded: boolean;
  onToggle: () => void;
  showDate?: boolean;
  colorMode?: "badge" | "row";
  index?: number;
}) {
  const ts = showDate
    ? log.timestamp.replace("T", " ").slice(0, 19)
    : log.timestamp.slice(11, 19);
  const cef = useMemo(
    () => parseCefMessage(log.raw) || parseCefMessage(log.message),
    [log.message, log.raw]
  );
  const displayMessage = cef
    ? [cef.eventName, cef.fields.msg].filter(Boolean).join(" · ")
    : log.message;

  const badgeClass = SEVERITY_BADGE_STYLES[log.severity] || DEFAULT_BADGE;
  const rowBg = colorMode === "row"
    ? SEVERITY_ROW_BG[log.severity]
    : index % 2 === 1
      ? "var(--row-stripe)"
      : undefined;

  return (
    <div
      className="group border-b border-border/30 font-mono text-[13px] font-medium"
      style={{ minHeight: LOG_ROW_HEIGHT, backgroundColor: rowBg }}
    >
      <div
        className="flex cursor-pointer items-start transition-colors hover:bg-muted/45 focus-visible:bg-muted/45 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
        role="button"
        tabIndex={0}
        aria-expanded={isExpanded}
        aria-label={`${isExpanded ? "Collapse" : "Inspect"} ${log.severity} log from ${log.host}`}
        onClick={onToggle}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onToggle();
          }
        }}
      >
        <div className="px-3 py-2 text-muted-foreground/70 whitespace-nowrap w-[180px] shrink-0 tabular-nums">
          {ts}
        </div>
        <div className="px-3 py-2 w-[90px] shrink-0">
          <span
            className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-bold uppercase tracking-wide ${badgeClass}`}
          >
            {log.severity}
          </span>
        </div>
        <div
          className="px-3 py-2 text-violet-400/80 w-[140px] shrink-0 truncate"
          title={log.host}
        >
          {log.host}
        </div>
        <div
          className="px-3 py-2 text-sky-400/70 w-[100px] shrink-0 truncate"
          title={log.facility}
        >
          {log.facility}
        </div>
        <div className="px-3 py-2 flex-1 min-w-0 overflow-hidden">
          <span className="truncate block text-foreground/80 group-hover:text-foreground/90 transition-colors">
            {displayMessage}
          </span>
        </div>
      </div>
      {isExpanded && <LogDetails log={log} />}
    </div>
  );
}

export const ALL_LOG_COLUMNS = [
  { label: "Time", width: "w-[180px]" },
  { label: "Level", width: "w-[90px]" },
  { label: "Host", width: "w-[140px]" },
  { label: "Facility", width: "w-[100px]" },
  { label: "Message", width: "flex-1" },
];
