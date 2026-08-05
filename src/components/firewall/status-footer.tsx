"use client";

import { Play, Pause, Square } from "lucide-react";
import { cn } from "@/lib/utils";
import type { StreamState } from "@/types/syslog";

const STATE_CONFIG: Record<
  StreamState,
  { label: string; icon: typeof Play; className: string }
> = {
  running: {
    label: "Live updates",
    icon: Play,
    className: "text-status-online",
  },
  paused: {
    label: "Updates paused",
    icon: Pause,
    className: "text-status-paused",
  },
  stopped: {
    label: "Updates stopped",
    icon: Square,
    className: "text-muted-foreground",
  },
};

export function StatusFooter({
  totalCount,
  streamState,
  isLoadingMore,
}: {
  totalCount: number;
  streamState: StreamState;
  isLoadingMore: boolean;
}) {
  const config = STATE_CONFIG[streamState];
  const Icon = config.icon;

  return (
    <footer className="flex min-h-10 shrink-0 items-center gap-4 border-t border-border/60 bg-card/75 px-3 py-2 text-xs backdrop-blur-md sm:px-4">
      <span
        className="tabular-nums text-muted-foreground"
        suppressHydrationWarning
      >
        {totalCount.toLocaleString()} total entries
        {isLoadingMore && " · Loading older logs..."}
      </span>
      <span className="ml-auto hidden font-mono text-[10px] text-muted-foreground md:inline">
        / search · Esc clear
      </span>
      <span
        className={cn("inline-flex items-center gap-1.5 font-medium", config.className)}
        aria-live="polite"
      >
        <Icon className="size-3" />
        {config.label}
      </span>
    </footer>
  );
}
