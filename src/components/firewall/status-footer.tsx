"use client";

import { Play, Pause, Square } from "lucide-react";
import type { StreamState } from "@/types/syslog";

const STATE_CONFIG: Record<
  StreamState,
  { label: string; icon: typeof Play; className: string }
> = {
  running: {
    label: "Streaming",
    icon: Play,
    className: "text-emerald-400",
  },
  paused: {
    label: "Paused",
    icon: Pause,
    className: "text-amber-400",
  },
  stopped: {
    label: "Stopped",
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
    <div className="flex items-center justify-between px-6 py-3 bg-card/60 backdrop-blur-sm border-t border-border/50 text-sm shrink-0">
      <span
        className="text-muted-foreground tabular-nums"
        suppressHydrationWarning
      >
        {totalCount.toLocaleString()} total entries
        {isLoadingMore && " · Loading older logs..."}
      </span>
      <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${config.className}`}>
        <Icon className="size-3" />
        {config.label}
      </span>
      <span className="text-xs text-muted-foreground/50">
        Made by Antonio112009
      </span>
    </div>
  );
}
