"use client";

import { useEffect, useState } from "react";
import { Shield, Trash2, Database } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Spinner } from "@/components/spinner";
import { SettingsDialog, type ExpandMode, type ColorMode } from "@/components/settings-dialog";
import type { Theme } from "@/hooks/use-theme";

interface DbStats {
  totalLogs: number;
  dbSizeMb: string;
}

export function Header({
  connected,
  isConnecting,
  retryCount,
  onClear,
  theme,
  onThemeChange,
  expandMode,
  onExpandModeChange,
  colorMode,
  onColorModeChange,
}: {
  connected: boolean;
  isConnecting: boolean;
  retryCount: number;
  onClear: () => void;
  theme: Theme;
  onThemeChange: (t: Theme) => void;
  expandMode: ExpandMode;
  onExpandModeChange: (m: ExpandMode) => void;
  colorMode: ColorMode;
  onColorModeChange: (m: ColorMode) => void;
}) {
  const [stats, setStats] = useState<DbStats | null>(null);

  useEffect(() => {
    const load = () =>
      fetch("/api/stats")
        .then((r) => r.json())
        .then(setStats)
        .catch(() => {});
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);

  const connectionLabel = isConnecting
    ? "Connecting"
    : connected
      ? "Viewer live"
      : "Offline";

  return (
    <header className="flex min-h-14 shrink-0 items-center gap-3 border-b border-border/60 bg-card/80 px-3 py-2 backdrop-blur-md sm:px-4">
      <div className="flex shrink-0 items-center gap-2.5">
        <div className="flex size-8 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
          <Shield className="size-4" />
        </div>
        <div className="hidden flex-col sm:flex">
          <h1 className="text-sm font-semibold leading-tight tracking-tight">
            UniFi Syslog
          </h1>
          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            Operations console
          </span>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        <Badge
          variant="outline"
          className="gap-1.5"
          title={
            connected
              ? "Browser connected to the application's live event stream"
              : isConnecting
                ? "Connecting..."
                : `Disconnected (retry #${retryCount})`
          }
        >
          {isConnecting ? (
            <Spinner className="size-3 text-status-paused" />
          ) : (
            <span
              className={cn(
                "size-1.5 rounded-full",
                connected ? "bg-status-online" : "bg-status-offline"
              )}
            />
          )}
          <span
            className={cn(
              connected
                ? "text-status-online"
                : isConnecting
                  ? "text-status-paused"
                  : "text-status-offline"
            )}
          >
            {connectionLabel}
          </span>
        </Badge>
        {stats && (
          <>
            <Separator orientation="vertical" className="hidden h-4 md:block" />
            <span
              className="hidden items-center gap-1.5 font-mono text-[11px] tabular-nums text-muted-foreground md:inline-flex"
              title={`${stats.totalLogs.toLocaleString()} logs, ${stats.dbSizeMb} MB database`}
            >
              <Database className="size-3" />
              <span className="hidden lg:inline">
                {stats.totalLogs.toLocaleString()} stored
              </span>
              <span>· {stats.dbSizeMb} MB database</span>
            </span>
          </>
        )}
      </div>

      <div className="flex-1" />

      <div className="flex shrink-0 items-center gap-1.5">
        <SettingsDialog
          theme={theme}
          expandMode={expandMode}
          colorMode={colorMode}
          onThemeChange={onThemeChange}
          onExpandModeChange={onExpandModeChange}
          onColorModeChange={onColorModeChange}
        />
        <Dialog>
          <DialogTrigger render={<Button variant="destructive" size="sm" />}>
            <Trash2 data-icon="inline-start" />
            <span className="hidden sm:inline">Clear all</span>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Clear all stored logs?</DialogTitle>
              <DialogDescription>
                This permanently deletes
                {stats ? ` ${stats.totalLogs.toLocaleString()}` : " all"} stored
                entries. New events will continue to arrive while the stream is running.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <DialogClose render={<Button variant="outline" />}>
                Cancel
              </DialogClose>
              <DialogClose
                render={<Button variant="destructive" onClick={onClear} />}
              >
                <Trash2 data-icon="inline-start" />
                Clear all logs
              </DialogClose>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </header>
  );
}
