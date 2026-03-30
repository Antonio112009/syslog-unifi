"use client";

import { useEffect, useState } from "react";
import { Shield, Trash2, Database } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
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

  return (
    <header className="flex items-center gap-4 px-4 py-2.5 bg-card/80 backdrop-blur-sm border-b border-border/50 sticky top-0 z-10">
      {/* Logo + title */}
      <div className="flex items-center gap-2 shrink-0">
        <div className="flex items-center justify-center size-7 rounded-lg bg-primary/10 text-primary">
          <Shield className="size-3.5" />
        </div>
        <h1 className="text-sm font-semibold tracking-tight hidden sm:block">
          Syslog Viewer
        </h1>
      </div>

      {/* Connection + stats */}
      <div className="flex items-center gap-2 shrink-0">
        <span
          className={cn(
            "inline-flex items-center gap-1.5 text-xs font-medium",
            connected
              ? "text-emerald-400"
              : isConnecting
                ? "text-amber-400"
                : "text-destructive"
          )}
          title={
            connected
              ? "Stream connected"
              : isConnecting
                ? "Connecting..."
                : `Disconnected (retry #${retryCount})`
          }
        >
          {isConnecting ? (
            <Spinner className="text-amber-400" />
          ) : (
            <span
              className={cn(
                "inline-block w-2 h-2 rounded-full",
                connected
                  ? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)]"
                  : "bg-destructive"
              )}
            />
          )}
          <span className="hidden md:inline">
            {isConnecting
              ? "Connecting"
              : connected
                ? "Connected"
                : "Disconnected"}
          </span>
        </span>
        {stats && (
          <>
            <Separator orientation="vertical" className="h-4" />
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground tabular-nums" title={`${stats.totalLogs.toLocaleString()} logs, ${stats.dbSizeMb} MB database`}>
              <Database className="size-3" />
              <span className="hidden lg:inline">{stats.totalLogs.toLocaleString()} logs ·</span> {stats.dbSizeMb} MB
            </span>
          </>
        )}
      </div>

      <div className="flex-1" />

      {/* Actions */}
      <div className="flex items-center gap-1.5 shrink-0">
        <SettingsDialog
          theme={theme}
          expandMode={expandMode}
          colorMode={colorMode}
          onThemeChange={onThemeChange}
          onExpandModeChange={onExpandModeChange}
          onColorModeChange={onColorModeChange}
        />
        <Button
          onClick={onClear}
          variant="outline"
          size="sm"
          className="text-destructive hover:text-destructive hover:bg-destructive/10 border-destructive/30"
        >
          <Trash2 className="size-3.5" />
          <span className="hidden sm:inline">Clear All</span>
        </Button>
      </div>
    </header>
  );
}
