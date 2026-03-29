"use client";

import { useEffect, useState } from "react";
import { Shield, Trash2, Sun, Moon, Monitor, Database } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Spinner } from "@/components/spinner";
import type { Theme } from "@/hooks/use-theme";

interface DbStats {
  totalLogs: number;
  dbSizeMb: string;
}

const THEME_ICONS: Record<Theme, typeof Sun> = {
  light: Sun,
  dark: Moon,
  system: Monitor,
};

const THEME_CYCLE: Record<Theme, Theme> = {
  dark: "light",
  light: "system",
  system: "dark",
};

export function Header({
  connected,
  isConnecting,
  retryCount,
  onClear,
  theme,
  onThemeChange,
}: {
  connected: boolean;
  isConnecting: boolean;
  retryCount: number;
  onClear: () => void;
  theme: Theme;
  onThemeChange: (t: Theme) => void;
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

  const ThemeIcon = THEME_ICONS[theme];

  return (
    <header className="flex items-center justify-between px-6 py-3 bg-card/80 backdrop-blur-sm border-b border-border/50 sticky top-0 z-10">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center size-8 rounded-lg bg-primary/10 text-primary">
            <Shield className="size-4" />
          </div>
          <h1 className="text-base font-semibold tracking-tight">
            Syslog Viewer
          </h1>
        </div>
        <Separator orientation="vertical" className="h-5" />
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
          {isConnecting
            ? "Connecting"
            : connected
              ? "Connected"
              : "Disconnected"}
        </span>
        {stats && (
          <>
            <Separator orientation="vertical" className="h-5" />
            <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground" title={`${stats.totalLogs.toLocaleString()} logs, ${stats.dbSizeMb} MB database`}>
              <Database className="size-3" />
              {stats.totalLogs.toLocaleString()} logs · {stats.dbSizeMb} MB
            </span>
          </>
        )}
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onThemeChange(THEME_CYCLE[theme])}
          title={`Theme: ${theme}`}
        >
          <ThemeIcon className="size-4" />
        </Button>
        <Button
          onClick={onClear}
          variant="outline"
          size="sm"
          className="text-destructive hover:text-destructive hover:bg-destructive/10 border-destructive/30"
        >
          <Trash2 className="size-3.5" />
          Clear All
        </Button>
      </div>
    </header>
  );
}
