"use client";

import { Settings, Sun, Moon, Monitor } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
} from "@/components/ui/dialog";
import type { Theme } from "@/hooks/use-theme";

export type ExpandMode = "single" | "single-keep" | "all";
export type ColorMode = "badge" | "row";

const THEME_OPTIONS: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
];

const EXPAND_OPTIONS: { value: ExpandMode; label: string; description: string }[] = [
  {
    value: "single",
    label: "One at a time",
    description: "Clicking a row closes the previously expanded one",
  },
  {
    value: "single-keep",
    label: "Accumulate",
    description: "Each click toggles that row, others stay as they are",
  },
  {
    value: "all",
    label: "Expand all",
    description: "All rows are expanded by default",
  },
];

const COLOR_MODE_OPTIONS: { value: ColorMode; label: string; description: string }[] = [
  {
    value: "badge",
    label: "Badge only",
    description: "Only the level badge is colored",
  },
  {
    value: "row",
    label: "Full row",
    description: "Entire row gets a subtle severity background tint",
  },
];

export function SettingsDialog({
  theme,
  expandMode,
  colorMode,
  onThemeChange,
  onExpandModeChange,
  onColorModeChange,
}: {
  theme: Theme;
  expandMode: ExpandMode;
  colorMode: ColorMode;
  onThemeChange: (t: Theme) => void;
  onExpandModeChange: (m: ExpandMode) => void;
  onColorModeChange: (m: ColorMode) => void;
}) {
  return (
    <Dialog>
      <DialogTrigger render={<Button variant="ghost" size="sm" title="Settings" />}>
        <Settings className="size-4" />
      </DialogTrigger>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>
            Customize appearance and log display behavior.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-5 py-2">
          {/* Theme */}
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Theme
            </label>
            <div className="flex rounded-md border border-input overflow-hidden text-sm font-medium">
              {THEME_OPTIONS.map(({ value, label, icon: Icon }) => (
                <button
                  key={value}
                  type="button"
                  className={`flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 transition-colors ${
                    value !== "light" ? "border-l border-input" : ""
                  } ${
                    theme === value
                      ? "bg-primary text-primary-foreground"
                      : "bg-transparent text-muted-foreground hover:text-foreground"
                  }`}
                  onClick={() => onThemeChange(value)}
                >
                  <Icon className="size-3.5" />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Expand mode */}
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Row expand behavior
            </label>
            <div className="grid gap-2">
              {EXPAND_OPTIONS.map(({ value, label, description }) => (
                <button
                  key={value}
                  type="button"
                  className={`flex flex-col items-start rounded-lg border px-3 py-2.5 text-left transition-colors ${
                    expandMode === value
                      ? "border-primary bg-primary/5 text-foreground"
                      : "border-border/60 text-muted-foreground hover:border-border hover:text-foreground"
                  }`}
                  onClick={() => onExpandModeChange(value)}
                >
                  <span className="text-sm font-medium">{label}</span>
                  <span className="text-xs text-muted-foreground mt-0.5">
                    {description}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Color mode */}
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Severity coloring
            </label>
            <div className="grid gap-2">
              {COLOR_MODE_OPTIONS.map(({ value, label, description }) => (
                <button
                  key={value}
                  type="button"
                  className={`flex flex-col items-start rounded-lg border px-3 py-2.5 text-left transition-colors ${
                    colorMode === value
                      ? "border-primary bg-primary/5 text-foreground"
                      : "border-border/60 text-muted-foreground hover:border-border hover:text-foreground"
                  }`}
                  onClick={() => onColorModeChange(value)}
                >
                  <span className="text-sm font-medium">{label}</span>
                  <span className="text-xs text-muted-foreground mt-0.5">
                    {description}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
