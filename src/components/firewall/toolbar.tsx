"use client";

import { useState } from "react";
import { Play, Pause, Square, Download, Shield, List, Filter, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
} from "@/components/ui/dialog";
import { FilterDialog, FilterBadges } from "./filter-dialog";
import type { Filters, StreamState } from "@/types/syslog";

export type ViewMode = "all" | "firewall";

export interface AllLogsFilters {
  severity: string;
  host: string;
  facility: string;
}

export const emptyAllLogsFilters: AllLogsFilters = {
  severity: "",
  host: "",
  facility: "",
};

const SEVERITY_OPTIONS = [
  "emergency",
  "alert",
  "critical",
  "error",
  "warning",
  "notice",
  "info",
  "debug",
] as const;

const selectClass =
  "h-9 w-full rounded-lg border border-input bg-transparent px-3 text-sm outline-none cursor-pointer focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30";

function AllLogsFilterDialog({
  filters,
  onChange,
  onClear,
}: {
  filters: AllLogsFilters;
  onChange: (f: AllLogsFilters) => void;
  onClear: () => void;
}) {
  const [local, setLocal] = useState(filters);
  const [open, setOpen] = useState(false);

  const handleOpenChange = (nextOpen: boolean) => {
    if (nextOpen) setLocal(filters);
    setOpen(nextOpen);
  };

  const set = (key: keyof AllLogsFilters, value: string) =>
    setLocal((prev) => ({ ...prev, [key]: value }));

  const apply = () => {
    onChange(local);
    setOpen(false);
  };

  const clear = () => {
    setLocal(emptyAllLogsFilters);
    onChange(emptyAllLogsFilters);
    onClear();
    setOpen(false);
  };

  const activeCount =
    (filters.severity ? 1 : 0) +
    (filters.host ? 1 : 0) +
    (filters.facility ? 1 : 0);

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger render={<Button variant="outline" size="sm" />}>
        <Filter className="size-4" />
        Filters
        {activeCount > 0 && (
          <Badge variant="secondary" className="ml-1 h-4 text-[10px] px-1.5">
            {activeCount}
          </Badge>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Filter All Logs</DialogTitle>
          <DialogDescription>
            Narrow down log entries by level, host, and facility.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              Level
            </label>
            <select
              value={local.severity}
              onChange={(e) => set("severity", e.target.value)}
              className={selectClass}
            >
              <option value="">All levels</option>
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              Host
            </label>
            <Input
              placeholder="e.g. Gateway, 192.168..."
              value={local.host}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                set("host", e.target.value)
              }
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              Facility
            </label>
            <Input
              placeholder="e.g. kern, user, daemon..."
              value={local.facility}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                set("facility", e.target.value)
              }
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
          </div>
        </div>

        <div className="flex items-center justify-between pt-2">
          <Button variant="ghost" size="sm" onClick={clear}>
            Clear all
          </Button>
          <Button size="sm" onClick={apply}>
            Apply filters
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function AllLogsFilterBadges({
  filters,
  onRemove,
  onClearAll,
}: {
  filters: AllLogsFilters;
  onRemove: (key: keyof AllLogsFilters) => void;
  onClearAll: () => void;
}) {
  const badges: { label: string; key: keyof AllLogsFilters }[] = [];
  if (filters.severity)
    badges.push({ label: `Level: ${filters.severity}`, key: "severity" });
  if (filters.host)
    badges.push({ label: `Host: ${filters.host}`, key: "host" });
  if (filters.facility)
    badges.push({ label: `Facility: ${filters.facility}`, key: "facility" });

  if (badges.length === 0) return null;

  return (
    <>
      {badges.map(({ label, key }) => (
        <Badge key={key} variant="outline" className="gap-1 pr-1">
          {label}
          <button
            onClick={() => onRemove(key)}
            className="ml-0.5 rounded-full hover:bg-muted p-0.5"
          >
            <X className="size-3" />
          </button>
        </Badge>
      ))}
      {badges.length > 0 && (
        <Button variant="ghost" size="xs" onClick={onClearAll}>
          Clear all
        </Button>
      )}
    </>
  );
}

export function Toolbar({
  viewMode,
  streamState,
  bufferedCount,
  filters,
  activeFilterCount,
  entryCount,
  allLogsFilters,
  onAllLogsFiltersChange,
  onClearAllLogsFilters,
  onRemoveAllLogsFilter,
  onFiltersChange,
  onClearFilters,
  onRemoveFilter,
  onDeleteFiltered,
  onStart,
  onPause,
  onResume,
  onStop,
  onViewModeChange,
  onExportCsv,
  onExportJson,
  ruleOptions,
  protocolOptions,
}: {
  viewMode: ViewMode;
  streamState: StreamState;
  bufferedCount: number;
  filters: Filters;
  activeFilterCount: number;
  entryCount: number;
  allLogsFilters: AllLogsFilters;
  onAllLogsFiltersChange: (f: AllLogsFilters) => void;
  onClearAllLogsFilters: () => void;
  onRemoveAllLogsFilter: (key: keyof AllLogsFilters) => void;
  onFiltersChange: (f: Filters) => void;
  onClearFilters: () => void;
  onRemoveFilter: (key: keyof Filters) => void;
  onDeleteFiltered: (f: Filters) => Promise<number>;
  onStart: () => void;
  onPause: () => void;
  onResume: () => void;
  onStop: () => void;
  onViewModeChange: (v: ViewMode) => void;
  onExportCsv: () => void;
  onExportJson: () => void;
  ruleOptions: string[];
  protocolOptions: string[];
}) {
  return (
    <div className="flex items-center gap-2 px-4 py-1.5 bg-card/40 border-b border-border/50 flex-wrap">
      {/* View mode toggle */}
      <div className="flex rounded-md border border-input overflow-hidden text-xs font-medium">
        <button
          type="button"
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 transition-colors ${
            viewMode === "all"
              ? "bg-primary text-primary-foreground"
              : "bg-transparent text-muted-foreground hover:text-foreground"
          }`}
          onClick={() => onViewModeChange("all")}
        >
          <List className="size-3" />
          All Logs
        </button>
        <button
          type="button"
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 transition-colors border-l border-input ${
            viewMode === "firewall"
              ? "bg-primary text-primary-foreground"
              : "bg-transparent text-muted-foreground hover:text-foreground"
          }`}
          onClick={() => onViewModeChange("firewall")}
        >
          <Shield className="size-3" />
          Firewall
        </button>
      </div>

      <Separator orientation="vertical" className="h-5 mx-1" />

      {/* Stream controls */}
      <div className="flex items-center gap-1">
        {streamState === "running" ? (
          <Button
            variant="outline"
            size="xs"
            onClick={onPause}
            title="Pause stream"
            className="gap-1.5"
          >
            <Pause className="size-3" />
            Pause
          </Button>
        ) : streamState === "paused" ? (
          <Button
            size="xs"
            onClick={onResume}
            className="bg-emerald-700 hover:bg-emerald-600 text-white border-emerald-700 gap-1.5"
            title="Resume stream"
          >
            <Play className="size-3" />
            Resume
            {bufferedCount > 0 && (
              <Badge
                variant="secondary"
                className="ml-0.5 h-4 text-[10px] px-1.5 bg-white/20 text-white"
              >
                {bufferedCount}
              </Badge>
            )}
          </Button>
        ) : (
          <Button
            size="xs"
            onClick={onStart}
            className="bg-emerald-700 hover:bg-emerald-600 text-white border-emerald-700 gap-1.5"
            title="Start stream"
          >
            <Play className="size-3" />
            Start
          </Button>
        )}
        {streamState !== "stopped" && (
          <Button
            variant="outline"
            size="xs"
            onClick={onStop}
            title="Stop stream"
            className="gap-1.5 text-destructive hover:text-destructive"
          >
            <Square className="size-3" />
          </Button>
        )}
      </div>

      <Separator orientation="vertical" className="h-5 mx-1" />

      {/* All logs filters */}
      {viewMode === "all" && (
        <>
          <AllLogsFilterDialog
            filters={allLogsFilters}
            onChange={onAllLogsFiltersChange}
            onClear={onClearAllLogsFilters}
          />
          <AllLogsFilterBadges
            filters={allLogsFilters}
            onRemove={onRemoveAllLogsFilter}
            onClearAll={onClearAllLogsFilters}
          />
        </>
      )}

      {/* Firewall filters */}
      {viewMode === "firewall" && (
        <>
          <FilterDialog
            filters={filters}
            onChange={onFiltersChange}
            activeCount={activeFilterCount}
            onClear={onClearFilters}
            ruleOptions={ruleOptions}
            protocolOptions={protocolOptions}
            onDeleteFiltered={onDeleteFiltered}
          />
          <FilterBadges
            filters={filters}
            onRemove={onRemoveFilter}
            onClearAll={onClearFilters}
            activeCount={activeFilterCount}
          />
        </>
      )}

      <div className="ml-auto flex items-center gap-3">
        <span
          className="text-xs text-muted-foreground tabular-nums"
          suppressHydrationWarning
        >
          {entryCount.toLocaleString()} entries
        </span>

        <div className="flex items-center">
          <Button
            variant="ghost"
            size="xs"
            onClick={onExportCsv}
            title="Export as CSV"
            className="gap-1"
          >
            <Download className="size-3" />
            CSV
          </Button>
          <Button
            variant="ghost"
            size="xs"
            onClick={onExportJson}
            title="Export as JSON"
            className="gap-1"
          >
            <Download className="size-3" />
            JSON
          </Button>
        </div>
      </div>
    </div>
  );
}
