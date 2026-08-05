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
        <Filter data-icon="inline-start" />
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
            type="button"
            onClick={() => onRemove(key)}
            className="ml-0.5 rounded-full hover:bg-muted p-0.5"
            aria-label={`Remove ${label} filter`}
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
  const allLogsFilterCount =
    (allLogsFilters.severity ? 1 : 0) +
    (allLogsFilters.host ? 1 : 0) +
    (allLogsFilters.facility ? 1 : 0);
  const visibleFilterCount =
    viewMode === "all" ? allLogsFilterCount : activeFilterCount;

  return (
    <div className="shrink-0 border-b border-border/60 bg-card/45">
      <div className="flex items-center gap-2 overflow-x-auto px-3 py-2 [scrollbar-width:none] sm:px-4">
        <div className="flex shrink-0 items-center rounded-lg bg-muted p-0.5" role="group" aria-label="Log view">
          <Button
            variant={viewMode === "all" ? "secondary" : "ghost"}
            size="sm"
            aria-pressed={viewMode === "all"}
            onClick={() => onViewModeChange("all")}
          >
            <List data-icon="inline-start" />
            All logs
          </Button>
          <Button
            variant={viewMode === "firewall" ? "secondary" : "ghost"}
            size="sm"
            aria-pressed={viewMode === "firewall"}
            onClick={() => onViewModeChange("firewall")}
          >
            <Shield data-icon="inline-start" />
            Firewall
          </Button>
        </div>

        <Separator orientation="vertical" className="mx-1 h-5 shrink-0" />

        <div className="flex shrink-0 items-center gap-1">
          {streamState === "running" ? (
            <Button variant="outline" size="sm" onClick={onPause} title="Pause stream">
              <Pause data-icon="inline-start" />
              Pause
            </Button>
          ) : streamState === "paused" ? (
            <Button size="sm" onClick={onResume} title="Resume stream">
              <Play data-icon="inline-start" />
              Resume
              {bufferedCount > 0 && (
                <Badge variant="secondary">{bufferedCount}</Badge>
              )}
            </Button>
          ) : (
            <Button size="sm" onClick={onStart} title="Start stream">
              <Play data-icon="inline-start" />
              Start
            </Button>
          )}
          {streamState !== "stopped" && (
            <Button
              variant="destructive"
              size="icon-sm"
              onClick={onStop}
              title="Stop stream"
              aria-label="Stop stream"
            >
              <Square />
            </Button>
          )}
        </div>

        <Separator orientation="vertical" className="mx-1 h-5 shrink-0" />

        {viewMode === "all" ? (
          <AllLogsFilterDialog
            filters={allLogsFilters}
            onChange={onAllLogsFiltersChange}
            onClear={onClearAllLogsFilters}
          />
        ) : (
          <FilterDialog
            filters={filters}
            onChange={onFiltersChange}
            activeCount={activeFilterCount}
            onClear={onClearFilters}
            ruleOptions={ruleOptions}
            protocolOptions={protocolOptions}
            onDeleteFiltered={onDeleteFiltered}
          />
        )}

        <div className="ml-auto flex shrink-0 items-center gap-2">
          <span className="font-mono text-[11px] tabular-nums text-muted-foreground" suppressHydrationWarning>
            {entryCount.toLocaleString()} shown
          </span>
          <Button variant="ghost" size="sm" onClick={onExportCsv} title="Export as CSV">
            <Download data-icon="inline-start" />
            CSV
          </Button>
          <Button variant="ghost" size="sm" onClick={onExportJson} title="Export as JSON">
            <Download data-icon="inline-start" />
            JSON
          </Button>
        </div>
      </div>

      {visibleFilterCount > 0 && (
        <div className="flex items-center gap-2 overflow-x-auto border-t border-border/40 px-3 py-1.5 [scrollbar-width:none] sm:px-4">
          <span className="shrink-0 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            Active
          </span>
          {viewMode === "all" ? (
            <AllLogsFilterBadges
              filters={allLogsFilters}
              onRemove={onRemoveAllLogsFilter}
              onClearAll={onClearAllLogsFilters}
            />
          ) : (
            <FilterBadges
              filters={filters}
              onRemove={onRemoveFilter}
              onClearAll={onClearFilters}
              activeCount={activeFilterCount}
            />
          )}
        </div>
      )}
    </div>
  );
}
