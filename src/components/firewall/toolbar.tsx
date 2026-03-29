"use client";

import { Radio, History, Download, Shield, List } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Spinner } from "@/components/spinner";
import { FilterDialog, FilterBadges } from "./filter-dialog";
import type { Filters } from "@/types/syslog";

export type ViewMode = "all" | "firewall";

export function Toolbar({
  mode,
  viewMode,
  historyPage,
  historyTotalPages,
  historyLoading,
  filters,
  activeFilterCount,
  entryCount,
  autoScroll,
  onFiltersChange,
  onClearFilters,
  onRemoveFilter,
  onDeleteFiltered,
  onBrowseHistory,
  onGoLive,
  onAutoScrollChange,
  onViewModeChange,
  onExportCsv,
  onExportJson,
  ruleOptions,
  protocolOptions,
}: {
  mode: "live" | "history";
  viewMode: ViewMode;
  historyPage: number;
  historyTotalPages: number;
  historyLoading: boolean;
  filters: Filters;
  activeFilterCount: number;
  entryCount: number;
  autoScroll: boolean;
  onFiltersChange: (f: Filters) => void;
  onClearFilters: () => void;
  onRemoveFilter: (key: keyof Filters) => void;
  onDeleteFiltered: (f: Filters) => Promise<number>;
  onBrowseHistory: () => void;
  onGoLive: () => void;
  onAutoScrollChange: (v: boolean) => void;
  onViewModeChange: (v: ViewMode) => void;
  onExportCsv: () => void;
  onExportJson: () => void;
  ruleOptions: string[];
  protocolOptions: string[];
}) {
  return (
    <div className="flex items-center gap-2 px-6 py-2 bg-card/40 border-b border-border/50 flex-wrap">
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

      {mode === "live" ? (
        <>
          <Badge className="bg-emerald-600/90 hover:bg-emerald-600 text-white border-emerald-600 font-medium gap-1.5">
            <Radio className="size-3" />
            Live
          </Badge>
          <Button
            variant="outline"
            size="xs"
            onClick={onBrowseHistory}
            className="gap-1.5"
          >
            <History className="size-3" />
            History
          </Button>
        </>
      ) : (
        <>
          <Badge variant="secondary" className="font-medium gap-1">
            <History className="size-3" />
            Page {historyPage}/{historyTotalPages}
          </Badge>
          <Button
            size="xs"
            onClick={onGoLive}
            className="bg-emerald-700 hover:bg-emerald-600 text-white border-emerald-700 gap-1.5"
          >
            <Radio className="size-3" />
            Go Live
          </Button>
        </>
      )}

      <Separator orientation="vertical" className="h-5 mx-1" />

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

      {historyLoading && <Spinner className="text-muted-foreground" />}

      <div className="ml-auto flex items-center gap-3">
        <span
          className="text-xs text-muted-foreground tabular-nums"
          suppressHydrationWarning
        >
          {entryCount.toLocaleString()} entries
        </span>

        {/* Export buttons */}
        <div className="flex items-center">
          <Button variant="ghost" size="xs" onClick={onExportCsv} title="Export as CSV" className="gap-1">
            <Download className="size-3" />
            CSV
          </Button>
          <Button variant="ghost" size="xs" onClick={onExportJson} title="Export as JSON" className="gap-1">
            <Download className="size-3" />
            JSON
          </Button>
        </div>

        {mode === "live" && (
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => onAutoScrollChange(e.target.checked)}
              className="accent-primary"
            />
            Auto-scroll
          </label>
        )}
      </div>
    </div>
  );
}
