"use client";

import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { ShieldAlert, Inbox, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/spinner";
import { Header } from "@/components/firewall/header";
import { Toolbar, type ViewMode, type AllLogsFilters, emptyAllLogsFilters } from "@/components/firewall/toolbar";
import { FirewallRow, ROW_HEIGHT } from "@/components/firewall/firewall-row";
import { LogRow, LOG_ROW_HEIGHT, ALL_LOG_COLUMNS } from "@/components/log-row";
import { StatusFooter } from "@/components/firewall/status-footer";
import { parseFirewallMessage } from "@/lib/firewall-parser";
import { useLogStream } from "@/hooks/use-log-stream";
import { useVirtualScroll } from "@/hooks/use-virtual-scroll";
import { useTheme } from "@/hooks/use-theme";
import { loadFromStorage, saveToStorage } from "@/lib/local-storage";
import { exportAsCsv, exportAsJson } from "@/lib/export";
import type { ExpandMode, ColorMode } from "@/components/settings-dialog";
import { parseQuery, matchQuery } from "@/lib/query-parser";
import type { SyslogEntry, Filters } from "@/types/syslog";
import { emptyFilters } from "@/types/syslog";

const FW_TABLE_COLUMNS = [
  { label: "Time", width: "w-[180px]" },
  { label: "Action", width: "w-[76px]" },
  { label: "Rule", width: "w-64" },
  { label: "Iface", width: "w-20" },
  { label: "Proto", width: "w-16" },
  { label: "Source", width: "w-48" },
  { label: "Destination", width: "w-48" },
  { label: "Details", width: "flex-1" },
];

export default function Home() {
  const [viewMode, setViewMode] = useState<ViewMode>(() =>
    loadFromStorage<ViewMode>("viewMode", "all")
  );
  const [filters, setFilters] = useState<Filters>(() =>
    loadFromStorage<Filters>("filters", emptyFilters)
  );
  const [search, setSearch] = useState("");
  const [allLogsFilters, setAllLogsFilters] = useState<AllLogsFilters>(emptyAllLogsFilters);
  const [expandMode, setExpandMode] = useState<ExpandMode>(() =>
    loadFromStorage<ExpandMode>("expandMode", "single")
  );
  const [colorMode, setColorMode] = useState<ColorMode>(() =>
    loadFromStorage<ColorMode>("colorMode", "badge")
  );
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [dbRules, setDbRules] = useState<string[]>([]);
  const [dbProtocols, setDbProtocols] = useState<string[]>([]);

  const { theme, setTheme } = useTheme();

  const {
    logs,
    streamState,
    connected,
    start,
    pause,
    resume,
    stop,
    loadMore,
    hasMore,
    bufferedCount,
    isLoadingMore,
    clearLogs,
    totalInDb,
  } = useLogStream();

  // Persist preferences
  useEffect(() => saveToStorage("viewMode", viewMode), [viewMode]);
  useEffect(() => saveToStorage("filters", filters), [filters]);
  useEffect(() => saveToStorage("expandMode", expandMode), [expandMode]);
  useEffect(() => saveToStorage("colorMode", colorMode), [colorMode]);

  // Expand toggle logic
  const isExpanded = useCallback(
    (id: string) => {
      if (expandMode === "all") return true;
      return expandedIds.has(id);
    },
    [expandMode, expandedIds]
  );

  const toggleExpand = useCallback(
    (id: string) => {
      if (expandMode === "all") return;
      setExpandedIds((prev) => {
        if (expandMode === "single") {
          // Toggle: if already open, close; otherwise open only this one
          if (prev.has(id)) return new Set();
          return new Set([id]);
        }
        // single-keep: toggle individual, keep others
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    },
    [expandMode]
  );

  // Fetch filter options from DB
  useEffect(() => {
    fetch("/api/logs/filters")
      .then((r) => r.json())
      .then((d: { rules: string[]; protocols: string[] }) => {
        setDbRules(d.rules);
        setDbProtocols(d.protocols || []);
      })
      .catch(() => {});
  }, []);

  // Parse search query
  const parsedQuery = useMemo(() => parseQuery(search), [search]);

  // Client-side search + all-logs filters
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (!matchQuery(log, parsedQuery)) return false;
      if (allLogsFilters.severity && log.severity !== allLogsFilters.severity)
        return false;
      if (
        allLogsFilters.host &&
        !log.host.toLowerCase().includes(allLogsFilters.host.toLowerCase())
      )
        return false;
      if (
        allLogsFilters.facility &&
        !log.facility
          .toLowerCase()
          .includes(allLogsFilters.facility.toLowerCase())
      )
        return false;
      return true;
    });
  }, [logs, parsedQuery, allLogsFilters]);

  // Firewall parsing + client-side filtering
  const firewallParsed = useMemo(() => {
    if (viewMode !== "firewall") return [];
    // First filter to firewall logs only
    const fwLogs = filteredLogs.filter(
      (log) =>
        log.message.includes("-A-") ||
        log.message.includes("-D-") ||
        log.message.includes("-R-")
    );
    let parsed = fwLogs.map((log) => ({
      log,
      fw: parseFirewallMessage(log.message)!,
    }));
    if (filters.action)
      parsed = parsed.filter(({ fw }) => fw.action === filters.action);
    if (filters.proto)
      parsed = parsed.filter(
        ({ fw }) => fw.proto.toUpperCase() === filters.proto.toUpperCase()
      );
    const hasSrcFilter = !!(filters.srcIp || filters.srcPort);
    const hasDstFilter = !!(filters.dstIp || filters.dstPort);
    if (hasSrcFilter || hasDstFilter) {
      parsed = parsed.filter(({ fw }) => {
        const srcMatch =
          (!filters.srcIp ||
            fw.src.toLowerCase().includes(filters.srcIp.toLowerCase())) &&
          (!filters.srcPort || fw.spt === filters.srcPort);
        const dstMatch =
          (!filters.dstIp ||
            fw.dst.toLowerCase().includes(filters.dstIp.toLowerCase())) &&
          (!filters.dstPort || fw.dpt === filters.dstPort);
        if (filters.ipMatch === "or" && hasSrcFilter && hasDstFilter)
          return srcMatch || dstMatch;
        return (!hasSrcFilter || srcMatch) && (!hasDstFilter || dstMatch);
      });
    }
    if (filters.rule) {
      const q = filters.rule.toLowerCase();
      parsed = parsed.filter(
        ({ fw }) =>
          fw.rule.toLowerCase().includes(q) ||
          fw.descr.toLowerCase().includes(q)
      );
    }
    return parsed;
  }, [filteredLogs, filters, viewMode]);

  const uniqueRules = useMemo(() => {
    const seen = new Set<string>();
    for (const { fw } of firewallParsed) {
      seen.add(fw.descr || fw.rule);
    }
    return Array.from(seen).sort();
  }, [firewallParsed]);

  // Items for virtual scroll
  const items: unknown[] =
    viewMode === "firewall" ? firewallParsed : filteredLogs;
  const rowHeight = viewMode === "firewall" ? ROW_HEIGHT : LOG_ROW_HEIGHT;

  const prevItemCountRef = useRef(items.length);
  const {
    scrollRef,
    handleScroll,
    virtualData,
    isNearTop,
    isNearBottom,
    scrollToBottom,
    adjustScrollForPrepend,
  } = useVirtualScroll(items, rowHeight, {
    autoScrollToBottom: streamState === "running",
  });

  // Load more when scrolling to top
  useEffect(() => {
    if (isNearTop && hasMore && !isLoadingMore) {
      const prevCount = items.length;
      loadMore().then(() => {
        // adjustScrollForPrepend will run after state update via the effect below
      });
    }
  }, [isNearTop, hasMore, isLoadingMore, loadMore, items.length]);

  // Adjust scroll when items are prepended (loadMore adds to beginning)
  useEffect(() => {
    const prevCount = prevItemCountRef.current;
    const newCount = items.length;
    prevItemCountRef.current = newCount;

    if (isLoadingMore === false && newCount > prevCount && isNearTop) {
      // Items were prepended — adjust scroll to keep viewport stable
      const prependedCount = newCount - prevCount;
      adjustScrollForPrepend(prependedCount);
    }
  }, [items.length, isLoadingMore, isNearTop, adjustScrollForPrepend]);

  const handleClear = async () => {
    await fetch("/api/logs", { method: "DELETE" });
    clearLogs();
  };

  const handleDeleteFiltered = useCallback(
    async (f: Filters): Promise<number> => {
      const params = new URLSearchParams();
      if (f.action) params.set("action", f.action);
      if (f.proto) params.set("proto", f.proto);
      if (f.srcIp) params.set("srcIp", f.srcIp);
      if (f.srcPort) params.set("srcPort", f.srcPort);
      if (f.dstIp) params.set("dstIp", f.dstIp);
      if (f.dstPort) params.set("dstPort", f.dstPort);
      if (f.rule) params.set("rule", f.rule);
      if (f.ipMatch === "or") params.set("ipMatch", "or");
      const res = await fetch(`/api/logs?${params}`, { method: "DELETE" });
      const data = await res.json();
      return data.deleted ?? 0;
    },
    []
  );

  const handleFiltersChange = useCallback((f: Filters) => {
    setFilters(f);
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilters(emptyFilters);
    setAllLogsFilters(emptyAllLogsFilters);
    setSearch("");
  }, []);

  const removeAllLogsFilter = useCallback((key: keyof AllLogsFilters) => {
    setAllLogsFilters((prev) => ({ ...prev, [key]: "" }));
  }, []);

  const removeFilter = useCallback((key: keyof Filters) => {
    setFilters((prev) => ({
      ...prev,
      [key]: key === "ipMatch" ? "and" : "",
    }));
  }, []);

  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (viewMode === "firewall") {
      if (filters.action) count++;
      if (filters.proto) count++;
      if (filters.srcIp) count++;
      if (filters.srcPort) count++;
      if (filters.dstIp) count++;
      if (filters.dstPort) count++;
      if (filters.rule) count++;
    } else {
      if (allLogsFilters.severity) count++;
      if (allLogsFilters.host) count++;
      if (allLogsFilters.facility) count++;
    }
    if (search) count++;
    return count;
  }, [filters, allLogsFilters, viewMode, search]);

  const handleExportCsv = useCallback(() => {
    const exportLogs =
      viewMode === "firewall"
        ? firewallParsed.map((p) => p.log)
        : filteredLogs;
    exportAsCsv(exportLogs);
  }, [viewMode, firewallParsed, filteredLogs]);

  const handleExportJson = useCallback(() => {
    const exportLogs =
      viewMode === "firewall"
        ? firewallParsed.map((p) => p.log)
        : filteredLogs;
    exportAsJson(exportLogs);
  }, [viewMode, firewallParsed, filteredLogs]);

  const handleViewModeChange = useCallback((v: ViewMode) => {
    setViewMode(v);
    setExpandedIds(new Set());
  }, []);

  const columns = viewMode === "firewall" ? FW_TABLE_COLUMNS : ALL_LOG_COLUMNS;

  const emptyIcon =
    viewMode === "firewall" ? (
      <ShieldAlert className="size-8 text-muted-foreground/40" />
    ) : (
      <Inbox className="size-8 text-muted-foreground/40" />
    );

  const emptyText =
    viewMode === "firewall" ? "No firewall logs yet" : "No logs yet";

  const emptyHint =
    viewMode === "firewall"
      ? "Configure your syslog source to send firewall logs to this server."
      : "Configure your devices to send syslog to this server.";

  return (
    <div className="flex flex-col h-screen bg-background text-foreground">
      <Header
        connected={connected}
        isConnecting={streamState === "running" && !connected}
        retryCount={0}
        onClear={handleClear}
        theme={theme}
        onThemeChange={setTheme}
        expandMode={expandMode}
        onExpandModeChange={setExpandMode}
        colorMode={colorMode}
        onColorModeChange={setColorMode}
      />

      {/* Search bar */}
      <div className="px-4 py-2 bg-card/40 border-b border-border/50">
        <div className="relative max-w-2xl">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground pointer-events-none" />
          <Input
            placeholder='Search: text, host=X, level=X, src=X, dst=X, proto=X OR/AND...'
            value={search}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setSearch(e.target.value)
            }
            className="h-9 pl-10 text-sm bg-muted/50 border-border/50 focus-visible:bg-background"
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </div>
      </div>

      <Toolbar
        viewMode={viewMode}
        streamState={streamState}
        bufferedCount={bufferedCount}
        filters={filters}
        activeFilterCount={activeFilterCount}
        entryCount={items.length}
        allLogsFilters={allLogsFilters}
        onAllLogsFiltersChange={setAllLogsFilters}
        onClearAllLogsFilters={() => setAllLogsFilters(emptyAllLogsFilters)}
        onRemoveAllLogsFilter={removeAllLogsFilter}
        onFiltersChange={handleFiltersChange}
        onClearFilters={clearAllFilters}
        onRemoveFilter={removeFilter}
        onDeleteFiltered={handleDeleteFiltered}
        onStart={start}
        onPause={pause}
        onResume={resume}
        onStop={stop}
        onViewModeChange={handleViewModeChange}
        onExportCsv={handleExportCsv}
        onExportJson={handleExportJson}
        ruleOptions={[...new Set([...dbRules, ...uniqueRules])].sort()}
        protocolOptions={dbProtocols}
      />

      {/* Scrollable log area (horizontal + vertical) */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-auto min-h-0"
        onScroll={handleScroll}
      >
        {/* Sticky column header — scrolls horizontally with content, pinned vertically */}
        <div className="sticky top-0 z-10 flex bg-muted/80 backdrop-blur-sm text-muted-foreground text-[11px] uppercase font-mono font-medium tracking-wider border-b-2 border-border mx-2">
          {columns.map((col) => (
            <div key={col.label} className={`px-3 py-2.5 ${col.width} shrink-0`}>
              {col.label}
            </div>
          ))}
        </div>

        {items.length === 0 ? (
          <div className="px-3 py-16 text-center text-muted-foreground">
            {streamState === "running" && !connected ? (
              <div className="flex flex-col items-center gap-3">
                <Spinner className="h-6 w-6" />
                <span className="text-sm">Connecting to log stream...</span>
              </div>
            ) : activeFilterCount > 0 ? (
              <div className="flex flex-col items-center gap-3">
                {emptyIcon}
                <span>No matching entries</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={clearAllFilters}
                >
                  Clear filters
                </Button>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3">
                {emptyIcon}
                <span className="text-sm">{emptyText}</span>
                <span className="text-xs text-muted-foreground/60">
                  {emptyHint}
                </span>
              </div>
            )}
          </div>
        ) : (
          <div
            style={{ height: virtualData.totalHeight, position: "relative" }}
          >
            {isLoadingMore && (
              <div className="sticky top-8 left-0 right-0 flex justify-center py-2 z-10">
                <span className="inline-flex items-center gap-2 text-xs text-muted-foreground bg-card/90 backdrop-blur-sm px-3 py-1.5 rounded-full border border-border/50">
                  <Spinner className="size-3" />
                  Loading older logs...
                </span>
              </div>
            )}
            <div
              className="mx-2"
              style={{
                position: "absolute",
                top: virtualData.offsetTop,
                left: 0,
                right: 0,
              }}
            >
              {viewMode === "firewall"
                ? (
                    virtualData.visible as {
                      log: SyslogEntry;
                      fw: NonNullable<
                        ReturnType<typeof parseFirewallMessage>
                      >;
                    }[]
                  ).map((item, i) => (
                    <FirewallRow
                      key={item.log.id}
                      log={item.log}
                      fw={item.fw}
                      isExpanded={isExpanded(item.log.id)}
                      onToggle={() => toggleExpand(item.log.id)}
                      showDate
                      index={virtualData.startIdx + i}
                    />
                  ))
                : (virtualData.visible as SyslogEntry[]).map((log, i) => (
                    <LogRow
                      key={log.id}
                      log={log}
                      isExpanded={isExpanded(log.id)}
                      onToggle={() => toggleExpand(log.id)}
                      showDate
                      colorMode={colorMode}
                      index={virtualData.startIdx + i}
                    />
                  ))}
            </div>
          </div>
        )}
      </div>

      <StatusFooter
        totalCount={totalInDb}
        streamState={streamState}
        isLoadingMore={isLoadingMore}
      />
    </div>
  );
}
