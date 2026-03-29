"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { ShieldAlert, Inbox } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/spinner";
import { Header } from "@/components/firewall/header";
import { Toolbar, type ViewMode } from "@/components/firewall/toolbar";
import { FirewallRow, ROW_HEIGHT } from "@/components/firewall/firewall-row";
import { LogRow, LOG_ROW_HEIGHT, ALL_LOG_COLUMNS } from "@/components/log-row";
import { StatusFooter } from "@/components/firewall/status-footer";
import { parseFirewallMessage } from "@/lib/firewall-parser";
import { useLogStream } from "@/hooks/use-log-stream";
import { useVirtualScroll } from "@/hooks/use-virtual-scroll";
import { useTheme } from "@/hooks/use-theme";
import { loadFromStorage, saveToStorage } from "@/lib/local-storage";
import { exportAsCsv, exportAsJson } from "@/lib/export";
import type { SyslogEntry, PaginatedResponse, Filters } from "@/types/syslog";
import { emptyFilters } from "@/types/syslog";

const PAGE_SIZE = 100;

const FW_TABLE_COLUMNS = [
  { label: "Time", width: "w-[88px]" },
  { label: "Action", width: "w-[76px]" },
  { label: "Rule", width: "w-64" },
  { label: "Iface", width: "w-20" },
  { label: "Proto", width: "w-16" },
  { label: "Source", width: "w-48" },
  { label: "Destination", width: "w-48" },
  { label: "Details", width: "flex-1" },
];

const FW_TABLE_COLUMNS_DATE = [
  { label: "Time", width: "w-[148px]" },
  ...FW_TABLE_COLUMNS.slice(1),
];

export default function Home() {
  // Persisted state
  const [viewMode, setViewMode] = useState<ViewMode>(() =>
    loadFromStorage<ViewMode>("viewMode", "all")
  );
  const [mode, setMode] = useState<"live" | "history">(() =>
    loadFromStorage<"live" | "history">("mode", "live")
  );
  const [filters, setFilters] = useState<Filters>(() =>
    loadFromStorage<Filters>("filters", emptyFilters)
  );
  const [autoScroll, setAutoScroll] = useState(() =>
    loadFromStorage("autoScroll", true)
  );

  // Theme
  const { theme, setTheme } = useTheme();

  // Stream
  const { liveLogs, connected, isConnecting, retryCount, clearLive } =
    useLogStream({ firewallOnly: viewMode === "firewall" });

  // History state
  const [historyLogs, setHistoryLogs] = useState<SyslogEntry[]>([]);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyTotalPages, setHistoryTotalPages] = useState(1);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [committedSearch, setCommittedSearch] = useState(filters.search || "");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [dbRules, setDbRules] = useState<string[]>([]);
  const [dbProtocols, setDbProtocols] = useState<string[]>([]);

  // Persist preferences
  useEffect(() => saveToStorage("viewMode", viewMode), [viewMode]);
  useEffect(() => saveToStorage("mode", mode), [mode]);
  useEffect(() => saveToStorage("filters", filters), [filters]);
  useEffect(() => saveToStorage("autoScroll", autoScroll), [autoScroll]);

  const displayLogs = mode === "live" ? liveLogs : historyLogs;

  const fetchPage = useCallback(
    async (page: number, searchOverride?: string, filterOverride?: Filters) => {
      setHistoryLoading(true);
      try {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("pageSize", String(PAGE_SIZE));
        if (viewMode === "firewall") params.set("firewall", "true");
        const q = searchOverride ?? committedSearch;
        if (q) params.set("search", q);

        const f = filterOverride ?? filters;
        if (viewMode === "firewall") {
          if (f.action) params.set("action", f.action);
          if (f.proto) params.set("proto", f.proto);
          if (f.srcIp) params.set("srcIp", f.srcIp);
          if (f.srcPort) params.set("srcPort", f.srcPort);
          if (f.dstIp) params.set("dstIp", f.dstIp);
          if (f.dstPort) params.set("dstPort", f.dstPort);
          if (f.rule) params.set("rule", f.rule);
          if (f.ipMatch === "or") params.set("ipMatch", "or");
        }

        const res = await fetch(`/api/logs?${params}`);
        const data: PaginatedResponse = await res.json();
        setHistoryLogs(data.logs);
        setHistoryPage(data.page);
        setHistoryTotal(data.total);
        setHistoryTotalPages(data.totalPages);
      } finally {
        setHistoryLoading(false);
      }
    },
    [committedSearch, filters, viewMode]
  );

  const handlePageChange = useCallback(
    (page: number) => {
      setHistoryPage(page);
      fetchPage(page);
    },
    [fetchPage]
  );

  const goLive = useCallback(() => {
    setMode("live");
    setAutoScroll(true);
    setHistoryPage(1);
  }, []);

  const browseHistory = useCallback(() => {
    setMode("history");
    fetchPage(1);
    fetch("/api/logs/filters")
      .then((r) => r.json())
      .then((d: { rules: string[]; protocols: string[] }) => {
        setDbRules(d.rules);
        setDbProtocols(d.protocols || []);
      })
      .catch(() => {});
  }, [fetchPage]);

  const handleFiltersChange = useCallback(
    (f: Filters) => {
      setFilters(f);
      if (f.search !== committedSearch) setCommittedSearch(f.search);
      if (mode === "history") fetchPage(1, f.search, f);
    },
    [committedSearch, fetchPage, mode]
  );

  const clearAllFilters = useCallback(() => {
    setFilters(emptyFilters);
    setCommittedSearch("");
    if (mode === "history") fetchPage(1, "", emptyFilters);
  }, [mode, fetchPage]);

  const removeFilter = useCallback(
    (key: keyof Filters) => {
      setFilters((prev) => {
        const next = { ...prev, [key]: key === "ipMatch" ? "and" : "" };
        if (key === "search") setCommittedSearch("");
        if (mode === "history")
          fetchPage(1, key === "search" ? "" : undefined, next);
        return next;
      });
    },
    [mode, fetchPage]
  );

  useEffect(() => {
    if (mode === "history") fetchPage(1);
  }, [mode, fetchPage]);

  // Client-side search for live mode
  const filteredLogs = useMemo(() => {
    return displayLogs.filter((log) => {
      if (mode === "live" && filters.search) {
        const q = filters.search.toLowerCase();
        if (
          !log.message.toLowerCase().includes(q) &&
          !log.host.toLowerCase().includes(q) &&
          !log.raw.toLowerCase().includes(q)
        )
          return false;
      }
      return true;
    });
  }, [displayLogs, filters.search, mode]);

  // Firewall parsing + client-side filtering
  const firewallParsed = useMemo(() => {
    if (viewMode !== "firewall") return [];
    let parsed = filteredLogs.map((log) => ({
      log,
      fw: parseFirewallMessage(log.message)!,
    }));
    if (mode === "live") {
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
    }
    return parsed;
  }, [filteredLogs, filters, viewMode, mode]);

  const uniqueRules = useMemo(() => {
    const seen = new Set<string>();
    for (const { fw } of firewallParsed) {
      seen.add(fw.descr || fw.rule);
    }
    return Array.from(seen).sort();
  }, [firewallParsed]);

  // Items for virtual scroll
  const items: unknown[] = viewMode === "firewall" ? firewallParsed : filteredLogs;
  const rowHeight = viewMode === "firewall" ? ROW_HEIGHT : LOG_ROW_HEIGHT;
  const showDate = mode === "history";

  const { scrollRef, handleScroll, virtualData, isNearTop, scrollToTop } =
    useVirtualScroll(items, rowHeight, {
      autoScrollToTop: mode === "live" && autoScroll,
      autoScrollDep: liveLogs,
    });

  // Disable auto-scroll when user scrolls away
  useEffect(() => {
    if (mode === "live" && !isNearTop && autoScroll) {
      setAutoScroll(false);
    }
  }, [isNearTop, mode, autoScroll]);

  const handleClear = async () => {
    await fetch("/api/logs", { method: "DELETE" });
    clearLive();
    setHistoryLogs([]);
    setHistoryTotal(0);
    setHistoryTotalPages(1);
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
      if (mode === "history") fetchPage(historyPage);
      return data.deleted ?? 0;
    },
    [mode, fetchPage, historyPage]
  );

  const totalCount = mode === "history" ? historyTotal : liveLogs.length;

  const activeFilterCount = useMemo(() => {
    if (viewMode !== "firewall") return 0;
    let count = 0;
    if (filters.action) count++;
    if (filters.proto) count++;
    if (filters.srcIp) count++;
    if (filters.srcPort) count++;
    if (filters.dstIp) count++;
    if (filters.dstPort) count++;
    if (filters.rule) count++;
    if (filters.search) count++;
    return count;
  }, [filters, viewMode]);

  const handleExportCsv = useCallback(() => {
    const logs =
      viewMode === "firewall" ? firewallParsed.map((p) => p.log) : filteredLogs;
    exportAsCsv(logs);
  }, [viewMode, firewallParsed, filteredLogs]);

  const handleExportJson = useCallback(() => {
    const logs =
      viewMode === "firewall" ? firewallParsed.map((p) => p.log) : filteredLogs;
    exportAsJson(logs);
  }, [viewMode, firewallParsed, filteredLogs]);

  const handleViewModeChange = useCallback((v: ViewMode) => {
    setViewMode(v);
    setExpandedId(null);
  }, []);

  const columns =
    viewMode === "firewall"
      ? showDate
        ? FW_TABLE_COLUMNS_DATE
        : FW_TABLE_COLUMNS
      : ALL_LOG_COLUMNS;

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
        isConnecting={isConnecting}
        retryCount={retryCount}
        onClear={handleClear}
        theme={theme}
        onThemeChange={setTheme}
      />

      <Toolbar
        mode={mode}
        viewMode={viewMode}
        historyPage={historyPage}
        historyTotalPages={historyTotalPages}
        historyLoading={historyLoading}
        filters={filters}
        activeFilterCount={activeFilterCount}
        entryCount={items.length}
        autoScroll={autoScroll}
        onFiltersChange={handleFiltersChange}
        onClearFilters={clearAllFilters}
        onRemoveFilter={removeFilter}
        onDeleteFiltered={handleDeleteFiltered}
        onBrowseHistory={browseHistory}
        onGoLive={goLive}
        onAutoScrollChange={setAutoScroll}
        onViewModeChange={handleViewModeChange}
        onExportCsv={handleExportCsv}
        onExportJson={handleExportJson}
        ruleOptions={mode === "history" ? dbRules : uniqueRules}
        protocolOptions={dbProtocols}
      />

      {/* Table header */}
      <div className="flex bg-card/60 text-muted-foreground text-[11px] uppercase font-mono font-medium tracking-wider shrink-0 border-b border-border/50">
        {columns.map((col) => (
          <div
            key={col.label}
            className={`px-3 py-2.5 ${col.width} shrink-0`}
          >
            {col.label}
          </div>
        ))}
      </div>

      {/* Scrollable log area */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-auto min-h-0"
        onScroll={handleScroll}
      >
        {items.length === 0 ? (
          <div className="px-3 py-16 text-center text-muted-foreground">
            {historyLoading ? (
              <div className="flex flex-col items-center gap-3">
                <Spinner className="h-6 w-6" />
                <span>Loading...</span>
              </div>
            ) : isConnecting && mode === "live" ? (
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
            <div
              style={{
                position: "absolute",
                top: virtualData.offsetTop,
                left: 0,
                right: 0,
              }}
            >
              {viewMode === "firewall"
                ? (virtualData.visible as { log: SyslogEntry; fw: NonNullable<ReturnType<typeof parseFirewallMessage>> }[]).map(
                    (item) => (
                      <FirewallRow
                        key={item.log.id}
                        log={item.log}
                        fw={item.fw}
                        isExpanded={expandedId === item.log.id}
                        onToggle={() =>
                          setExpandedId(
                            expandedId === item.log.id ? null : item.log.id
                          )
                        }
                        showDate={showDate}
                      />
                    )
                  )
                : (virtualData.visible as SyslogEntry[]).map((log) => (
                    <LogRow
                      key={log.id}
                      log={log}
                      isExpanded={expandedId === log.id}
                      onToggle={() =>
                        setExpandedId(
                          expandedId === log.id ? null : log.id
                        )
                      }
                      showDate={showDate}
                    />
                  ))}
            </div>
          </div>
        )}
      </div>

      <StatusFooter
        mode={mode}
        totalCount={totalCount}
        historyPage={historyPage}
        historyTotalPages={historyTotalPages}
        onPageChange={(page) => {
          handlePageChange(page);
          scrollToTop();
        }}
        onBrowseHistory={browseHistory}
        onGoLive={goLive}
      />
    </div>
  );
}
