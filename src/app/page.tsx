"use client";

import { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
} from "@/components/ui/dialog";

interface SyslogEntry {
  id: string;
  timestamp: string;
  facility: string;
  severity: string;
  host: string;
  message: string;
  raw: string;
  receivedAt: string;
  subsystem: string;
  key: string;
}

interface PaginatedResponse {
  logs: SyslogEntry[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

const ROW_HEIGHT = 32;
const OVERSCAN = 10;
const PAGE_SIZE = 100;

const selectClass =
  "h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm outline-none cursor-pointer focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30";

interface ParsedFirewall {
  rule: string;
  action: string;
  descr: string;
  iface: string;
  src: string;
  dst: string;
  proto: string;
  spt: string;
  dpt: string;
  len: string;
  mac: string;
}

const FW_KV_REGEXES: Record<string, RegExp> = {
  IN: /IN=([^\s]*)/,
  SRC: /SRC=([^\s]*)/,
  DST: /DST=([^\s]*)/,
  PROTO: /PROTO=([^\s]*)/,
  SPT: /SPT=([^\s]*)/,
  DPT: /DPT=([^\s]*)/,
  LEN: /LEN=([^\s]*)/,
  MAC: /MAC=([^\s]*)/,
};

function parseFirewallMessage(msg: string): ParsedFirewall | null {
  const ruleMatch = msg.match(/\[([^\]]+)\]/);
  if (!ruleMatch) return null;
  const ruleRaw = ruleMatch[1];
  const actionCode = ruleRaw.match(/-([ADR])-/)?.[1] || "";
  const actionMap: Record<string, string> = { A: "Allow", D: "Drop", R: "Reject" };
  const action = actionMap[actionCode] || actionCode;
  const descrMatch = msg.match(/DESCR="([^"]*)"/s);
  const kv = (key: string) => msg.match(FW_KV_REGEXES[key])?.[1] || "";
  return {
    rule: ruleRaw,
    action,
    descr: descrMatch?.[1]?.replace(/^\[[^\]]*\]/, "") || "",
    iface: kv("IN"),
    src: kv("SRC"),
    dst: kv("DST"),
    proto: kv("PROTO"),
    spt: kv("SPT"),
    dpt: kv("DPT"),
    len: kv("LEN"),
    mac: kv("MAC"),
  };
}

function Spinner({ className = "" }: { className?: string }) {
  return (
    <svg
      className={`animate-spin h-4 w-4 ${className}`}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

const ACTION_COLORS: Record<string, string> = {
  Allow: "text-green-400",
  Drop: "text-red-400",
  Reject: "text-yellow-400",
};

function FirewallRow({
  log,
  fw,
  isExpanded,
  onToggle,
}: {
  log: SyslogEntry;
  fw: ParsedFirewall;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      className="flex items-start border-b border-border/50 hover:bg-muted/30 cursor-pointer font-mono text-sm"
      style={{ minHeight: ROW_HEIGHT }}
      onClick={onToggle}
    >
      <div className="px-3 py-1.5 text-muted-foreground whitespace-nowrap w-24 shrink-0">
        {log.timestamp.slice(11, 19)}
      </div>
      <div
        className={`px-3 py-1.5 w-20 shrink-0 font-medium ${ACTION_COLORS[fw.action] || "text-foreground"}`}
      >
        {fw.action}
      </div>
      <div className="px-3 py-1.5 text-cyan-400 w-72 shrink-0 truncate" title={fw.rule}>
        {fw.descr || fw.rule}
      </div>
      <div className="px-3 py-1.5 text-purple-400 w-20 shrink-0">{fw.iface}</div>
      <div className="px-3 py-1.5 text-blue-300 w-20 shrink-0">{fw.proto}</div>
      <div className="px-3 py-1.5 w-48 shrink-0 truncate" title={`${fw.src}:${fw.spt}`}>
        {fw.src}
        <span className="text-muted-foreground">{fw.spt ? `:${fw.spt}` : ""}</span>
      </div>
      <div className="px-3 py-1.5 w-48 shrink-0 truncate" title={`${fw.dst}:${fw.dpt}`}>
        {fw.dst}
        <span className="text-muted-foreground">{fw.dpt ? `:${fw.dpt}` : ""}</span>
      </div>
      <div className="px-2 py-1.5 flex-1 min-w-0">
        {isExpanded ? (
          <pre className="whitespace-pre-wrap break-all text-xs text-muted-foreground">
            {log.raw}
          </pre>
        ) : (
          <span className="truncate block text-muted-foreground">{fw.rule}</span>
        )}
      </div>
    </div>
  );
}

interface Filters {
  action: string;
  proto: string;
  srcIp: string;
  srcPort: string;
  dstIp: string;
  dstPort: string;
  rule: string;
  search: string;
  ipMatch: "and" | "or";
}

const emptyFilters: Filters = {
  action: "",
  proto: "",
  srcIp: "",
  srcPort: "",
  dstIp: "",
  dstPort: "",
  rule: "",
  search: "",
  ipMatch: "and",
};

function FilterDialog({
  filters,
  onChange,
  activeCount,
  onClear,
  ruleOptions,
  onDeleteFiltered,
}: {
  filters: Filters;
  onChange: (f: Filters) => void;
  activeCount: number;
  onClear: () => void;
  ruleOptions: string[];
  onDeleteFiltered: (f: Filters) => Promise<number>;
}) {
  const [local, setLocal] = useState(filters);
  const [open, setOpen] = useState(false);
  const [ruleDropdownOpen, setRuleDropdownOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const ruleRef = useRef<HTMLDivElement>(null);

  const handleOpenChange = (nextOpen: boolean) => {
    if (nextOpen) setLocal(filters);
    setConfirmDelete(false);
    setOpen(nextOpen);
  };

  const hasAnyFilter = !!(local.action || local.proto || local.srcIp || local.srcPort || local.dstIp || local.dstPort || local.rule);

  const handleDelete = async () => {
    setDeleting(true);
    try {
      const deleted = await onDeleteFiltered(local);
      setConfirmDelete(false);
      setOpen(false);
      if (deleted > 0) onChange(local);
    } finally {
      setDeleting(false);
    }
  };

  const apply = () => {
    onChange(local);
    setOpen(false);
  };

  const clear = () => {
    setLocal(emptyFilters);
    onChange(emptyFilters);
    onClear();
    setOpen(false);
  };

  const set = (key: keyof Filters, value: string) =>
    setLocal((prev) => ({ ...prev, [key]: value }));

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger render={<Button variant="outline" size="sm" />}>
        <svg
          xmlns="http://www.w3.org/2000/svg"
          className="size-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
        </svg>
        Filters
        {activeCount > 0 && (
          <Badge variant="secondary" className="ml-1 h-4 text-[10px] px-1.5">
            {activeCount}
          </Badge>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Filter Firewall Logs</DialogTitle>
          <DialogDescription>
            Narrow down firewall entries by action, protocol, addresses, and ports.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Action</label>
              <select
                value={local.action}
                onChange={(e) => set("action", e.target.value)}
                className={selectClass}
              >
                <option value="">All</option>
                <option value="Allow">Allow</option>
                <option value="Drop">Drop</option>
                <option value="Reject">Reject</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Protocol</label>
              <select
                value={local.proto}
                onChange={(e) => set("proto", e.target.value)}
                className={selectClass}
              >
                <option value="">All</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-muted/20 p-3 space-y-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Source</label>
              <div className="grid grid-cols-[1fr_100px] gap-2">
                <Input
                  placeholder="e.g. 192.168.2 or .2.11"
                  value={local.srcIp}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("srcIp", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
                <Input
                  placeholder="Port"
                  value={local.srcPort}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("srcPort", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex-1 h-px bg-border/60" />
              <div className="flex rounded-md border border-input overflow-hidden text-xs font-medium">
                <button
                  type="button"
                  className={cn(
                    "px-3 py-1 transition-colors",
                    local.ipMatch === "and"
                      ? "bg-primary text-primary-foreground"
                      : "bg-transparent text-muted-foreground hover:text-foreground",
                  )}
                  onClick={() => set("ipMatch", "and")}
                >
                  AND
                </button>
                <button
                  type="button"
                  className={cn(
                    "px-3 py-1 transition-colors border-l border-input",
                    local.ipMatch === "or"
                      ? "bg-primary text-primary-foreground"
                      : "bg-transparent text-muted-foreground hover:text-foreground",
                  )}
                  onClick={() => set("ipMatch", "or")}
                >
                  OR
                </button>
              </div>
              <div className="flex-1 h-px bg-border/60" />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Destination</label>
              <div className="grid grid-cols-[1fr_100px] gap-2">
                <Input
                  placeholder="e.g. 192.168.2 or .2.11"
                  value={local.dstIp}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("dstIp", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
                <Input
                  placeholder="Port"
                  value={local.dstPort}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("dstPort", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Rule</label>
            <div className="relative" ref={ruleRef}>
              <Input
                placeholder="e.g. LAN_IN, WAN_OUT..."
                value={local.rule}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                  set("rule", e.target.value);
                  setRuleDropdownOpen(true);
                }}
                onFocus={() => setRuleDropdownOpen(true)}
                onBlur={(e: React.FocusEvent) => {
                  if (!ruleRef.current?.contains(e.relatedTarget as Node)) {
                    setRuleDropdownOpen(false);
                  }
                }}
                autoComplete="off"
                data-1p-ignore
                data-lpignore="true"
              />
              {ruleDropdownOpen && (() => {
                const filtered = ruleOptions.filter((r) =>
                  !local.rule || r.toLowerCase().includes(local.rule.toLowerCase())
                );
                if (filtered.length === 0) return null;
                return (
                  <div className="absolute z-50 mt-1 w-full max-h-48 overflow-y-auto rounded-md border border-border bg-popover py-1 shadow-md">
                    {filtered.map((r) => (
                      <button
                        key={r}
                        type="button"
                        className="w-full px-3 py-1.5 text-left text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer truncate"
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={() => {
                          set("rule", r);
                          setRuleDropdownOpen(false);
                        }}
                      >
                        {r}
                      </button>
                    ))}
                  </div>
                );
              })()}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              Search (message)
            </label>
            <Input
              placeholder="e.g. DNS, 443..."
              value={local.search}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                set("search", e.target.value)
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
          <div className="flex items-center gap-2">
            {confirmDelete ? (
              <>
                <span className="text-xs text-destructive">Delete all matching?</span>
                <Button variant="destructive" size="sm" onClick={handleDelete} disabled={deleting}>
                  {deleting ? "Deleting..." : "Confirm"}
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(false)}>
                  Cancel
                </Button>
              </>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="text-destructive border-destructive/30 hover:bg-destructive/10"
                onClick={() => setConfirmDelete(true)}
                disabled={!hasAnyFilter}
                title={hasAnyFilter ? "Delete logs matching current filters" : "Set at least one filter to delete"}
              >
                Delete Matching
              </Button>
            )}
            <Button size="sm" onClick={apply}>
              Apply filters
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function Home() {
  const [mode, setMode] = useState<"live" | "history">("live");
  const [liveLogs, setLiveLogs] = useState<SyslogEntry[]>([]);
  const [historyLogs, setHistoryLogs] = useState<SyslogEntry[]>([]);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyTotalPages, setHistoryTotalPages] = useState(1);
  const [historyLoading, setHistoryLoading] = useState(false);

  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [committedSearch, setCommittedSearch] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [connected, setConnected] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isConnecting, setIsConnecting] = useState(true);
  const [retryCount, setRetryCount] = useState(0);
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewHeight, setViewHeight] = useState(800);
  const [dbRules, setDbRules] = useState<string[]>([]);

  const displayLogs = mode === "live" ? liveLogs : historyLogs;

  const fetchPage = useCallback(
    async (page: number, searchOverride?: string, filterOverride?: Filters) => {
      setHistoryLoading(true);
      try {
        const params = new URLSearchParams();
        params.set("page", String(page));
        params.set("pageSize", String(PAGE_SIZE));
        params.set("firewall", "true");
        const q = searchOverride ?? committedSearch;
        if (q) params.set("search", q);

        const f = filterOverride ?? filters;
        if (f.action) params.set("action", f.action);
        if (f.proto) params.set("proto", f.proto);
        if (f.srcIp) params.set("srcIp", f.srcIp);
        if (f.srcPort) params.set("srcPort", f.srcPort);
        if (f.dstIp) params.set("dstIp", f.dstIp);
        if (f.dstPort) params.set("dstPort", f.dstPort);
        if (f.rule) params.set("rule", f.rule);
        if (f.ipMatch === "or") params.set("ipMatch", "or");

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
    [committedSearch, filters],
  );

  const handlePageChange = useCallback(
    (page: number) => {
      setHistoryPage(page);
      fetchPage(page);
      scrollRef.current?.scrollTo(0, 0);
    },
    [fetchPage],
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
      .then((d: { rules: string[] }) => setDbRules(d.rules))
      .catch(() => {});
  }, [fetchPage]);

  const handleFiltersChange = useCallback(
    (f: Filters) => {
      setFilters(f);
      if (f.search !== committedSearch) {
        setCommittedSearch(f.search);
      }
      if (mode === "history") {
        fetchPage(1, f.search, f);
      }
    },
    [committedSearch, fetchPage, mode],
  );

  const clearAllFilters = useCallback(() => {
    setFilters(emptyFilters);
    setCommittedSearch("");
    if (mode === "history") fetchPage(1, "", emptyFilters);
  }, [mode, fetchPage]);

  useEffect(() => {
    if (mode === "history") {
      fetchPage(1);
    }
  }, [mode, fetchPage]);

  const connectStream = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }
    setIsConnecting(true);

    const es = new EventSource("/api/logs?stream=true&firewall=true");
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setIsConnecting(false);
      setRetryCount(0);
    };

    es.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "init") {
        setLiveLogs(data.logs);
      } else if (data.type === "log") {
        setLiveLogs((prev) => {
          const next = [...prev, data.entry];
          if (next.length > 500) return next.slice(-500);
          return next;
        });
      }
    };

    es.onerror = () => {
      setConnected(false);
      setIsConnecting(false);
      es.close();
      setRetryCount((prev) => {
        const next = prev + 1;
        const delay = Math.min(1000 * Math.pow(2, next), 30000);
        retryTimeoutRef.current = setTimeout(connectStream, delay);
        return next;
      });
    };
  }, []);

  useEffect(() => {
    connectStream();
    return () => {
      eventSourceRef.current?.close();
      if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
    };
  }, [connectStream]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) =>
      setViewHeight(entry.contentRect.height),
    );
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (mode === "live" && autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [liveLogs, autoScroll, mode]);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setScrollTop(el.scrollTop);
    if (mode === "live") {
      const atBottom =
        el.scrollHeight - el.scrollTop - el.clientHeight < ROW_HEIGHT * 2;
      if (!atBottom && autoScroll) setAutoScroll(false);
    }
  }, [autoScroll, mode]);

  const firewallLogs = useMemo(() => {
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

  const firewallParsed = useMemo(() => {
    let parsed = firewallLogs.map((log) => ({
      log,
      fw: parseFirewallMessage(log.message)!,
    }));
    if (filters.action) {
      parsed = parsed.filter(({ fw }) => fw.action === filters.action);
    }
    if (filters.proto) {
      parsed = parsed.filter(
        ({ fw }) => fw.proto.toUpperCase() === filters.proto.toUpperCase(),
      );
    }
    const hasSrcFilter = !!(filters.srcIp || filters.srcPort);
    const hasDstFilter = !!(filters.dstIp || filters.dstPort);
    if (hasSrcFilter || hasDstFilter) {
      parsed = parsed.filter(({ fw }) => {
        const srcMatch =
          (!filters.srcIp || fw.src.toLowerCase().includes(filters.srcIp.toLowerCase())) &&
          (!filters.srcPort || fw.spt === filters.srcPort);
        const dstMatch =
          (!filters.dstIp || fw.dst.toLowerCase().includes(filters.dstIp.toLowerCase())) &&
          (!filters.dstPort || fw.dpt === filters.dstPort);

        if (filters.ipMatch === "or" && hasSrcFilter && hasDstFilter) {
          return srcMatch || dstMatch;
        }
        return (!hasSrcFilter || srcMatch) && (!hasDstFilter || dstMatch);
      });
    }
    if (filters.rule) {
      const q = filters.rule.toLowerCase();
      parsed = parsed.filter(
        ({ fw }) =>
          fw.rule.toLowerCase().includes(q) ||
          fw.descr.toLowerCase().includes(q),
      );
    }
    return parsed;
  }, [firewallLogs, filters]);

  const uniqueRules = useMemo(() => {
    const seen = new Set<string>();
    for (const { fw } of firewallParsed) {
      seen.add(fw.descr || fw.rule);
    }
    return Array.from(seen).sort();
  }, [firewallParsed]);

  const virtualData = useMemo(() => {
    const totalHeight = firewallParsed.length * ROW_HEIGHT;
    const startIdx = Math.max(
      0,
      Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN,
    );
    const endIdx = Math.min(
      firewallParsed.length,
      Math.ceil((scrollTop + viewHeight) / ROW_HEIGHT) + OVERSCAN,
    );
    const offsetTop = startIdx * ROW_HEIGHT;
    return {
      totalHeight,
      offsetTop,
      visible: firewallParsed.slice(startIdx, endIdx),
    };
  }, [firewallParsed, scrollTop, viewHeight]);

  const handleClear = async () => {
    await fetch("/api/logs", { method: "DELETE" });
    setLiveLogs([]);
    setHistoryLogs([]);
    setHistoryTotal(0);
    setHistoryTotalPages(1);
  };

  const handleDeleteFiltered = useCallback(async (f: Filters): Promise<number> => {
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
  }, [mode, fetchPage, historyPage]);

  const totalCount =
    mode === "history" ? historyTotal : liveLogs.length;

  const activeFilterCount = useMemo(() => {
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
  }, [filters]);

  const filterBadges = useMemo(() => {
    const badges: { label: string; key: keyof Filters }[] = [];
    if (filters.action)
      badges.push({ label: `Action: ${filters.action}`, key: "action" });
    if (filters.proto)
      badges.push({ label: `Proto: ${filters.proto}`, key: "proto" });
    const hasSrc = !!(filters.srcIp || filters.srcPort);
    const hasDst = !!(filters.dstIp || filters.dstPort);
    const orMode = filters.ipMatch === "or" && hasSrc && hasDst;
    if (filters.srcIp)
      badges.push({ label: `Src: ${filters.srcIp}`, key: "srcIp" });
    if (filters.srcPort)
      badges.push({ label: `Src Port: ${filters.srcPort}`, key: "srcPort" });
    if (orMode)
      badges.push({ label: "OR", key: "ipMatch" });
    if (filters.dstIp)
      badges.push({ label: `Dst: ${filters.dstIp}`, key: "dstIp" });
    if (filters.dstPort)
      badges.push({ label: `Dst Port: ${filters.dstPort}`, key: "dstPort" });
    if (filters.rule)
      badges.push({ label: `Rule: ${filters.rule}`, key: "rule" });
    if (filters.search)
      badges.push({ label: `"${filters.search}"`, key: "search" });
    return badges;
  }, [filters]);

  const removeFilter = useCallback((key: keyof Filters) => {
    setFilters((prev) => {
      const next = { ...prev, [key]: key === "ipMatch" ? "and" : "" };
      if (key === "search") setCommittedSearch("");
      if (mode === "history") fetchPage(1, key === "search" ? "" : undefined, next);
      return next;
    });
  }, [mode, fetchPage]);

  const paginationPages = useMemo(() => {
    const pages: (number | "...")[] = [];
    const w = 2;
    for (let i = 1; i <= historyTotalPages; i++) {
      if (
        i === 1 ||
        i === historyTotalPages ||
        (i >= historyPage - w && i <= historyPage + w)
      ) {
        pages.push(i);
      } else if (pages.length > 0 && pages[pages.length - 1] !== "...") {
        pages.push("...");
      }
    }
    return pages;
  }, [historyPage, historyTotalPages]);

  return (
    <div className="flex flex-col h-screen bg-background text-foreground">
      <header className="flex items-center justify-between px-6 py-3 bg-card border-b border-border">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold tracking-tight">
            Firewall Log Viewer
          </h1>
          <Separator orientation="vertical" className="h-5" />
          <span
            className={cn(
              "inline-flex items-center gap-1.5 text-xs",
              connected
                ? "text-green-400"
                : isConnecting
                  ? "text-yellow-400"
                  : "text-destructive",
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
              <Spinner className="text-yellow-400" />
            ) : (
              <span
                className={cn(
                  "inline-block w-2 h-2 rounded-full",
                  connected ? "bg-green-500" : "bg-destructive",
                )}
              />
            )}
            {isConnecting
              ? "Connecting"
              : connected
                ? "Stream"
                : "Disconnected"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={handleClear} variant="destructive" size="sm">
            Clear
          </Button>
        </div>
      </header>

      <div className="flex items-center gap-2 px-6 py-2 bg-card/50 border-b border-border">
        {mode === "live" ? (
          <>
            <Badge className="bg-green-600 hover:bg-green-600 text-white border-green-600 font-medium">
              ● Live
            </Badge>
            <Button variant="outline" size="xs" onClick={browseHistory}>
              Browse History
            </Button>
          </>
        ) : (
          <>
            <Badge variant="secondary" className="font-medium">
              History · Page {historyPage}/{historyTotalPages}
            </Badge>
            <Button
              size="xs"
              onClick={goLive}
              className="bg-green-700 hover:bg-green-600 text-white border-green-700"
            >
              ● Go Live
            </Button>
          </>
        )}

        <Separator orientation="vertical" className="h-5 mx-1" />

        <FilterDialog
          filters={filters}
          onChange={handleFiltersChange}
          activeCount={activeFilterCount}
          onClear={clearAllFilters}
          ruleOptions={mode === "history" ? dbRules : uniqueRules}
          onDeleteFiltered={handleDeleteFiltered}
        />

        {filterBadges.map(({ label, key }) =>
          key === "ipMatch" ? (
            <span
              key={key}
              className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider"
            >
              or
            </span>
          ) : (
            <Badge key={key} variant="outline" className="gap-1 pr-1">
              {label}
              <button
                onClick={() => removeFilter(key)}
                className="ml-0.5 rounded-full hover:bg-muted p-0.5"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="size-3"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M18 6 6 18" />
                  <path d="m6 6 12 12" />
                </svg>
              </button>
            </Badge>
          ),
        )}

        {activeFilterCount > 0 && (
          <Button variant="ghost" size="xs" onClick={clearAllFilters}>
            Clear all
          </Button>
        )}

        {historyLoading && <Spinner className="text-muted-foreground" />}

        <div className="ml-auto flex items-center gap-3">
          <span
            className="text-xs text-muted-foreground"
            suppressHydrationWarning
          >
            {firewallParsed.length} entries
          </span>
          {mode === "live" && (
            <label className="flex items-center gap-1.5 text-sm text-muted-foreground cursor-pointer select-none">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="accent-primary"
              />
              Auto-scroll
            </label>
          )}
        </div>
      </div>

      <div className="flex bg-card text-muted-foreground text-xs uppercase font-mono shrink-0 border-b border-border">
        <div className="px-3 py-2 w-24 shrink-0">Time</div>
        <div className="px-3 py-2 w-20 shrink-0">Action</div>
        <div className="px-3 py-2 w-72 shrink-0">Rule</div>
        <div className="px-3 py-2 w-20 shrink-0">Iface</div>
        <div className="px-3 py-2 w-20 shrink-0">Proto</div>
        <div className="px-3 py-2 w-48 shrink-0">Source</div>
        <div className="px-3 py-2 w-48 shrink-0">Destination</div>
        <div className="px-3 py-2 flex-1">Rule ID</div>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 overflow-auto min-h-0"
        onScroll={handleScroll}
      >
        {firewallParsed.length === 0 ? (
          <div className="px-3 py-12 text-center text-muted-foreground">
            {historyLoading ? (
              <div className="flex flex-col items-center gap-3">
                <Spinner className="h-6 w-6" />
                <span>Loading...</span>
              </div>
            ) : isConnecting && mode === "live" ? (
              <div className="flex flex-col items-center gap-3">
                <Spinner className="h-6 w-6" />
                <span>Connecting to log stream...</span>
              </div>
            ) : activeFilterCount > 0 ? (
              <div className="flex flex-col items-center gap-3">
                <span>No matching firewall entries</span>
                <Button variant="outline" size="sm" onClick={clearAllFilters}>
                  Clear filters
                </Button>
              </div>
            ) : (
              "No firewall logs yet. Configure your UniFi controller to send syslog to this server."
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
              {virtualData.visible.map(({ log, fw }) => (
                <FirewallRow
                  key={log.id}
                  log={log}
                  fw={fw}
                  isExpanded={expandedId === log.id}
                  onToggle={() =>
                    setExpandedId(expandedId === log.id ? null : log.id)
                  }
                />
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between px-6 py-2 bg-card border-t border-border text-sm shrink-0">
        <span className="text-muted-foreground" suppressHydrationWarning>
          {totalCount.toLocaleString()} total entries
          {mode === "history" &&
            ` · Page ${historyPage} of ${historyTotalPages}`}
        </span>
        <div className="flex items-center gap-1.5">
          {mode === "history" && (
            <>
              <Button
                size="xs"
                variant="outline"
                onClick={() => handlePageChange(historyPage - 1)}
                disabled={historyPage <= 1}
              >
                ← Newer
              </Button>
              {paginationPages.map((p, i) =>
                p === "..." ? (
                  <span key={`e${i}`} className="text-muted-foreground px-1">
                    …
                  </span>
                ) : (
                  <Button
                    key={p}
                    size="xs"
                    variant={p === historyPage ? "default" : "outline"}
                    onClick={() => handlePageChange(p as number)}
                  >
                    {p}
                  </Button>
                ),
              )}
              <Button
                size="xs"
                variant="outline"
                onClick={() => handlePageChange(historyPage + 1)}
                disabled={historyPage >= historyTotalPages}
              >
                Older →
              </Button>
              <Separator orientation="vertical" className="h-4 mx-1" />
            </>
          )}
          {mode === "live" ? (
            <Button variant="outline" size="sm" onClick={browseHistory}>
              Browse History
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={goLive}
              className="bg-green-700 hover:bg-green-600 text-white border-green-700"
            >
              ● Go Live
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
