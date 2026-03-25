"use client";

import { useEffect, useRef, useState, useCallback, useMemo } from "react";

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

interface PollStatus {
  configured: boolean;
  polling: boolean;
  lastPollTime: string | null;
  lastError: string | null;
  logCount: number;
  syslog?: { running: boolean; port: number };
}

const SEVERITY_COLORS: Record<string, string> = {
  emergency: "bg-red-900 text-red-100",
  alert: "bg-red-800 text-red-100",
  critical: "bg-red-700 text-red-100",
  error: "bg-red-600 text-white",
  warning: "bg-yellow-600 text-white",
  notice: "bg-blue-600 text-white",
  info: "bg-green-600 text-white",
  debug: "bg-gray-500 text-white",
};

const ROW_HEIGHT = 32;
const OVERSCAN = 10;

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

function parseFirewallMessage(msg: string): ParsedFirewall | null {
  const ruleMatch = msg.match(/\[([^\]]+)\]/);
  if (!ruleMatch) return null;
  const ruleRaw = ruleMatch[1];
  // e.g. LAN_LOCAL-A-30000 → action A=Allow, D=Drop, R=Reject
  const actionCode = ruleRaw.match(/-([ADR])-/)?.[1] || "";
  const actionMap: Record<string, string> = { A: "Allow", D: "Drop", R: "Reject" };
  const action = actionMap[actionCode] || actionCode;
  const descrMatch = msg.match(/DESCR="([^"]*)"/s);
  const kv = (key: string) => msg.match(new RegExp(`${key}=([^\\s]*)`))?.[1] || "";
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

function isFirewallLog(log: SyslogEntry): boolean {
  return /^\[\w+-(A|D|R)-\d+\]/.test(log.message);
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

function LogRow({ log, isExpanded, onToggle }: { log: SyslogEntry; isExpanded: boolean; onToggle: () => void }) {
  return (
    <div
      className="flex items-start border-b border-gray-800/50 hover:bg-gray-900/50 cursor-pointer font-mono text-sm"
      style={{ minHeight: ROW_HEIGHT }}
      onClick={onToggle}
    >
      <div className="px-3 py-1.5 text-gray-400 whitespace-nowrap w-44 shrink-0">
        {log.timestamp.slice(11, 19)}
      </div>
      <div className="px-3 py-1.5 w-24 shrink-0">
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLORS[log.severity] || "bg-gray-600 text-white"}`}>
          {log.severity}
        </span>
      </div>
      <div className="px-3 py-1.5 text-purple-400 w-28 shrink-0 truncate">{log.subsystem}</div>
      <div className="px-3 py-1.5 text-blue-400 w-40 shrink-0 truncate">{log.host}</div>
      <div className="px-3 py-1.5 flex-1 min-w-0">
        {isExpanded ? (
          <pre className="whitespace-pre-wrap break-all text-xs text-gray-300">{log.raw}</pre>
        ) : (
          <span className="truncate block">{log.message.slice(0, 200)}</span>
        )}
      </div>
    </div>
  );
}

const ACTION_COLORS: Record<string, string> = {
  Allow: "text-green-400",
  Drop: "text-red-400",
  Reject: "text-yellow-400",
};

function FirewallRow({ log, fw, isExpanded, onToggle }: { log: SyslogEntry; fw: ParsedFirewall; isExpanded: boolean; onToggle: () => void }) {
  return (
    <div
      className="flex items-start border-b border-gray-800/50 hover:bg-gray-900/50 cursor-pointer font-mono text-sm"
      style={{ minHeight: ROW_HEIGHT }}
      onClick={onToggle}
    >
      <div className="px-3 py-1.5 text-gray-400 whitespace-nowrap w-24 shrink-0">
        {log.timestamp.slice(11, 19)}
      </div>
      <div className={`px-3 py-1.5 w-20 shrink-0 font-medium ${ACTION_COLORS[fw.action] || "text-gray-300"}`}>
        {fw.action}
      </div>
      <div className="px-3 py-1.5 text-cyan-400 w-72 shrink-0 truncate" title={fw.rule}>
        {fw.descr || fw.rule}
      </div>
      <div className="px-3 py-1.5 text-purple-400 w-20 shrink-0">{fw.iface}</div>
      <div className="px-3 py-1.5 text-blue-300 w-20 shrink-0">{fw.proto}</div>
      <div className="px-3 py-1.5 w-48 shrink-0 truncate" title={fw.src}>
        {fw.src}{fw.spt ? `:${fw.spt}` : ""}
      </div>
      <div className="px-3 py-1.5 w-48 shrink-0 truncate" title={fw.dst}>
        {fw.dst}{fw.dpt ? `:${fw.dpt}` : ""}
      </div>
      <div className="px-3 py-1.5 text-gray-500 w-16 shrink-0">{fw.len}</div>
      <div className="px-2 py-1.5 flex-1 min-w-0">
        {isExpanded ? (
          <pre className="whitespace-pre-wrap break-all text-xs text-gray-300">{log.raw}</pre>
        ) : (
          <span className="truncate block text-gray-500">{fw.rule}</span>
        )}
      </div>
    </div>
  );
}

export default function Home() {
  const [logs, setLogs] = useState<SyslogEntry[]>([]);
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [fwIp, setFwIp] = useState("");
  const [fwIpScope, setFwIpScope] = useState<"either" | "src" | "dst">("either");
  const [autoScroll, setAutoScroll] = useState(true);
  const [connected, setConnected] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [pollStatus, setPollStatus] = useState<PollStatus | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const [isConnecting, setIsConnecting] = useState(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewHeight, setViewHeight] = useState(800);
  const [activeTab, setActiveTab] = useState<"all" | "firewall">("firewall");
  const fwScrollRef = useRef<HTMLDivElement>(null);
  const [fwScrollTop, setFwScrollTop] = useState(0);
  const [fwViewHeight, setFwViewHeight] = useState(800);

  // Check polling status
  const checkStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/poll");
      const data = await res.json();
      setPollStatus(data);
    } catch {
      // ignore
    }
  }, []);

  // Start polling the UniFi API
  const startPolling = useCallback(async () => {
    setIsPolling(true);
    setConnectionError(null);
    try {
      const res = await fetch("/api/poll", { method: "POST" });
      const data = await res.json();
      if (data.error) {
        setConnectionError(data.error);
        setPollStatus((prev) => prev ? { ...prev, lastError: data.error } : null);
      } else {
        setConnectionError(null);
      }
      checkStatus();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Network error";
      setConnectionError(msg);
    } finally {
      setIsPolling(false);
    }
  }, [checkStatus]);

  // Connect to SSE stream for real-time updates
  const connectStream = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }

    setIsConnecting(true);

    const es = new EventSource(`/api/logs?stream=true`);
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setIsConnecting(false);
      setRetryCount(0);
    };

    es.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "init") {
        setLogs(data.logs);
      } else if (data.type === "log") {
        setLogs((prev) => {
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
    checkStatus();
    connectStream();
    const statusInterval = setInterval(checkStatus, 15000);
    return () => {
      eventSourceRef.current?.close();
      if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
      clearInterval(statusInterval);
    };
  }, [connectStream, checkStatus]);

  // Measure container height
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      setViewHeight(entry.contentRect.height);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      const el = scrollRef.current;
      el.scrollTop = el.scrollHeight;
    }
  }, [logs, autoScroll]);

  // Track scroll position for virtual scrolling
  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setScrollTop(el.scrollTop);
    // Disable auto-scroll if user scrolls up
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < ROW_HEIGHT * 2;
    if (!atBottom && autoScroll) setAutoScroll(false);
  }, [autoScroll]);

  // Client-side filtered logs (for All Logs tab)
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (severity && log.severity !== severity) return false;
      if (sourceFilter) {
        const q = sourceFilter.toLowerCase();
        if (!log.host.toLowerCase().includes(q)) return false;
      }
      if (search) {
        const q = search.toLowerCase();
        if (!log.message.toLowerCase().includes(q) && !log.host.toLowerCase().includes(q) && !log.raw.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [logs, severity, search, sourceFilter]);

  // Firewall logs: filter by severity+search first, then by parsed SRC/DST for sourceFilter
  const firewallLogs = useMemo(() => {
    return logs.filter((log) => {
      if (!isFirewallLog(log)) return false;
      if (severity && log.severity !== severity) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!log.message.toLowerCase().includes(q) && !log.host.toLowerCase().includes(q) && !log.raw.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [logs, severity, search]);

  const firewallParsed = useMemo(() => {
    const parsed = firewallLogs.map((log) => ({ log, fw: parseFirewallMessage(log.message)! }));
    if (!fwIp) return parsed;
    const q = fwIp.toLowerCase();
    return parsed.filter(({ fw }) => {
      if (fwIpScope === "src") return fw.src.toLowerCase().includes(q);
      if (fwIpScope === "dst") return fw.dst.toLowerCase().includes(q);
      return fw.src.toLowerCase().includes(q) || fw.dst.toLowerCase().includes(q);
    });
  }, [firewallLogs, fwIp, fwIpScope]);

  // Virtual scroll calculations for all logs tab
  const virtualData = useMemo(() => {
    const totalHeight = filteredLogs.length * ROW_HEIGHT;
    const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
    const endIdx = Math.min(filteredLogs.length, Math.ceil((scrollTop + viewHeight) / ROW_HEIGHT) + OVERSCAN);
    const offsetTop = startIdx * ROW_HEIGHT;
    return { totalHeight, startIdx, endIdx, offsetTop, visibleLogs: filteredLogs.slice(startIdx, endIdx) };
  }, [filteredLogs, scrollTop, viewHeight]);

  // Virtual scroll calculations for firewall tab
  const fwVirtualData = useMemo(() => {
    const totalHeight = firewallParsed.length * ROW_HEIGHT;
    const startIdx = Math.max(0, Math.floor(fwScrollTop / ROW_HEIGHT) - OVERSCAN);
    const endIdx = Math.min(firewallParsed.length, Math.ceil((fwScrollTop + fwViewHeight) / ROW_HEIGHT) + OVERSCAN);
    const offsetTop = startIdx * ROW_HEIGHT;
    return { totalHeight, startIdx, endIdx, offsetTop, visible: firewallParsed.slice(startIdx, endIdx) };
  }, [firewallParsed, fwScrollTop, fwViewHeight]);

  // Measure firewall scroll container
  useEffect(() => {
    const el = fwScrollRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      setFwViewHeight(entry.contentRect.height);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [activeTab]);

  const handleFwScroll = useCallback(() => {
    const el = fwScrollRef.current;
    if (!el) return;
    setFwScrollTop(el.scrollTop);
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < ROW_HEIGHT * 2;
    if (!atBottom && autoScroll) setAutoScroll(false);
  }, [autoScroll]);

  // Auto-scroll firewall tab
  useEffect(() => {
    if (autoScroll && activeTab === "firewall" && fwScrollRef.current) {
      fwScrollRef.current.scrollTop = fwScrollRef.current.scrollHeight;
    }
  }, [firewallLogs, autoScroll, activeTab]);

  const handleClear = async () => {
    await fetch("/api/logs", { method: "DELETE" });
    setLogs([]);
  };
  

  const notConfigured = pollStatus && !pollStatus.configured;
  const hasError = connectionError || pollStatus?.lastError;

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100">
      {/* Config banner */}
      {notConfigured && (
        <div className="px-6 py-3 bg-yellow-900/50 border-b border-yellow-700 text-yellow-200 text-sm">
          UniFi not configured. Edit <code className="bg-yellow-900 px-1 rounded">.env.local</code> with your controller URL, username, and password, then restart.
        </div>
      )}

      {/* Error banner */}
      {hasError && !notConfigured && (
        <div className="px-6 py-3 bg-red-900/50 border-b border-red-700 text-red-200 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg className="h-4 w-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <span>{connectionError || pollStatus?.lastError}</span>
          </div>
          <button
            onClick={() => { setConnectionError(null); startPolling(); }}
            className="px-2 py-1 text-xs bg-red-800 hover:bg-red-700 rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 bg-gray-900 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold tracking-tight">UniFi Log Viewer</h1>
          <span
            className={`inline-flex items-center gap-1.5 text-xs ${connected ? "text-green-400" : isConnecting ? "text-yellow-400" : "text-red-400"}`}
            title={connected ? "Stream connected" : isConnecting ? "Connecting..." : `Disconnected (retry #${retryCount})`}
          >
            {isConnecting ? (
              <Spinner className="text-yellow-400" />
            ) : (
              <span className={`inline-block w-2 h-2 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`} />
            )}
            {isConnecting ? "Connecting" : connected ? "Live" : "Disconnected"}
          </span>
          {pollStatus?.syslog?.running && (
            <span className="inline-flex items-center gap-1 text-xs text-emerald-400" title={`UDP+TCP syslog receiver on port ${pollStatus.syslog.port}`}>
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              Syslog :{pollStatus.syslog.port}
            </span>
          )}
          {pollStatus?.polling && (
            <span className="text-xs text-green-400">Polling active</span>
          )}
          <span className="text-sm text-gray-400">
            {activeTab === "firewall" ? `${firewallLogs.length} firewall` : filteredLogs.length} entries
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={startPolling}
            disabled={notConfigured || isPolling}
            className="px-3 py-1.5 text-sm bg-blue-700 hover:bg-blue-600 disabled:bg-gray-700 disabled:text-gray-500 rounded-md transition-colors inline-flex items-center gap-1.5"
          >
            {isPolling && <Spinner />}
            {isPolling ? "Connecting..." : pollStatus?.polling ? "Poll Now" : "Start Polling"}
          </button>
          <button
            onClick={handleClear}
            className="px-3 py-1.5 text-sm bg-red-900 hover:bg-red-800 rounded-md transition-colors"
          >
            Clear
          </button>
          <label className="flex items-center gap-1.5 text-sm text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="accent-blue-500"
            />
            Auto-scroll
          </label>
        </div>
      </header>

      {/* Filter bar */}
      <div className="flex items-center gap-3 px-6 py-2 bg-gray-900/50 border-b border-gray-800">
        <input
          type="text"
          placeholder="Search logs..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="px-3 py-1.5 text-sm bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:border-blue-500 w-56"
        />
        {activeTab === "firewall" ? (
          <>
            <input
              type="text"
              placeholder="Filter IP address..."
              value={fwIp}
              onChange={(e) => setFwIp(e.target.value)}
              className="px-3 py-1.5 text-sm bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:border-blue-500 w-48"
            />
            <select
              value={fwIpScope}
              onChange={(e) => setFwIpScope(e.target.value as "either" | "src" | "dst")}
              className="px-3 py-1.5 text-sm bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:border-blue-500"
            >
              <option value="either">Source or Dest</option>
              <option value="src">Source only</option>
              <option value="dst">Dest only</option>
            </select>
          </>
        ) : (
          <input
            type="text"
            placeholder="Filter by host..."
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="px-3 py-1.5 text-sm bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:border-blue-500 w-52"
          />
        )}
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="px-3 py-1.5 text-sm bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:border-blue-500"
        >
          <option value="">All Severities</option>
          <option value="emergency">Emergency</option>
          <option value="alert">Alert</option>
          <option value="critical">Critical</option>
          <option value="error">Error</option>
          <option value="warning">Warning</option>
          <option value="notice">Notice</option>
          <option value="info">Info</option>
          <option value="debug">Debug</option>
        </select>
        {(search || sourceFilter || fwIp || severity) && (
          <button
            onClick={() => { setSearch(""); setSourceFilter(""); setFwIp(""); setFwIpScope("either"); setSeverity(""); }}
            className="px-2 py-1 text-xs text-gray-400 hover:text-white transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Tab bar */}
      <div className="flex items-center gap-0 bg-gray-900/80 border-b border-gray-800 px-6 shrink-0">
        <button
          onClick={() => setActiveTab("firewall")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors inline-flex items-center gap-2 ${
            activeTab === "firewall"
              ? "border-orange-500 text-orange-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          Firewall
          {firewallLogs.length > 0 && (
            <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded-full">{firewallLogs.length}</span>
          )}
        </button>
        <button
          onClick={() => setActiveTab("all")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === "all"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          All Logs
        </button>
      </div>

      {/* Tab content */}
      <div className="flex-1 min-h-0 flex flex-col">
        {activeTab === "all" ? (
          <>
            {/* All logs header */}
            <div className="flex bg-gray-900 text-gray-400 text-xs uppercase font-mono shrink-0 border-b border-gray-800">
              <div className="px-3 py-2 w-44 shrink-0">Time</div>
              <div className="px-3 py-2 w-24 shrink-0">Severity</div>
              <div className="px-3 py-2 w-28 shrink-0">Subsystem</div>
              <div className="px-3 py-2 w-40 shrink-0">Host</div>
              <div className="px-3 py-2 flex-1">Message</div>
            </div>
            <div
              ref={scrollRef}
              className="flex-1 overflow-auto min-h-0"
              onScroll={handleScroll}
            >
              {filteredLogs.length === 0 ? (
                <div className="px-3 py-12 text-center text-gray-500">
                  {isConnecting ? (
                    <div className="flex flex-col items-center gap-3">
                      <Spinner className="h-6 w-6 text-gray-400" />
                      <span>Connecting to log stream...</span>
                    </div>
                  ) : notConfigured ? (
                    "Configure .env.local with your UniFi controller credentials to get started."
                  ) : (
                    pollStatus?.syslog?.running
                      ? `Syslog receiver listening on port ${pollStatus.syslog.port}. Configure your UniFi controller's SIEM settings to send logs here.`
                      : "No logs yet. Click \"Start Polling\" to fetch logs from your UniFi controller."
                  )}
                </div>
              ) : (
                <div style={{ height: virtualData.totalHeight, position: "relative" }}>
                  <div style={{ position: "absolute", top: virtualData.offsetTop, left: 0, right: 0 }}>
                    {virtualData.visibleLogs.map((log) => (
                      <LogRow
                        key={log.id}
                        log={log}
                        isExpanded={expandedId === log.id}
                        onToggle={() => setExpandedId(expandedId === log.id ? null : log.id)}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </>
        ) : (
          <>
            {/* Firewall header */}
            <div className="flex bg-gray-900 text-gray-400 text-xs uppercase font-mono shrink-0 border-b border-gray-800">
              <div className="px-3 py-2 w-24 shrink-0">Time</div>
              <div className="px-3 py-2 w-20 shrink-0">Action</div>
              <div className="px-3 py-2 w-72 shrink-0">Rule</div>
              <div className="px-3 py-2 w-20 shrink-0">Iface</div>
              <div className="px-3 py-2 w-20 shrink-0">Proto</div>
              <div className="px-3 py-2 w-48 shrink-0">Source</div>
              <div className="px-3 py-2 w-48 shrink-0">Destination</div>
              <div className="px-3 py-2 w-16 shrink-0">Len</div>
              <div className="px-3 py-2 flex-1">Rule ID</div>
            </div>
            <div
              ref={fwScrollRef}
              className="flex-1 overflow-auto min-h-0"
              onScroll={handleFwScroll}
            >
              {firewallParsed.length === 0 ? (
                <div className="px-3 py-12 text-center text-gray-500">
                  No firewall log entries yet.
                </div>
              ) : (
                <div style={{ height: fwVirtualData.totalHeight, position: "relative" }}>
                  <div style={{ position: "absolute", top: fwVirtualData.offsetTop, left: 0, right: 0 }}>
                    {fwVirtualData.visible.map(({ log, fw }) => (
                      <FirewallRow
                        key={log.id}
                        log={log}
                        fw={fw}
                        isExpanded={expandedId === log.id}
                        onToggle={() => setExpandedId(expandedId === log.id ? null : log.id)}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
