"use client";

import { useEffect, useRef, useState, useCallback } from "react";

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

export default function Home() {
  const [logs, setLogs] = useState<SyslogEntry[]>([]);
  const [severity, setSeverity] = useState("");
  const [search, setSearch] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [connected, setConnected] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [pollStatus, setPollStatus] = useState<PollStatus | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

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
    try {
      const res = await fetch("/api/poll", { method: "POST" });
      const data = await res.json();
      if (data.error) {
        setPollStatus((prev) => prev ? { ...prev, lastError: data.error } : null);
      }
      checkStatus();
    } catch {
      // ignore
    }
  }, [checkStatus]);

  // Connect to SSE stream for real-time updates
  const connectStream = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const params = new URLSearchParams({ stream: "true" });
    if (severity) params.set("severity", severity);
    if (search) params.set("search", search);

    const es = new EventSource(`/api/logs?${params}`);
    eventSourceRef.current = es;

    es.onopen = () => setConnected(true);

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
      es.close();
      setTimeout(connectStream, 3000);
    };
  }, [severity, search]);

  useEffect(() => {
    checkStatus();
    connectStream();
    // Poll status every 15s
    const statusInterval = setInterval(checkStatus, 15000);
    return () => {
      eventSourceRef.current?.close();
      clearInterval(statusInterval);
    };
  }, [connectStream, checkStatus]);

  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  const handleClear = async () => {
    await fetch("/api/logs", { method: "DELETE" });
    setLogs([]);
  };

  const notConfigured = pollStatus && !pollStatus.configured;

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100">
      {/* Config banner */}
      {notConfigured && (
        <div className="px-6 py-3 bg-yellow-900/50 border-b border-yellow-700 text-yellow-200 text-sm">
          UniFi not configured. Edit <code className="bg-yellow-900 px-1 rounded">.env.local</code> with your controller URL, username, and password, then restart.
        </div>
      )}

      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 bg-gray-900 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold tracking-tight">UniFi Log Viewer</h1>
          <span
            className={`inline-block w-2.5 h-2.5 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`}
            title={connected ? "Stream connected" : "Stream disconnected"}
          />
          {pollStatus?.polling && (
            <span className="text-xs text-green-400">Polling active</span>
          )}
          {pollStatus?.lastError && (
            <span className="text-xs text-red-400" title={pollStatus.lastError}>
              Error: {pollStatus.lastError.slice(0, 50)}
            </span>
          )}
          <span className="text-sm text-gray-400">{logs.length} entries</span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={startPolling}
            disabled={notConfigured || false}
            className="px-3 py-1.5 text-sm bg-blue-700 hover:bg-blue-600 disabled:bg-gray-700 disabled:text-gray-500 rounded-md transition-colors"
          >
            {pollStatus?.polling ? "Poll Now" : "Start Polling"}
          </button>
          <input
            type="text"
            placeholder="Search logs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="px-3 py-1.5 text-sm bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:border-blue-500 w-64"
          />
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
          <label className="flex items-center gap-1.5 text-sm text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="accent-blue-500"
            />
            Auto-scroll
          </label>
          <button
            onClick={handleClear}
            className="px-3 py-1.5 text-sm bg-red-900 hover:bg-red-800 rounded-md transition-colors"
          >
            Clear
          </button>
        </div>
      </header>

      {/* Log Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm font-mono">
          <thead className="sticky top-0 bg-gray-900 text-gray-400 text-xs uppercase">
            <tr>
              <th className="px-3 py-2 text-left w-44">Time</th>
              <th className="px-3 py-2 text-left w-24">Severity</th>
              <th className="px-3 py-2 text-left w-28">Subsystem</th>
              <th className="px-3 py-2 text-left w-40">Host</th>
              <th className="px-3 py-2 text-left">Message</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-12 text-center text-gray-500">
                  {notConfigured
                    ? "Configure .env.local with your UniFi controller credentials to get started."
                    : "No logs yet. Click \"Start Polling\" to fetch logs from your UniFi controller."}
                </td>
              </tr>
            )}
            {logs.map((log) => (
              <tr
                key={log.id}
                className="border-b border-gray-800/50 hover:bg-gray-900/50 cursor-pointer"
                onClick={() =>
                  setExpandedId(expandedId === log.id ? null : log.id)
                }
              >
                <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap">
                  {log.timestamp}
                </td>
                <td className="px-3 py-1.5">
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLORS[log.severity] || "bg-gray-600 text-white"}`}
                  >
                    {log.severity}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-purple-400">{log.subsystem}</td>
                <td className="px-3 py-1.5 text-blue-400">{log.host}</td>
                <td className="px-3 py-1.5 truncate max-w-xl">
                  {expandedId === log.id ? (
                    <pre className="whitespace-pre-wrap break-all text-xs text-gray-300">
                      {log.raw}
                    </pre>
                  ) : (
                    log.message.slice(0, 200)
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
