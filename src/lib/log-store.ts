import fs from "fs";
import path from "path";
import type { UniFiLogEntry } from "./unifi-client";

export interface SyslogEntry {
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

const MAX_LOGS = 10000;
const DATA_DIR = path.join(process.cwd(), "data");
const LOG_FILE = path.join(DATA_DIR, "syslogs.json");

let logs: SyslogEntry[] = [];
let seenIds = new Set<string>();
let listeners: Set<(entry: SyslogEntry) => void> = new Set();

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

export function loadLogs(): void {
  ensureDataDir();
  try {
    if (fs.existsSync(LOG_FILE)) {
      const data = fs.readFileSync(LOG_FILE, "utf-8");
      logs = JSON.parse(data);
      seenIds = new Set(logs.map((l) => l.id));
    }
  } catch {
    logs = [];
    seenIds = new Set();
  }
}

function saveLogs(): void {
  ensureDataDir();
  fs.writeFileSync(LOG_FILE, JSON.stringify(logs));
}

function guessSeverity(key: string, msg: string): string {
  const lower = (key + " " + msg).toLowerCase();
  if (lower.includes("error") || lower.includes("fail")) return "error";
  if (lower.includes("warn")) return "warning";
  if (lower.includes("crit")) return "critical";
  if (lower.includes("alert") || lower.includes("alarm")) return "alert";
  if (lower.includes("disconnect") || lower.includes("lost")) return "warning";
  if (lower.includes("connect") || lower.includes("success")) return "info";
  return "notice";
}

export function ingestUniFiLogs(unifiLogs: UniFiLogEntry[]): number {
  let newCount = 0;

  // Process oldest first so they appear in order
  const sorted = [...unifiLogs].sort((a, b) => a.time - b.time);

  for (const log of sorted) {
    if (seenIds.has(log._id)) continue;

    const entry: SyslogEntry = {
      id: log._id,
      timestamp: log.datetime || new Date(log.time).toISOString(),
      facility: log.subsystem || "system",
      severity: guessSeverity(log.key || "", log.msg || ""),
      host: log.hostname || log.ip || "controller",
      message: log.msg || log.key || "",
      raw: JSON.stringify(log),
      receivedAt: new Date().toISOString(),
      subsystem: log.subsystem || "",
      key: log.key || "",
    };

    logs.push(entry);
    seenIds.add(log._id);
    newCount++;

    for (const listener of listeners) {
      listener(entry);
    }
  }

  if (newCount > 0) {
    if (logs.length > MAX_LOGS) {
      const removed = logs.splice(0, logs.length - MAX_LOGS);
      for (const r of removed) seenIds.delete(r.id);
    }
    saveLogs();
  }

  return newCount;
}

export function getLogs(
  limit = 200,
  severity?: string,
  search?: string
): SyslogEntry[] {
  let filtered = logs;
  if (severity) {
    filtered = filtered.filter((l) => l.severity === severity);
  }
  if (search) {
    const q = search.toLowerCase();
    filtered = filtered.filter(
      (l) =>
        l.message.toLowerCase().includes(q) ||
        l.host.toLowerCase().includes(q) ||
        l.key.toLowerCase().includes(q) ||
        l.subsystem.toLowerCase().includes(q)
    );
  }
  return filtered.slice(-limit);
}

export function clearLogs(): void {
  logs = [];
  seenIds = new Set();
  saveLogs();
}

export function subscribe(listener: (entry: SyslogEntry) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getLogCount(): number {
  return logs.length;
}
