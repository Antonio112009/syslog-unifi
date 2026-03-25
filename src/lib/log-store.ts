import crypto from "crypto";
import { getDb, migrateFromJson } from "./db";
import type { UniFiLogEntry } from "./unifi-client";
import type { SyslogMessage } from "./syslog-server";

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

export interface PaginatedLogs {
  logs: SyslogEntry[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

let listeners: Set<(entry: SyslogEntry) => void> = new Set();

function rowToEntry(row: Record<string, unknown>): SyslogEntry {
  return {
    id: row.id as string,
    timestamp: row.timestamp as string,
    facility: row.facility as string,
    severity: row.severity as string,
    host: row.host as string,
    message: row.message as string,
    raw: row.raw as string,
    receivedAt: row.received_at as string,
    subsystem: row.subsystem as string,
    key: row.key as string,
  };
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

/** Escape user input for FTS5 MATCH queries */
function ftsEscape(query: string): string {
  return '"' + query.replace(/"/g, '""') + '"';
}

export function loadLogs(): void {
  getDb(); // Ensure DB is initialized
  migrateFromJson();
}

export function ingestUniFiLogs(unifiLogs: UniFiLogEntry[]): number {
  const db = getDb();
  let newCount = 0;

  const sorted = [...unifiLogs].sort((a, b) => a.time - b.time);

  const insert = db.prepare(`
    INSERT OR IGNORE INTO logs (id, timestamp, facility, severity, host, message, raw, received_at, subsystem, key)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const tx = db.transaction(() => {
    for (const log of sorted) {
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

      const result = insert.run(
        entry.id, entry.timestamp, entry.facility, entry.severity, entry.host,
        entry.message, entry.raw, entry.receivedAt, entry.subsystem, entry.key
      );

      if (result.changes > 0) {
        newCount++;
        for (const listener of listeners) {
          listener(entry);
        }
      }
    }
  });

  tx();
  return newCount;
}

export function ingestSyslogMessage(msg: SyslogMessage): number {
  const db = getDb();
  const id = crypto.randomUUID();

  const entry: SyslogEntry = {
    id,
    timestamp: msg.timestamp,
    facility: msg.facility,
    severity: msg.severity,
    host: msg.host,
    message: msg.message,
    raw: msg.raw,
    receivedAt: new Date().toISOString(),
    subsystem: msg.facility,
    key: "",
  };

  const insert = db.prepare(`
    INSERT OR IGNORE INTO logs (id, timestamp, facility, severity, host, message, raw, received_at, subsystem, key)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = insert.run(
    entry.id, entry.timestamp, entry.facility, entry.severity, entry.host,
    entry.message, entry.raw, entry.receivedAt, entry.subsystem, entry.key
  );

  if (result.changes > 0) {
    for (const listener of listeners) {
      listener(entry);
    }
    return 1;
  }
  return 0;
}

/** Get logs with server-side pagination, filtering, and FTS search */
export function getLogs(
  page = 1,
  pageSize = 100,
  severity?: string,
  search?: string,
  source?: string
): PaginatedLogs {
  const db = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  // If there's a search query, use FTS5
  let usesFts = false;
  if (search && search.trim()) {
    usesFts = true;
    conditions.push("logs_fts MATCH ?");
    params.push(ftsEscape(search.trim()));
  }

  if (severity) {
    conditions.push("logs.severity = ?");
    params.push(severity);
  }

  if (source) {
    conditions.push("logs.host LIKE ?");
    params.push(`%${source}%`);
  }

  const joinClause = usesFts
    ? "INNER JOIN logs_fts ON logs.rowid = logs_fts.rowid"
    : "";
  const whereClause = conditions.length > 0
    ? "WHERE " + conditions.join(" AND ")
    : "";

  // Get total count
  const countSql = `SELECT COUNT(*) as c FROM logs ${joinClause} ${whereClause}`;
  const total = (db.prepare(countSql).get(...params) as { c: number }).c;

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.max(1, Math.min(page, totalPages));
  const offset = (safePage - 1) * pageSize;

  // Page 1 = newest, so ORDER BY rowid DESC, then reverse for display
  const dataSql = `
    SELECT logs.* FROM logs ${joinClause} ${whereClause}
    ORDER BY logs.rowid DESC
    LIMIT ? OFFSET ?
  `;
  const rows = db.prepare(dataSql).all(...params, pageSize, offset) as Record<string, unknown>[];

  // Reverse so within a page, oldest is at top (natural reading order)
  const logs = rows.map(rowToEntry).reverse();

  return { logs, total, page: safePage, pageSize, totalPages };
}

/** Get the most recent N logs (for SSE init) */
export function getRecentLogs(
  limit = 200,
  severity?: string,
  search?: string,
  source?: string
): SyslogEntry[] {
  const result = getLogs(1, limit, severity, search, source);
  return result.logs;
}

export function clearLogs(): void {
  const db = getDb();
  db.exec("DELETE FROM logs");
}

export function subscribe(listener: (entry: SyslogEntry) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getLogCount(): number {
  const db = getDb();
  return (db.prepare("SELECT COUNT(*) as c FROM logs").get() as { c: number }).c;
}
