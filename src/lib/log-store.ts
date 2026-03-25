import crypto from "crypto";
import { getDb, migrateFromJson } from "./db";
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

const listeners: Set<(entry: SyslogEntry) => void> = new Set();

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

/** Escape user input for FTS5 MATCH queries */
function ftsEscape(query: string): string {
  return '"' + query.replace(/"/g, '""') + '"';
}

export function loadLogs(): void {
  getDb(); // Ensure DB is initialized
  migrateFromJson();
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

export interface FilterOptions {
  action?: string;
  proto?: string;
  srcIp?: string;
  srcPort?: string;
  dstIp?: string;
  dstPort?: string;
  rule?: string;
  ipMatch?: "and" | "or";
}

/** Get logs with server-side pagination, filtering, and FTS search */
export function getLogs(
  page = 1,
  pageSize = 100,
  severity?: string,
  search?: string,
  source?: string,
  firewallOnly?: boolean,
  filterOptions?: FilterOptions
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

  if (firewallOnly) {
    conditions.push("(logs.message LIKE '[%-A-%]%' OR logs.message LIKE '[%-D-%]%' OR logs.message LIKE '[%-R-%]%')");
  }

  // Firewall field filters
  if (filterOptions) {
    if (filterOptions.action) {
      const actionCode: Record<string, string> = { Allow: "A", Drop: "D", Reject: "R" };
      const code = actionCode[filterOptions.action];
      if (code) {
        conditions.push("logs.message LIKE ?");
        params.push(`[%-${code}-%]%`);
      }
    }

    if (filterOptions.proto) {
      conditions.push("logs.message LIKE ?");
      params.push(`%PROTO=${filterOptions.proto}%`);
    }

    if (filterOptions.rule) {
      conditions.push("(logs.message LIKE ? OR logs.message LIKE ?)");
      params.push(`%${filterOptions.rule}%`, `%DESCR="%${filterOptions.rule}%"%`);
    }

    const hasSrc = !!(filterOptions.srcIp || filterOptions.srcPort);
    const hasDst = !!(filterOptions.dstIp || filterOptions.dstPort);

    if (hasSrc || hasDst) {
      const srcParts: string[] = [];
      const srcParams: unknown[] = [];
      if (filterOptions.srcIp) {
        srcParts.push("logs.message LIKE ?");
        srcParams.push(`%SRC=%${filterOptions.srcIp}%`);
      }
      if (filterOptions.srcPort) {
        srcParts.push("logs.message LIKE ?");
        srcParams.push(`%SPT=${filterOptions.srcPort} %`);
      }

      const dstParts: string[] = [];
      const dstParams: unknown[] = [];
      if (filterOptions.dstIp) {
        dstParts.push("logs.message LIKE ?");
        dstParams.push(`%DST=%${filterOptions.dstIp}%`);
      }
      if (filterOptions.dstPort) {
        dstParts.push("logs.message LIKE ?");
        dstParams.push(`%DPT=${filterOptions.dstPort} %`);
      }

      const srcCond = srcParts.length > 0 ? `(${srcParts.join(" AND ")})` : null;
      const dstCond = dstParts.length > 0 ? `(${dstParts.join(" AND ")})` : null;

      if (filterOptions.ipMatch === "or" && srcCond && dstCond) {
        conditions.push(`(${srcCond} OR ${dstCond})`);
        params.push(...srcParams, ...dstParams);
      } else {
        if (srcCond) {
          conditions.push(srcCond);
          params.push(...srcParams);
        }
        if (dstCond) {
          conditions.push(dstCond);
          params.push(...dstParams);
        }
      }
    }
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
  source?: string,
  firewallOnly?: boolean
): SyslogEntry[] {
  const result = getLogs(1, limit, severity, search, source, firewallOnly);
  return result.logs;
}

/** Get all distinct rule names from firewall log messages */
export function getDistinctRules(): string[] {
  const db = getDb();
  // Grab every distinct message that looks like a firewall log
  const rows = db
    .prepare(
      `SELECT DISTINCT message FROM logs
       WHERE message LIKE '[%-A-%]%' OR message LIKE '[%-D-%]%' OR message LIKE '[%-R-%]%'`
    )
    .all() as { message: string }[];

  const seen = new Set<string>();
  const descrRe = /DESCR="([^"]+)"/;
  const ruleRe = /^\[([^\]]+)\]/;
  for (const { message } of rows) {
    const dm = descrRe.exec(message);
    if (dm) {
      seen.add(dm[1]);
    } else {
      const rm = ruleRe.exec(message);
      if (rm) seen.add(rm[1]);
    }
  }
  return Array.from(seen).sort();
}

export function clearLogs(): void {
  const db = getDb();
  db.exec("DELETE FROM logs");
}

export function subscribe(listener: (entry: SyslogEntry) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
