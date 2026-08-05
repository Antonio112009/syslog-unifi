import crypto from "crypto";
import path from "path";
import fs from "fs";
import Database from "better-sqlite3";
import { getDb, migrateFromJson, extractFirewallFields } from "./db";
import { checkWebhookAlert } from "./webhook";
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

let _insertStmt: Database.Statement | null = null;

function getInsertStmt() {
  if (!_insertStmt) {
    _insertStmt = getDb().prepare(`
      INSERT OR IGNORE INTO logs (id, timestamp, facility, severity, host, message, raw, received_at, subsystem, key, fw_action, fw_proto, fw_src, fw_dst, fw_spt, fw_dpt, fw_rule, fw_rule_descr)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
  }
  return _insertStmt;
}

export function ingestSyslogMessage(msg: SyslogMessage): number {
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

  const fw = extractFirewallFields(msg.message, msg.raw);
  const insert = getInsertStmt();

  const result = insert.run(
    entry.id, entry.timestamp, entry.facility, entry.severity, entry.host,
    entry.message, entry.raw, entry.receivedAt, entry.subsystem, entry.key,
    fw.fw_action, fw.fw_proto, fw.fw_src, fw.fw_dst, fw.fw_spt, fw.fw_dpt, fw.fw_rule, fw.fw_rule_descr
  );

  if (result.changes > 0) {
    for (const listener of listeners) {
      listener(entry);
    }
    checkWebhookAlert(fw, entry.host, entry.timestamp);
    _insertCounter++;
    if (_insertCounter % 1000 === 0) purgeOldLogs();
    return 1;
  }
  return 0;
}

let _insertCounter = 0;

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
    conditions.push("logs.fw_action != ''");
  }

  // Firewall field filters — use indexed columns
  if (filterOptions) {
    if (filterOptions.action) {
      conditions.push("logs.fw_action = ?");
      params.push(filterOptions.action);
    }

    if (filterOptions.proto) {
      conditions.push("logs.fw_proto = ?");
      params.push(filterOptions.proto);
    }

    if (filterOptions.rule) {
      conditions.push("(logs.fw_rule LIKE ? OR logs.fw_rule_descr LIKE ?)");
      params.push(`%${filterOptions.rule}%`, `%${filterOptions.rule}%`);
    }

    const hasSrc = !!(filterOptions.srcIp || filterOptions.srcPort);
    const hasDst = !!(filterOptions.dstIp || filterOptions.dstPort);

    if (hasSrc || hasDst) {
      const srcParts: string[] = [];
      const srcParams: unknown[] = [];
      if (filterOptions.srcIp) {
        srcParts.push("logs.fw_src LIKE ?");
        srcParams.push(`%${filterOptions.srcIp}%`);
      }
      if (filterOptions.srcPort) {
        srcParts.push("logs.fw_spt = ?");
        srcParams.push(filterOptions.srcPort);
      }

      const dstParts: string[] = [];
      const dstParams: unknown[] = [];
      if (filterOptions.dstIp) {
        dstParts.push("logs.fw_dst LIKE ?");
        dstParams.push(`%${filterOptions.dstIp}%`);
      }
      if (filterOptions.dstPort) {
        dstParts.push("logs.fw_dpt = ?");
        dstParams.push(filterOptions.dstPort);
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

  // Page 1 = newest, ORDER BY rowid DESC (newest first)
  const dataSql = `
    SELECT logs.* FROM logs ${joinClause} ${whereClause}
    ORDER BY logs.rowid DESC
    LIMIT ? OFFSET ?
  `;
  const rows = db.prepare(dataSql).all(...params, pageSize, offset) as Record<string, unknown>[];

  const logs = rows.map(rowToEntry);

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

let _rulesCache: { rules: string[]; timestamp: number } | null = null;
const RULES_CACHE_TTL = 10_000; // 10 seconds

/** Get all distinct rule names from firewall log messages */
export function getDistinctRules(): string[] {
  const now = Date.now();
  if (_rulesCache && now - _rulesCache.timestamp < RULES_CACHE_TTL) {
    return _rulesCache.rules;
  }

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT DISTINCT CASE WHEN fw_rule_descr != '' THEN fw_rule_descr ELSE fw_rule END AS name
       FROM logs WHERE fw_action != '' ORDER BY name`
    )
    .all() as { name: string }[];

  const rules = rows.map((r) => r.name);
  _rulesCache = { rules, timestamp: now };
  return rules;
}

export function clearLogs(): void {
  _rulesCache = null;
  _protosCache = null;
  const db = getDb();
  db.exec("DELETE FROM logs");
  db.pragma("wal_checkpoint(TRUNCATE)");
  db.exec("VACUUM");
}

/** Delete logs matching the given filter criteria. Returns number of deleted rows. */
export function deleteFilteredLogs(filterOptions: FilterOptions): number {
  const db = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (filterOptions.action) {
    conditions.push("fw_action = ?");
    params.push(filterOptions.action);
  }
  if (filterOptions.proto) {
    conditions.push("fw_proto = ?");
    params.push(filterOptions.proto);
  }
  if (filterOptions.rule) {
    conditions.push("(fw_rule LIKE ? OR fw_rule_descr LIKE ?)");
    params.push(`%${filterOptions.rule}%`, `%${filterOptions.rule}%`);
  }

  const hasSrc = !!(filterOptions.srcIp || filterOptions.srcPort);
  const hasDst = !!(filterOptions.dstIp || filterOptions.dstPort);

  if (hasSrc || hasDst) {
    const srcParts: string[] = [];
    const srcParams: unknown[] = [];
    if (filterOptions.srcIp) {
      srcParts.push("fw_src LIKE ?");
      srcParams.push(`%${filterOptions.srcIp}%`);
    }
    if (filterOptions.srcPort) {
      srcParts.push("fw_spt = ?");
      srcParams.push(filterOptions.srcPort);
    }

    const dstParts: string[] = [];
    const dstParams: unknown[] = [];
    if (filterOptions.dstIp) {
      dstParts.push("fw_dst LIKE ?");
      dstParams.push(`%${filterOptions.dstIp}%`);
    }
    if (filterOptions.dstPort) {
      dstParts.push("fw_dpt = ?");
      dstParams.push(filterOptions.dstPort);
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

  if (conditions.length === 0) return 0;

  const sql = `DELETE FROM logs WHERE ${conditions.join(" AND ")}`;
  const result = db.prepare(sql).run(...params);
  _rulesCache = null;
  return result.changes;
}

export function subscribe(listener: (entry: SyslogEntry) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

// --- Retention ---

const LOG_RETENTION_DAYS = parseInt(process.env.LOG_RETENTION_DAYS || "0", 10);

export function purgeOldLogs(): number {
  if (LOG_RETENTION_DAYS <= 0) return 0;
  const db = getDb();
  const cutoff = new Date(Date.now() - LOG_RETENTION_DAYS * 86400000).toISOString();
  const result = db.prepare("DELETE FROM logs WHERE timestamp < ?").run(cutoff);
  if (result.changes > 0) {
    console.log(`[retention] Purged ${result.changes} logs older than ${LOG_RETENTION_DAYS} days`);
    _rulesCache = null;
  }
  return result.changes;
}

// --- Dynamic Protocols ---

let _protosCache: { protocols: string[]; timestamp: number } | null = null;

export function getDistinctProtocols(): string[] {
  const now = Date.now();
  if (_protosCache && now - _protosCache.timestamp < RULES_CACHE_TTL) {
    return _protosCache.protocols;
  }
  const db = getDb();
  const rows = db
    .prepare("SELECT DISTINCT fw_proto AS name FROM logs WHERE fw_proto != '' ORDER BY name")
    .all() as { name: string }[];
  const protocols = rows.map((r) => r.name);
  _protosCache = { protocols, timestamp: now };
  return protocols;
}

// --- DB Stats ---

const DATA_DIR = path.join(process.cwd(), "data");
const DB_PATH = path.join(DATA_DIR, "syslogs.db");

export function getDbStats(): { totalLogs: number; dbSizeBytes: number; dbSizeMb: string } {
  const db = getDb();
  const total = (db.prepare("SELECT COUNT(*) as c FROM logs").get() as { c: number }).c;
  let sizeBytes = 0;
  try {
    const stat = fs.statSync(DB_PATH);
    sizeBytes = stat.size;
  } catch {
    // file may not exist yet
  }
  return {
    totalLogs: total,
    dbSizeBytes: sizeBytes,
    dbSizeMb: (sizeBytes / (1024 * 1024)).toFixed(1),
  };
}
