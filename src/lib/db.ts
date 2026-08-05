import Database from "better-sqlite3";
import path from "path";
import fs from "fs";
import { parseFirewallMessage } from "./firewall-parser";

const DATA_DIR = path.join(process.cwd(), "data");
const DB_PATH = path.join(DATA_DIR, "syslogs.db");

let _db: Database.Database | null = null;

export interface FirewallFields {
  fw_action: string;
  fw_proto: string;
  fw_src: string;
  fw_dst: string;
  fw_spt: string;
  fw_dpt: string;
  fw_rule: string;
  fw_rule_descr: string;
}

/** Extract firewall fields from a syslog message. Returns empty strings for non-firewall messages. */
export function extractFirewallFields(message: string, raw = ""): FirewallFields {
  const empty: FirewallFields = { fw_action: "", fw_proto: "", fw_src: "", fw_dst: "", fw_spt: "", fw_dpt: "", fw_rule: "", fw_rule_descr: "" };
  const parsed = parseFirewallMessage(message) || (raw ? parseFirewallMessage(raw) : null);
  if (!parsed) return empty;

  return {
    fw_action: parsed.action,
    fw_proto: parsed.proto,
    fw_src: parsed.src,
    fw_dst: parsed.dst,
    fw_spt: parsed.spt,
    fw_dpt: parsed.dpt,
    fw_rule: parsed.rule,
    fw_rule_descr: parsed.descr,
  };
}

function backfillFirewallColumns(db: Database.Database): void {
  const rows = db.prepare(
    `SELECT rowid, message, raw FROM logs
     WHERE fw_action = '' AND (
       message LIKE '[%-A-%]%' OR message LIKE '[%-D-%]%' OR message LIKE '[%-R-%]%'
       OR ((message LIKE '%CEF:%' OR raw LIKE '%CEF:%') AND (message LIKE '% act=%' OR raw LIKE '% act=%'))
     )`
  ).all() as { rowid: number; message: string; raw: string }[];
  if (rows.length === 0) return;
  const update = db.prepare(
    `UPDATE logs SET fw_action=?, fw_proto=?, fw_src=?, fw_dst=?, fw_spt=?, fw_dpt=?, fw_rule=?, fw_rule_descr=? WHERE rowid=?`
  );
  const tx = db.transaction(() => {
    for (const row of rows) {
      const fw = extractFirewallFields(row.message, row.raw);
      if (!fw.fw_action) continue;
      update.run(fw.fw_action, fw.fw_proto, fw.fw_src, fw.fw_dst, fw.fw_spt, fw.fw_dpt, fw.fw_rule, fw.fw_rule_descr, row.rowid);
    }
  });
  tx();
  console.log(`[db] Backfilled firewall columns for ${rows.length} rows`);
}

export function getDb(): Database.Database {
  if (_db) return _db;

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");

  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS logs (
      rowid INTEGER PRIMARY KEY AUTOINCREMENT,
      id TEXT UNIQUE NOT NULL,
      timestamp TEXT NOT NULL,
      facility TEXT NOT NULL,
      severity TEXT NOT NULL,
      host TEXT NOT NULL,
      message TEXT NOT NULL,
      raw TEXT NOT NULL,
      received_at TEXT NOT NULL,
      subsystem TEXT NOT NULL,
      key TEXT NOT NULL,
      fw_action TEXT NOT NULL DEFAULT '',
      fw_proto TEXT NOT NULL DEFAULT '',
      fw_src TEXT NOT NULL DEFAULT '',
      fw_dst TEXT NOT NULL DEFAULT '',
      fw_spt TEXT NOT NULL DEFAULT '',
      fw_dpt TEXT NOT NULL DEFAULT '',
      fw_rule TEXT NOT NULL DEFAULT '',
      fw_rule_descr TEXT NOT NULL DEFAULT ''
    );

    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
    CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host);

    CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
      message, host, subsystem, key,
      content='logs',
      content_rowid='rowid'
    );

    CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
      INSERT INTO logs_fts(rowid, message, host, subsystem, key)
      VALUES (new.rowid, new.message, new.host, new.subsystem, new.key);
    END;

    CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
      INSERT INTO logs_fts(logs_fts, rowid, message, host, subsystem, key)
      VALUES('delete', old.rowid, old.message, old.host, old.subsystem, old.key);
    END;
  `);

  // Migration: add firewall columns to existing databases
  const cols = db.pragma("table_info(logs)") as { name: string }[];
  const colNames = new Set(cols.map((c) => c.name));
  if (!colNames.has("fw_action")) {
    db.exec(`
      ALTER TABLE logs ADD COLUMN fw_action TEXT NOT NULL DEFAULT '';
      ALTER TABLE logs ADD COLUMN fw_proto TEXT NOT NULL DEFAULT '';
      ALTER TABLE logs ADD COLUMN fw_src TEXT NOT NULL DEFAULT '';
      ALTER TABLE logs ADD COLUMN fw_dst TEXT NOT NULL DEFAULT '';
      ALTER TABLE logs ADD COLUMN fw_spt TEXT NOT NULL DEFAULT '';
      ALTER TABLE logs ADD COLUMN fw_dpt TEXT NOT NULL DEFAULT '';
      ALTER TABLE logs ADD COLUMN fw_rule TEXT NOT NULL DEFAULT '';
      ALTER TABLE logs ADD COLUMN fw_rule_descr TEXT NOT NULL DEFAULT '';
      CREATE INDEX IF NOT EXISTS idx_logs_fw_action ON logs(fw_action) WHERE fw_action != '';
      CREATE INDEX IF NOT EXISTS idx_logs_fw_proto ON logs(fw_proto) WHERE fw_proto != '';
      CREATE INDEX IF NOT EXISTS idx_logs_fw_rule ON logs(fw_rule) WHERE fw_rule != '';
    `);
  }

  // Create firewall indexes (after migration ensures columns exist)
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_logs_fw_action ON logs(fw_action) WHERE fw_action != '';
    CREATE INDEX IF NOT EXISTS idx_logs_fw_proto ON logs(fw_proto) WHERE fw_proto != '';
    CREATE INDEX IF NOT EXISTS idx_logs_fw_rule ON logs(fw_rule) WHERE fw_rule != '';
  `);

  // Backfill newly supported firewall formats without touching existing rows.
  backfillFirewallColumns(db);

  _db = db;
  return db;
}

/** Migrate existing JSON logs into SQLite (one-time) */
export function migrateFromJson(): void {
  const jsonPath = path.join(DATA_DIR, "syslogs.json");
  if (!fs.existsSync(jsonPath)) return;

  const db = getDb();
  const count = (db.prepare("SELECT COUNT(*) as c FROM logs").get() as { c: number }).c;
  if (count > 0) {
    // Already have data, skip migration
    // Delete old JSON file
    fs.unlinkSync(jsonPath);
    return;
  }

  try {
    const raw = fs.readFileSync(jsonPath, "utf-8");
    const logs = JSON.parse(raw) as Array<{
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
    }>;

    const insert = db.prepare(`
      INSERT OR IGNORE INTO logs (id, timestamp, facility, severity, host, message, raw, received_at, subsystem, key)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const tx = db.transaction(() => {
      for (const log of logs) {
        insert.run(
          log.id, log.timestamp, log.facility, log.severity, log.host,
          log.message, log.raw, log.receivedAt, log.subsystem, log.key
        );
      }
    });
    tx();

    console.log(`[db] Migrated ${logs.length} logs from JSON to SQLite`);
    fs.unlinkSync(jsonPath);
  } catch (err) {
    console.error("[db] Failed to migrate JSON logs:", err);
  }
}
