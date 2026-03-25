import Database from "better-sqlite3";
import path from "path";
import fs from "fs";

const DATA_DIR = path.join(process.cwd(), "data");
const DB_PATH = path.join(DATA_DIR, "syslogs.db");

let _db: Database.Database | null = null;

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
      key TEXT NOT NULL
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
