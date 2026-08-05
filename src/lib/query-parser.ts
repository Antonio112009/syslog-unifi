/**
 * Simple query language for log search.
 *
 * Supports:
 *   field=value     — match a specific field (partial, case-insensitive)
 *   "free text"     — search across message, host, and raw
 *   bare words      — same as free text
 *   OR              — logical OR between terms
 *   AND             — logical AND (default between terms)
 *
 * Fields: host, level, severity, facility, message, msg, src, dst, proto, port
 *
 * Examples:
 *   host=Gateway
 *   level=error OR level=warning
 *   src=192.168.1.0 AND dst=10.0.0
 *   proto=TCP port=443
 *   "connection refused"
 */

import type { SyslogEntry } from "@/types/syslog";

interface FieldCondition {
  type: "field";
  field: string;
  value: string;
}

interface TextCondition {
  type: "text";
  value: string;
}

type Condition = FieldCondition | TextCondition;

interface ParsedQuery {
  groups: Condition[][]; // OR-separated groups of AND-joined conditions
}

const FIELD_ALIASES: Record<string, string> = {
  host: "host",
  level: "severity",
  severity: "severity",
  facility: "facility",
  message: "message",
  msg: "message",
  src: "raw",
  dst: "raw",
  proto: "raw",
  port: "raw",
};

// Fields where we search raw with a specific pattern rather than the log field directly
const RAW_SEARCH_FIELDS = new Set(["src", "dst", "proto", "port"]);

// Map field names to raw-log search patterns
function rawPattern(field: string, value: string): string {
  switch (field) {
    case "src":
      return `SRC=${value}`;
    case "dst":
      return `DST=${value}`;
    case "proto":
      return `PROTO=${value}`;
    case "port":
      return value; // port appears as SPT=X or DPT=X, just search the value
    default:
      return value;
  }
}

export function parseQuery(input: string): ParsedQuery {
  const trimmed = input.trim();
  if (!trimmed) return { groups: [] };

  const tokens = tokenize(trimmed);
  const groups: Condition[][] = [];
  let current: Condition[] = [];

  for (const token of tokens) {
    if (token === "OR") {
      if (current.length > 0) {
        groups.push(current);
        current = [];
      }
    } else if (token === "AND") {
      // AND is default, just continue
      continue;
    } else {
      const eqIdx = token.indexOf("=");
      if (eqIdx > 0) {
        const field = token.slice(0, eqIdx).toLowerCase();
        const value = token.slice(eqIdx + 1);
        if (field in FIELD_ALIASES && value) {
          current.push({ type: "field", field, value });
        } else {
          // Unknown field — treat as text search
          current.push({ type: "text", value: token });
        }
      } else {
        current.push({ type: "text", value: token });
      }
    }
  }

  if (current.length > 0) groups.push(current);
  return { groups };
}

function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let i = 0;

  while (i < input.length) {
    // Skip whitespace
    if (input[i] === " " || input[i] === "\t") {
      i++;
      continue;
    }

    // Quoted string
    if (input[i] === '"' || input[i] === "'") {
      const quote = input[i];
      let j = i + 1;
      while (j < input.length && input[j] !== quote) j++;
      tokens.push(input.slice(i + 1, j));
      i = j + 1;
      continue;
    }

    // Regular token (until space)
    let j = i;
    while (j < input.length && input[j] !== " " && input[j] !== "\t") j++;
    tokens.push(input.slice(i, j));
    i = j;
  }

  return tokens;
}

function matchCondition(log: SyslogEntry, cond: Condition): boolean {
  if (cond.type === "text") {
    const q = cond.value.toLowerCase();
    return (
      log.message.toLowerCase().includes(q) ||
      log.host.toLowerCase().includes(q) ||
      log.raw.toLowerCase().includes(q)
    );
  }

  const val = cond.value.toLowerCase();

  if (RAW_SEARCH_FIELDS.has(cond.field)) {
    const pattern = rawPattern(cond.field, cond.value);
    return log.raw.toLowerCase().includes(pattern.toLowerCase());
  }

  const logField = FIELD_ALIASES[cond.field] as keyof SyslogEntry;
  if (!logField) return false;

  const logValue = log[logField];
  if (typeof logValue !== "string") return false;

  return logValue.toLowerCase().includes(val);
}

export function matchQuery(log: SyslogEntry, query: ParsedQuery): boolean {
  if (query.groups.length === 0) return true;

  // OR between groups, AND within each group
  return query.groups.some((group) =>
    group.every((cond) => matchCondition(log, cond))
  );
}
