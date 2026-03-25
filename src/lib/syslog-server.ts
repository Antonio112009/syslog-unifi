import dgram from "dgram";
import net from "net";

// Re-export for use by log-store
export interface SyslogMessage {
  facility: string;
  severity: string;
  host: string;
  message: string;
  timestamp: string;
  raw: string;
}

type SyslogListener = (msg: SyslogMessage) => void;

const SYSLOG_PORT = parseInt(process.env.SYSLOG_PORT || "5514", 10);

// Use globalThis to survive HMR reloads in dev mode
const globalSyslog = globalThis as unknown as {
  __syslogUdp?: dgram.Socket;
  __syslogTcp?: net.Server;
  __syslogStarted?: boolean;
  __syslogListeners?: Set<SyslogListener>;
};

if (!globalSyslog.__syslogListeners) {
  globalSyslog.__syslogListeners = new Set();
}
const syslogListeners = globalSyslog.__syslogListeners;

// RFC 3164 facility codes
const FACILITIES = [
  "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
  "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
  "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

// RFC 3164 severity codes
const SEVERITIES = [
  "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
];

function parseSyslogMessage(raw: string, remoteAddress: string): SyslogMessage {
  // RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG
  // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
  const trimmed = raw.trim();

  let facility = "system";
  let severity = "info";
  let host = remoteAddress;
  let message = trimmed;
  let timestamp = new Date().toISOString();

  // Parse PRI field: <number>
  const priMatch = trimmed.match(/^<(\d{1,3})>(.*)/s);
  if (priMatch) {
    const pri = parseInt(priMatch[1], 10);
    const facilityCode = pri >> 3;
    const severityCode = pri & 7;
    facility = FACILITIES[facilityCode] || `facility${facilityCode}`;
    severity = SEVERITIES[severityCode] || "info";
    message = priMatch[2];
  }

  // Try RFC 5424: <PRI>1 TIMESTAMP HOSTNAME ...
  const rfc5424Match = message.match(
    /^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]|-)\s*(.*)/s
  );
  if (rfc5424Match) {
    timestamp = rfc5424Match[1] !== "-" ? rfc5424Match[1] : timestamp;
    host = rfc5424Match[2] !== "-" ? rfc5424Match[2] : host;
    message = rfc5424Match[6] || `${rfc5424Match[3]}[${rfc5424Match[4]}]: ${rfc5424Match[6]}`;
    return { facility, severity, host, message: message.trim(), timestamp, raw: trimmed };
  }

  // UniFi CEF format: Mon DD HH:MM:SS <ISO-timestamp> <device name> CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extensions
  const cefMatch = message.match(
    /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\d{4}-\d{2}-\d{2}T\S+)\s+(.*?)\s+CEF:(\d+\|.*)/s
  );
  if (cefMatch) {
    timestamp = cefMatch[2]; // Use the ISO timestamp
    host = cefMatch[3]; // Device name (can have spaces)
    const cefBody = cefMatch[4];
    // Parse CEF: version|vendor|product|productVersion|eventId|name|severity|extensions
    const cefParts = cefBody.split("|");
    const cefName = cefParts.length > 5 ? cefParts[5] : "";
    const cefSeverityNum = cefParts.length > 6 ? parseInt(cefParts[6], 10) : 5;
    // Map CEF severity (0-10) to syslog severity
    if (cefSeverityNum <= 3) severity = "info";
    else if (cefSeverityNum <= 6) severity = "warning";
    else if (cefSeverityNum <= 8) severity = "error";
    else severity = "critical";
    // Extract msg= from extensions
    const extensions = cefParts.length > 7 ? cefParts.slice(7).join("|") : "";
    const msgMatch = extensions.match(/\bmsg=(.+?)(?:\s+\w+=|$)/s);
    message = msgMatch ? msgMatch[1].trim() : cefName || cefBody;
    // Extract subsystem from product
    if (cefParts.length > 2) {
      facility = cefParts[2]; // e.g. "UniFi OS"
    }
    return { facility, severity, host, message, timestamp, raw: trimmed };
  }

  // Try RFC 3164: <PRI>Mon DD HH:MM:SS HOSTNAME MSG
  const rfc3164Match = message.match(
    /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)/s
  );
  if (rfc3164Match) {
    const year = new Date().getFullYear();
    const parsed = new Date(`${rfc3164Match[1]} ${year}`);
    if (!isNaN(parsed.getTime())) {
      timestamp = parsed.toISOString();
    }
    host = rfc3164Match[2];
    message = rfc3164Match[3];
    return { facility, severity, host, message: message.trim(), timestamp, raw: trimmed };
  }

  // UniFi sometimes sends: <PRI>HOSTNAME TAG[PID]: message
  const simpleMatch = message.match(/^(\S+)\s+(.*)/s);
  if (simpleMatch) {
    host = simpleMatch[1];
    message = simpleMatch[2];
  }

  return { facility, severity, host, message: message.trim(), timestamp, raw: trimmed };
}

function handleSyslogData(data: Buffer, remoteAddress: string) {
  const raw = data.toString("utf-8");
  // Syslog can have multiple messages in one packet (newline-separated)
  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  for (const line of lines) {
    const msg = parseSyslogMessage(line, remoteAddress);
    for (const listener of syslogListeners) {
      listener(msg);
    }
  }
}

export function startSyslogServer(): { port: number } {
  if (globalSyslog.__syslogStarted) return { port: SYSLOG_PORT };
  globalSyslog.__syslogStarted = true;

  console.log(`[syslog] Starting syslog server on port ${SYSLOG_PORT}...`);

  // Close any previous servers (HMR cleanup)
  if (globalSyslog.__syslogUdp) {
    try { globalSyslog.__syslogUdp.close(); } catch { /* ignore */ }
  }
  if (globalSyslog.__syslogTcp) {
    try { globalSyslog.__syslogTcp.close(); } catch { /* ignore */ }
  }

  // UDP syslog server (most common)
  try {
    const udp = dgram.createSocket({ type: "udp4", reuseAddr: true });
    udp.on("message", (data, rinfo) => {
      console.log(`[syslog] UDP message from ${rinfo.address}:${rinfo.port} (${data.length} bytes)`);
      handleSyslogData(data, rinfo.address);
    });
    udp.on("error", (err) => {
      console.error(`[syslog] UDP server error: ${err.message}`);
      if ((err as NodeJS.ErrnoException).code === "EACCES") {
        console.error(`[syslog] Port ${SYSLOG_PORT} requires elevated privileges. Try a port > 1024.`);
      }
    });
    udp.bind(SYSLOG_PORT, () => {
      console.log(`[syslog] UDP server listening on port ${SYSLOG_PORT}`);
    });
    globalSyslog.__syslogUdp = udp;
  } catch (err) {
    console.error(`[syslog] Failed to create UDP server:`, err);
  }

  // TCP syslog server (some devices use TCP)
  try {
    const tcp = net.createServer((socket) => {
      console.log(`[syslog] TCP connection from ${socket.remoteAddress}`);
      let buffer = "";
      socket.on("data", (data) => {
        buffer += data.toString("utf-8");
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (line.trim()) {
            handleSyslogData(Buffer.from(line), socket.remoteAddress || "unknown");
          }
        }
      });
      socket.on("end", () => {
        if (buffer.trim()) {
          handleSyslogData(Buffer.from(buffer), socket.remoteAddress || "unknown");
        }
      });
      socket.on("error", () => {
        // client disconnect, ignore
      });
    });
  tcp.on("error", (err) => {
    console.error(`[syslog] TCP server error: ${err.message}`);
  });
  tcp.listen(SYSLOG_PORT, () => {
    console.log(`[syslog] TCP server listening on port ${SYSLOG_PORT}`);
  });
  globalSyslog.__syslogTcp = tcp;
  } catch (err) {
    console.error(`[syslog] Failed to create TCP server:`, err);
  }

  return { port: SYSLOG_PORT };
}

export function onSyslogMessage(listener: SyslogListener): () => void {
  syslogListeners.add(listener);
  return () => syslogListeners.delete(listener);
}

export function getSyslogStatus(): { running: boolean; port: number } {
  return { running: globalSyslog.__syslogStarted ?? false, port: SYSLOG_PORT };
}
