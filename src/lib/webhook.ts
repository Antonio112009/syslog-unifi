import type { FirewallFields } from "./db";

const WEBHOOK_URL = process.env.SYSLOG_WEBHOOK_URL || "";
const THRESHOLD = parseInt(process.env.SYSLOG_WEBHOOK_THRESHOLD || "10", 10);
const WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes between alerts for same key

interface WindowEntry {
  count: number;
  firstSeen: number;
  lastAlerted: number;
}

const windows = new Map<string, WindowEntry>();

function cleanup() {
  const now = Date.now();
  for (const [key, entry] of windows) {
    if (now - entry.firstSeen > WINDOW_MS + COOLDOWN_MS) {
      windows.delete(key);
    }
  }
}

export function checkWebhookAlert(
  fw: FirewallFields,
  host: string,
  timestamp: string
): void {
  if (!WEBHOOK_URL || !fw.fw_action) return;
  if (fw.fw_action === "Allow") return; // only alert on Drop/Reject

  const key = `${fw.fw_action}:${fw.fw_src}`;
  const now = Date.now();
  const entry = windows.get(key);

  if (!entry) {
    windows.set(key, { count: 1, firstSeen: now, lastAlerted: 0 });
    return;
  }

  // Reset window if expired
  if (now - entry.firstSeen > WINDOW_MS) {
    windows.set(key, { count: 1, firstSeen: now, lastAlerted: entry.lastAlerted });
    return;
  }

  entry.count++;

  if (entry.count >= THRESHOLD && now - entry.lastAlerted > COOLDOWN_MS) {
    entry.lastAlerted = now;
    sendAlert({
      action: fw.fw_action,
      sourceIp: fw.fw_src,
      destinationIp: fw.fw_dst,
      protocol: fw.fw_proto,
      count: entry.count,
      windowMinutes: Math.round(WINDOW_MS / 60000),
      host,
      timestamp,
    }).catch((err) => {
      console.error("[webhook] Failed to send alert:", err);
    });
  }

  // Periodic cleanup
  if (windows.size > 1000) cleanup();
}

async function sendAlert(payload: Record<string, unknown>) {
  console.log(`[webhook] Alerting: ${payload.count}x ${payload.action} from ${payload.sourceIp}`);
  await fetch(WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      type: "syslog-alert",
      ...payload,
      sentAt: new Date().toISOString(),
    }),
  });
}
