import { login, fetchSystemLogs, fetchEvents, isConfigured } from "@/lib/unifi-client";
import { ingestUniFiLogs, loadLogs, getLogCount } from "@/lib/log-store";

loadLogs();

let isPolling = false;
let pollInterval: ReturnType<typeof setInterval> | null = null;
let lastPollTime: string | null = null;
let lastError: string | null = null;
let loggedIn = false;

async function doPoll(): Promise<{ newLogs: number; total: number; error?: string }> {
  try {
    if (!loggedIn) {
      loggedIn = await login();
      if (!loggedIn) {
        lastError = "Login failed - check credentials";
        return { newLogs: 0, total: getLogCount(), error: lastError };
      }
    }

    const [sysLogs, events] = await Promise.all([
      fetchSystemLogs(undefined, 200),
      fetchEvents(200),
    ]);

    const newSys = ingestUniFiLogs(sysLogs);
    const newEvt = ingestUniFiLogs(events);

    lastPollTime = new Date().toISOString();
    lastError = null;

    return { newLogs: newSys + newEvt, total: getLogCount() };
  } catch (err) {
    lastError = err instanceof Error ? err.message : String(err);
    loggedIn = false;
    return { newLogs: 0, total: getLogCount(), error: lastError };
  }
}

// POST /api/poll - start polling or trigger a manual poll
export async function POST() {
  if (!isConfigured()) {
    return Response.json(
      { error: "UniFi not configured. Set UNIFI_CONTROLLER_URL, UNIFI_USERNAME, UNIFI_PASSWORD in .env.local" },
      { status: 400 }
    );
  }

  const result = await doPoll();

  // Start auto-polling if not already running
  if (!isPolling) {
    const intervalSec = parseInt(process.env.UNIFI_POLL_INTERVAL || "10", 10);
    pollInterval = setInterval(doPoll, intervalSec * 1000);
    isPolling = true;
  }

  return Response.json(result);
}

// GET /api/poll - get polling status
export async function GET() {
  return Response.json({
    configured: isConfigured(),
    polling: isPolling,
    lastPollTime,
    lastError,
    logCount: getLogCount(),
  });
}

// DELETE /api/poll - stop polling
export async function DELETE() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  isPolling = false;
  loggedIn = false;
  return Response.json({ ok: true, polling: false });
}
