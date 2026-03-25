import { NextRequest } from "next/server";
import { getLogs, getRecentLogs, clearLogs, subscribe, loadLogs, ingestSyslogMessage } from "@/lib/log-store";
import type { FilterOptions } from "@/lib/log-store";
import { startSyslogServer, onSyslogMessage } from "@/lib/syslog-server";

loadLogs();
startSyslogServer();
onSyslogMessage((msg) => {
  ingestSyslogMessage(msg);
});

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const stream = searchParams.get("stream") === "true";
  const severity = searchParams.get("severity") || undefined;
  const search = searchParams.get("search") || undefined;
  const source = searchParams.get("source") || undefined;
  const firewallOnly = searchParams.get("firewall") === "true";

  if (stream) {
    const encoder = new TextEncoder();
    const readable = new ReadableStream({
      start(controller) {
        const existing = getRecentLogs(200, severity, search, source, firewallOnly);
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify({ type: "init", logs: existing })}\n\n`)
        );

        const unsubscribe = subscribe((entry) => {
          if (firewallOnly && !/^\[\w+-(A|D|R)-\d+\]/.test(entry.message)) return;
          if (severity && entry.severity !== severity) return;
          if (source) {
            const q = source.toLowerCase();
            if (!entry.host.toLowerCase().includes(q)) return;
          }
          if (search) {
            const q = search.toLowerCase();
            if (
              !entry.message.toLowerCase().includes(q) &&
              !entry.host.toLowerCase().includes(q)
            )
              return;
          }
          controller.enqueue(
            encoder.encode(`data: ${JSON.stringify({ type: "log", entry })}\n\n`)
          );
        });

        request.signal.addEventListener("abort", () => {
          unsubscribe();
          controller.close();
        });
      },
    });

    return new Response(readable, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    });
  }

  // Paginated query
  const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
  const pageSize = Math.min(500, Math.max(1, parseInt(searchParams.get("pageSize") || "100", 10)));

  const filterOptions: FilterOptions = {};
  const action = searchParams.get("action");
  const proto = searchParams.get("proto");
  const srcIp = searchParams.get("srcIp");
  const srcPort = searchParams.get("srcPort");
  const dstIp = searchParams.get("dstIp");
  const dstPort = searchParams.get("dstPort");
  const rule = searchParams.get("rule");
  const ipMatch = searchParams.get("ipMatch");
  if (action) filterOptions.action = action;
  if (proto) filterOptions.proto = proto;
  if (srcIp) filterOptions.srcIp = srcIp;
  if (srcPort) filterOptions.srcPort = srcPort;
  if (dstIp) filterOptions.dstIp = dstIp;
  if (dstPort) filterOptions.dstPort = dstPort;
  if (rule) filterOptions.rule = rule;
  if (ipMatch === "or") filterOptions.ipMatch = "or";

  const result = getLogs(page, pageSize, severity, search, source, firewallOnly, filterOptions);
  return Response.json(result);
}

export async function DELETE() {
  clearLogs();
  return Response.json({ ok: true });
}
