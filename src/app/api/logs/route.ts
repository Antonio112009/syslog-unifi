import { NextRequest } from "next/server";
import { getLogs, getRecentLogs, clearLogs, subscribe, loadLogs } from "@/lib/log-store";

loadLogs();

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const stream = searchParams.get("stream") === "true";
  const severity = searchParams.get("severity") || undefined;
  const search = searchParams.get("search") || undefined;
  const source = searchParams.get("source") || undefined;

  if (stream) {
    const encoder = new TextEncoder();
    const readable = new ReadableStream({
      start(controller) {
        const existing = getRecentLogs(200, severity, search, source);
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify({ type: "init", logs: existing })}\n\n`)
        );

        const unsubscribe = subscribe((entry) => {
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

  const result = getLogs(page, pageSize, severity, search, source);
  return Response.json(result);
}

export async function DELETE() {
  clearLogs();
  return Response.json({ ok: true });
}
