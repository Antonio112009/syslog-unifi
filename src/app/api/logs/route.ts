import { NextRequest } from "next/server";
import { getLogs, clearLogs, subscribe, loadLogs } from "@/lib/log-store";

loadLogs();

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const stream = searchParams.get("stream") === "true";
  const severity = searchParams.get("severity") || undefined;
  const search = searchParams.get("search") || undefined;
  const limit = parseInt(searchParams.get("limit") || "200", 10);

  if (stream) {
    const encoder = new TextEncoder();
    const readable = new ReadableStream({
      start(controller) {
        const existing = getLogs(limit, severity, search);
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify({ type: "init", logs: existing })}\n\n`)
        );

        const unsubscribe = subscribe((entry) => {
          if (severity && entry.severity !== severity) return;
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

  const logs = getLogs(limit, severity, search);
  return Response.json(logs);
}

export async function DELETE() {
  clearLogs();
  return Response.json({ ok: true });
}
