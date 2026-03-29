import { purgeOldLogs } from "@/lib/log-store";

export async function DELETE() {
  const purged = purgeOldLogs();
  return Response.json({ ok: true, purged });
}
