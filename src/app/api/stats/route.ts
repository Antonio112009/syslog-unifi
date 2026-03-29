import { getDbStats } from "@/lib/log-store";

export async function GET() {
  const stats = getDbStats();
  return Response.json(stats);
}
