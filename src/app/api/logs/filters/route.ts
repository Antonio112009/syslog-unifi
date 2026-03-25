import { getDistinctRules } from "@/lib/log-store";

export async function GET() {
  const rules = getDistinctRules();
  return Response.json({ rules });
}
