import { getDistinctRules, getDistinctProtocols } from "@/lib/log-store";

export async function GET() {
  const rules = getDistinctRules();
  const protocols = getDistinctProtocols();
  return Response.json({ rules, protocols });
}
