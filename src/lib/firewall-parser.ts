import type { ParsedFirewall } from "@/types/syslog";

const FW_KV_REGEXES: Record<string, RegExp> = {
  IN: /IN=([^\s]*)/,
  SRC: /SRC=([^\s]*)/,
  DST: /DST=([^\s]*)/,
  PROTO: /PROTO=([^\s]*)/,
  SPT: /SPT=([^\s]*)/,
  DPT: /DPT=([^\s]*)/,
  LEN: /LEN=([^\s]*)/,
  MAC: /MAC=([^\s]*)/,
};

export function parseFirewallMessage(msg: string): ParsedFirewall | null {
  const ruleMatch = msg.match(/\[([^\]]+)\]/);
  if (!ruleMatch) return null;
  const ruleRaw = ruleMatch[1];
  const actionCode = ruleRaw.match(/-([ADR])-/)?.[1] || "";
  const actionMap: Record<string, string> = {
    A: "Allow",
    D: "Drop",
    R: "Reject",
  };
  const action = actionMap[actionCode] || actionCode;
  const descrMatch = msg.match(/DESCR="([^"]*)"/s);
  const kv = (key: string) => msg.match(FW_KV_REGEXES[key])?.[1] || "";
  return {
    rule: ruleRaw,
    action,
    descr: descrMatch?.[1]?.replace(/^\[[^\]]*\]/, "") || "",
    iface: kv("IN"),
    src: kv("SRC"),
    dst: kv("DST"),
    proto: kv("PROTO"),
    spt: kv("SPT"),
    dpt: kv("DPT"),
    len: kv("LEN"),
    mac: kv("MAC"),
  };
}
