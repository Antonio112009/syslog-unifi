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

const CEF_ACTIONS: Record<string, string> = {
  allow: "Allow",
  allowed: "Allow",
  block: "Drop",
  blocked: "Drop",
  deny: "Drop",
  denied: "Drop",
  reject: "Reject",
  rejected: "Reject",
  alert: "Alert",
  alerted: "Alert",
  detect: "Alert",
  detected: "Alert",
};

export interface ParsedCefEvent {
  version: string;
  vendor: string;
  product: string;
  productVersion: string;
  eventId: string;
  eventName: string;
  severity: string;
  fields: Record<string, string>;
}

function parseCefFields(extension: string): Record<string, string> {
  const fields: Record<string, string> = {};
  const fieldPattern =
    /(?:^|\s)([A-Za-z][A-Za-z0-9]*)=(.*?)(?=\s+[A-Za-z][A-Za-z0-9]*=|$)/gs;

  for (const match of extension.matchAll(fieldPattern)) {
    fields[match[1]] = match[2].trim();
  }

  return fields;
}

export function parseCefMessage(msg: string): ParsedCefEvent | null {
  const cefStart = msg.indexOf("CEF:");
  if (cefStart === -1) return null;

  const parts = msg.slice(cefStart).split("|");
  if (parts.length < 8) return null;

  return {
    version: parts[0]?.slice(4).trim() || "",
    vendor: parts[1]?.trim() || "",
    product: parts[2]?.trim() || "",
    productVersion: parts[3]?.trim() || "",
    eventId: parts[4]?.trim() || "",
    eventName: parts[5]?.trim() || "",
    severity: parts[6]?.trim() || "",
    fields: parseCefFields(parts.slice(7).join("|")),
  };
}

function parseCefFirewallMessage(msg: string): ParsedFirewall | null {
  const cef = parseCefMessage(msg);
  if (!cef) return null;

  const { eventId, eventName, fields } = cef;
  const action = CEF_ACTIONS[fields.act?.toLowerCase() || ""];
  if (!action) return null;

  return {
    action,
    rule:
      fields.UNIFIipsSignature ||
      fields.UNIFIpolicyType ||
      eventName ||
      `CEF ${eventId}`,
    descr: fields.UNIFIpolicyName || eventName,
    iface:
      fields.deviceInboundInterface || fields.deviceOutboundInterface || "",
    src: fields.src || "",
    dst: fields.dst || "",
    proto: fields.proto?.toUpperCase() || "",
    spt: fields.spt || "",
    dpt: fields.dpt || "",
    len: fields.UNIFItotalBytes || "",
    mac: fields.UNIFIdeviceMac || "",
  };
}

export function parseFirewallMessage(msg: string): ParsedFirewall | null {
  const cefFirewall = parseCefFirewallMessage(msg);
  if (cefFirewall) return cefFirewall;

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
