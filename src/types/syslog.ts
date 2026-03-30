export interface SyslogEntry {
  id: string;
  timestamp: string;
  facility: string;
  severity: string;
  host: string;
  message: string;
  raw: string;
  receivedAt: string;
  subsystem: string;
  key: string;
}

export interface PaginatedResponse {
  logs: SyslogEntry[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export interface ParsedFirewall {
  rule: string;
  action: string;
  descr: string;
  iface: string;
  src: string;
  dst: string;
  proto: string;
  spt: string;
  dpt: string;
  len: string;
  mac: string;
}

export type StreamState = "running" | "paused" | "stopped";

export interface Filters {
  action: string;
  proto: string;
  srcIp: string;
  srcPort: string;
  dstIp: string;
  dstPort: string;
  rule: string;
  search: string;
  ipMatch: "and" | "or";
}

export const emptyFilters: Filters = {
  action: "",
  proto: "",
  srcIp: "",
  srcPort: "",
  dstIp: "",
  dstPort: "",
  rule: "",
  search: "",
  ipMatch: "and",
};
