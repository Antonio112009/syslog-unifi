import type { SyslogEntry } from "@/types/syslog";

export function exportAsJson(logs: SyslogEntry[], filename = "syslog-export.json") {
  const json = JSON.stringify(logs, null, 2);
  downloadBlob(json, filename, "application/json");
}

export function exportAsCsv(logs: SyslogEntry[], filename = "syslog-export.csv") {
  const headers = [
    "id",
    "timestamp",
    "facility",
    "severity",
    "host",
    "message",
    "raw",
    "receivedAt",
    "subsystem",
  ];
  const escapeCell = (val: string) => {
    if (val.includes(",") || val.includes('"') || val.includes("\n")) {
      return `"${val.replace(/"/g, '""')}"`;
    }
    return val;
  };
  const rows = logs.map((log) =>
    headers.map((h) => escapeCell(String(log[h as keyof SyslogEntry] ?? ""))).join(",")
  );
  const csv = [headers.join(","), ...rows].join("\n");
  downloadBlob(csv, filename, "text/csv");
}

function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
