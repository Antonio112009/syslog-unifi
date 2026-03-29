import { describe, it, expect, vi, beforeEach } from "vitest";

// We test the CSV/JSON generation logic by capturing what Blob receives
let lastBlobContent = "";
let lastBlobType = "";
let lastDownloadName = "";

const mockElement = {
  href: "",
  download: "",
  click: vi.fn(),
};

vi.stubGlobal("Blob", class {
  constructor(parts: string[], options: { type: string }) {
    lastBlobContent = parts[0];
    lastBlobType = options.type;
  }
});
const OriginalURL = globalThis.URL;
vi.stubGlobal("URL", Object.assign(
  function(...args: ConstructorParameters<typeof OriginalURL>) { return new OriginalURL(...args); },
  {
    createObjectURL: vi.fn(() => "blob:test"),
    revokeObjectURL: vi.fn(),
  }
));
vi.stubGlobal("document", {
  createElement: vi.fn(() => {
    mockElement.href = "";
    mockElement.download = "";
    mockElement.click = vi.fn();
    return mockElement;
  }),
  body: {
    appendChild: vi.fn(),
    removeChild: vi.fn(),
  },
});

const { exportAsCsv, exportAsJson } = await import("@/lib/export");

const sampleLogs = [
  {
    id: "1",
    timestamp: "2024-01-05T14:30:00Z",
    facility: "local0",
    severity: "info",
    host: "myhost",
    message: "Test message",
    raw: "<134>Jan  5 14:30:00 myhost Test message",
    receivedAt: "2024-01-05T14:30:01Z",
    subsystem: "local0",
    key: "",
  },
  {
    id: "2",
    timestamp: "2024-01-05T14:31:00Z",
    facility: "kern",
    severity: "error",
    host: "otherhost",
    message: 'Has "quotes" and,commas',
    raw: "<3>msg",
    receivedAt: "2024-01-05T14:31:01Z",
    subsystem: "kern",
    key: "",
  },
];

beforeEach(() => {
  lastBlobContent = "";
  lastBlobType = "";
  lastDownloadName = "";
});

describe("exportAsJson", () => {
  it("creates valid JSON", () => {
    exportAsJson(sampleLogs);
    expect(lastBlobType).toBe("application/json");
    const parsed = JSON.parse(lastBlobContent);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].id).toBe("1");
    expect(mockElement.download).toBe("syslog-export.json");
  });
});

describe("exportAsCsv", () => {
  it("creates valid CSV with headers", () => {
    exportAsCsv(sampleLogs);
    expect(lastBlobType).toBe("text/csv");
    const lines = lastBlobContent.split("\n");
    expect(lines[0]).toBe("id,timestamp,facility,severity,host,message,raw,receivedAt,subsystem");
    expect(lines).toHaveLength(3); // header + 2 rows
    expect(mockElement.download).toBe("syslog-export.csv");
  });

  it("escapes quotes and commas in CSV", () => {
    exportAsCsv(sampleLogs);
    const lines = lastBlobContent.split("\n");
    // Second data row should have escaped quotes
    expect(lines[2]).toContain('""quotes""');
  });

  it("uses custom filename", () => {
    exportAsCsv(sampleLogs, "custom.csv");
    expect(mockElement.download).toBe("custom.csv");
  });
});
