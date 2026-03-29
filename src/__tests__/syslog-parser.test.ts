import { describe, it, expect } from "vitest";
import { parseSyslogMessage } from "@/lib/syslog-server";

describe("parseSyslogMessage", () => {
  it("parses RFC 3164 format", () => {
    const raw = `<134>Jan  5 14:30:00 myhost sshd[1234]: Accepted publickey`;
    const result = parseSyslogMessage(raw, "10.0.0.1");
    expect(result.host).toBe("myhost");
    expect(result.severity).toBe("info"); // 134 & 7 = 6 = info
    expect(result.facility).toBe("local0"); // 134 >> 3 = 16 = local0
    expect(result.message).toBe("sshd[1234]: Accepted publickey");
  });

  it("parses RFC 5424 format", () => {
    const raw = `<165>1 2024-01-05T14:30:00Z myhost app 1234 - - Hello world`;
    const result = parseSyslogMessage(raw, "10.0.0.1");
    expect(result.host).toBe("myhost");
    expect(result.message).toBe("Hello world");
    expect(result.timestamp).toBe("2024-01-05T14:30:00Z");
  });

  it("parses UniFi CEF format", () => {
    const raw = `<134>Jan  5 14:30:00 2024-01-05T14:30:00Z MyDevice CEF:0|Ubiquiti|UniFi OS|1.0|100|Firewall|5|msg=Blocked traffic`;
    const result = parseSyslogMessage(raw, "10.0.0.1");
    expect(result.host).toBe("MyDevice");
    expect(result.message).toBe("Blocked traffic");
    expect(result.timestamp).toBe("2024-01-05T14:30:00Z");
  });

  it("handles simple fallback format", () => {
    const raw = `<13>myhost Some random message`;
    const result = parseSyslogMessage(raw, "10.0.0.1");
    expect(result.host).toBe("myhost");
    expect(result.message).toBe("Some random message");
  });

  it("parses simple hostname+message format", () => {
    // Parser splits first word as host, rest as message
    const raw = `<13>myhost a plain message`;
    const result = parseSyslogMessage(raw, "192.168.1.5");
    expect(result.host).toBe("myhost");
    expect(result.message).toBe("a plain message");
  });

  it("correctly extracts severity from PRI", () => {
    // PRI = 11 = facility 1 (user) + severity 3 (error)
    const raw = `<11>Jan  1 00:00:00 host msg`;
    const result = parseSyslogMessage(raw, "10.0.0.1");
    expect(result.severity).toBe("error");
    expect(result.facility).toBe("user");
  });

  it("handles empty/whitespace messages", () => {
    const result = parseSyslogMessage("   ", "10.0.0.1");
    expect(result.message).toBe("");
  });
});
