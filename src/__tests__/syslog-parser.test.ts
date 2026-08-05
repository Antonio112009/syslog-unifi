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

  it("normalizes RFC 3164-wrapped UniFi CEF events", () => {
    const raw = `<134>Aug  6 00:22:02 HH-Gateway CEF:0|Ubiquiti|UniFi Network|10.5.67|201|Threat Detected and Blocked|7|proto=TCP act=blocked src=192.168.2.3 dst=192.168.30.29 msg=A network intrusion attempt has been detected and blocked.`;
    const result = parseSyslogMessage(raw, "10.0.0.1");

    expect(result.host).toBe("HH-Gateway");
    expect(result.facility).toBe("UniFi Network");
    expect(result.severity).toBe("error");
    expect(result.message).toBe(
      "A network intrusion attempt has been detected and blocked."
    );
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
