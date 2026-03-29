import { describe, it, expect } from "vitest";
import { parseFirewallMessage } from "@/lib/firewall-parser";

describe("parseFirewallMessage", () => {
  it("parses a Drop rule with all fields", () => {
    const msg = `[WAN_IN-D-1000] DESCR="Block all" IN=eth0 SRC=10.0.0.1 DST=192.168.1.1 PROTO=TCP SPT=12345 DPT=443 LEN=60 MAC=aa:bb:cc:dd:ee:ff`;
    const result = parseFirewallMessage(msg);
    expect(result).not.toBeNull();
    expect(result!.action).toBe("Drop");
    expect(result!.rule).toBe("WAN_IN-D-1000");
    expect(result!.descr).toBe("Block all");
    expect(result!.iface).toBe("eth0");
    expect(result!.src).toBe("10.0.0.1");
    expect(result!.dst).toBe("192.168.1.1");
    expect(result!.proto).toBe("TCP");
    expect(result!.spt).toBe("12345");
    expect(result!.dpt).toBe("443");
    expect(result!.len).toBe("60");
    expect(result!.mac).toBe("aa:bb:cc:dd:ee:ff");
  });

  it("parses an Allow rule", () => {
    const msg = `[LAN_IN-A-200] DESCR="Allow LAN" IN=br0 SRC=192.168.1.5 DST=8.8.8.8 PROTO=UDP SPT=53 DPT=53`;
    const result = parseFirewallMessage(msg);
    expect(result!.action).toBe("Allow");
    expect(result!.descr).toBe("Allow LAN");
  });

  it("parses a Reject rule", () => {
    const msg = `[WAN_OUT-R-50] DESCR="Reject outbound" SRC=192.168.1.1 DST=1.2.3.4 PROTO=ICMP`;
    const result = parseFirewallMessage(msg);
    expect(result!.action).toBe("Reject");
    expect(result!.proto).toBe("ICMP");
  });

  it("returns null for non-firewall messages", () => {
    expect(parseFirewallMessage("Just a normal syslog message")).toBeNull();
  });

  it("returns null when no brackets found", () => {
    expect(parseFirewallMessage("kernel: some kernel message")).toBeNull();
  });

  it("handles missing optional fields gracefully", () => {
    const msg = `[WAN_IN-D-1] SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP`;
    const result = parseFirewallMessage(msg);
    expect(result!.action).toBe("Drop");
    expect(result!.descr).toBe("");
    expect(result!.spt).toBe("");
    expect(result!.dpt).toBe("");
    expect(result!.iface).toBe("");
    expect(result!.len).toBe("");
    expect(result!.mac).toBe("");
  });

  it("strips prefix from description", () => {
    const msg = `[WAN_IN-D-1] DESCR="[prefix]Real description" SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP`;
    const result = parseFirewallMessage(msg);
    expect(result!.descr).toBe("Real description");
  });
});
