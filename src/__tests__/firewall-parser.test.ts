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

  it("parses a blocked UniFi CEF security event", () => {
    const msg = `Aug 06 00:22:02 HH-Gateway CEF:0|Ubiquiti|UniFi Network|10.5.67|201|Threat Detected and Blocked|7|UNIFIcategory=Security proto=TCP spt=60363 dpt=22 act=blocked UNIFIpolicyName=Scanning Activity UNIFIpolicyType=IDS/IPS deviceInboundInterface=WireGuard Server 1 UNIFIdeviceMac=0c:ea:14:8a:4d:e3 src=192.168.2.3 dst=192.168.30.29 UNIFItotalBytes=78 UNIFIipsSignature=ET SCAN Potential SSH Scan msg=A network intrusion attempt has been detected and blocked.`;
    const result = parseFirewallMessage(msg);

    expect(result).not.toBeNull();
    expect(result!.action).toBe("Drop");
    expect(result!.descr).toBe("Scanning Activity");
    expect(result!.rule).toBe("ET SCAN Potential SSH Scan");
    expect(result!.iface).toBe("WireGuard Server 1");
    expect(result!.src).toBe("192.168.2.3");
    expect(result!.dst).toBe("192.168.30.29");
    expect(result!.proto).toBe("TCP");
    expect(result!.spt).toBe("60363");
    expect(result!.dpt).toBe("22");
    expect(result!.len).toBe("78");
    expect(result!.mac).toBe("0c:ea:14:8a:4d:e3");
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
