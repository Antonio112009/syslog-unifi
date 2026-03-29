import { describe, it, expect } from "vitest";
import { extractFirewallFields } from "@/lib/db";

describe("extractFirewallFields", () => {
  it("extracts all firewall fields from a valid message", () => {
    const msg = `[WAN_IN-D-100] DESCR="Block WAN" PROTO=TCP SRC=10.0.0.1 DST=192.168.1.1 SPT=443 DPT=8080`;
    const result = extractFirewallFields(msg);
    expect(result.fw_action).toBe("Drop");
    expect(result.fw_proto).toBe("TCP");
    expect(result.fw_src).toBe("10.0.0.1");
    expect(result.fw_dst).toBe("192.168.1.1");
    expect(result.fw_spt).toBe("443");
    expect(result.fw_dpt).toBe("8080");
    expect(result.fw_rule).toBe("WAN_IN-D-100");
    expect(result.fw_rule_descr).toBe("Block WAN");
  });

  it("returns empty fields for Allow action", () => {
    const msg = `[LAN_IN-A-200] DESCR="Allow" PROTO=UDP SRC=192.168.1.5 DST=8.8.8.8`;
    const result = extractFirewallFields(msg);
    expect(result.fw_action).toBe("Allow");
  });

  it("returns empty fields for Reject action", () => {
    const msg = `[WAN-R-5] PROTO=ICMP SRC=1.2.3.4 DST=5.6.7.8`;
    const result = extractFirewallFields(msg);
    expect(result.fw_action).toBe("Reject");
  });

  it("returns empty fields for non-firewall messages", () => {
    const msg = "Jan  1 00:00:00 host kernel: some message";
    const result = extractFirewallFields(msg);
    expect(result.fw_action).toBe("");
    expect(result.fw_proto).toBe("");
    expect(result.fw_src).toBe("");
    expect(result.fw_rule).toBe("");
  });

  it("returns empty fields when brackets exist but no action code", () => {
    const msg = "[some-tag] random message";
    const result = extractFirewallFields(msg);
    expect(result.fw_action).toBe("");
  });

  it("handles missing DESCR field", () => {
    const msg = `[WAN_IN-D-1] PROTO=TCP SRC=1.2.3.4 DST=5.6.7.8`;
    const result = extractFirewallFields(msg);
    expect(result.fw_action).toBe("Drop");
    expect(result.fw_rule_descr).toBe("");
  });
});
