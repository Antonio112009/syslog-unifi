"use client";

import { useState } from "react";
import {
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  FileText,
  ShieldAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { parseCefMessage } from "@/lib/firewall-parser";
import type { ParsedFirewall, SyslogEntry } from "@/types/syslog";

function endpoint(address: string, port: string) {
  if (!address) return "Not reported";
  return port ? `${address}:${port}` : address;
}

function titleCase(value: string) {
  if (!value) return "";
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function DetailItem({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="min-w-0 bg-card px-3 py-2.5">
      <dt className="font-sans text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </dt>
      <dd className="mt-1 truncate font-mono text-xs text-foreground" title={value}>
        {value || "Not reported"}
      </dd>
    </div>
  );
}

export function LogDetails({
  log,
  firewall,
}: {
  log: SyslogEntry;
  firewall?: ParsedFirewall;
}) {
  const [copied, setCopied] = useState(false);
  const cef = parseCefMessage(log.raw) || parseCefMessage(log.message);
  const fields = cef?.fields || {};

  const action =
    firewall?.action ||
    ({
      blocked: "Drop",
      denied: "Drop",
      allowed: "Allow",
      detected: "Alert",
    }[fields.act?.toLowerCase() || ""] ?? "");
  const source = endpoint(firewall?.src || fields.src || "", firewall?.spt || fields.spt || "");
  const destination = endpoint(firewall?.dst || fields.dst || "", firewall?.dpt || fields.dpt || "");
  const protocol = firewall?.proto || fields.proto?.toUpperCase() || "";
  const application = fields.app || "";
  const direction = titleCase(fields.UNIFIdirection || "");
  const inboundInterface = firewall?.iface || fields.deviceInboundInterface || "";
  const outboundInterface = fields.deviceOutboundInterface || "";
  const policy = firewall?.descr || fields.UNIFIpolicyName || "";
  const signature = firewall?.rule || fields.UNIFIipsSignature || "";
  const message = fields.msg || (cef ? "" : log.message);
  const eventTitle =
    cef?.eventName || firewall?.descr || firewall?.rule || "Event details";
  const hasNetworkDetails = Boolean(
    firewall || fields.src || fields.dst || fields.proto || fields.act
  );

  const handleCopy = async () => {
    await navigator.clipboard.writeText(log.raw);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <section className="mx-3 mb-3 overflow-hidden rounded-xl border border-border/70 bg-card/90 font-sans shadow-sm">
      <header className="flex flex-wrap items-start gap-3 px-3 py-3">
        <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
          {hasNetworkDetails ? (
            <ShieldAlert className="size-4" />
          ) : (
            <FileText className="size-4" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="truncate text-sm font-semibold text-foreground">
            {eventTitle}
          </h3>
          <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
            {cef
              ? `${cef.vendor} · ${cef.product} ${cef.productVersion} · Event ${cef.eventId}`
              : `${log.host} · ${log.facility} · ${log.timestamp.replace("T", " ").slice(0, 19)}`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {action && (
            <Badge variant={action === "Drop" ? "destructive" : "outline"}>
              {action}
            </Badge>
          )}
          {fields.UNIFIrisk && (
            <Badge variant="outline">{titleCase(fields.UNIFIrisk)} risk</Badge>
          )}
          <Button variant="outline" size="xs" onClick={handleCopy}>
            {copied ? (
              <Check data-icon="inline-start" />
            ) : (
              <Copy data-icon="inline-start" />
            )}
            {copied ? "Copied" : "Copy raw"}
          </Button>
        </div>
      </header>

      {hasNetworkDetails && (
        <dl className="grid gap-px border-t border-border/60 bg-border/50 sm:grid-cols-2 xl:grid-cols-4">
          <DetailItem label="Source" value={source} />
          <DetailItem label="Destination" value={destination} />
          <DetailItem
            label="Traffic"
            value={[protocol, application].filter(Boolean).join(" · ")}
          />
          <DetailItem
            label="Path"
            value={
              [direction, inboundInterface, outboundInterface]
                .filter(Boolean)
                .join(" · ")
            }
          />
        </dl>
      )}

      {(policy || signature) && (
        <dl className="grid gap-px border-t border-border/60 bg-border/50 sm:grid-cols-2">
          <DetailItem label="Policy" value={policy} />
          <DetailItem label="Signature / rule" value={signature} />
        </dl>
      )}

      {message && (
        <div className="border-t border-border/60 px-3 py-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Message
          </p>
          <p className="mt-1.5 text-sm leading-relaxed text-foreground/85">
            {message}
          </p>
        </div>
      )}

      <details className="group border-t border-border/60">
        <summary className="flex list-none items-center gap-2 px-3 py-2.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-muted/40 hover:text-foreground [&::-webkit-details-marker]:hidden">
          <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />
          Raw payload
          <span className="ml-auto font-mono text-[10px] text-muted-foreground/70">
            {log.raw.length.toLocaleString()} characters
          </span>
        </summary>
        <div className="px-3 pb-3">
          <pre className="max-h-44 overflow-auto rounded-lg bg-background/80 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground whitespace-pre-wrap break-words ring-1 ring-border/60">
            {log.raw}
          </pre>
        </div>
      </details>
    </section>
  );
}
