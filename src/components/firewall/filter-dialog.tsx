"use client";

import { useState, useRef } from "react";
import { Filter, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
} from "@/components/ui/dialog";
import type { Filters } from "@/types/syslog";
import { emptyFilters } from "@/types/syslog";

const selectClass =
  "h-9 w-full rounded-lg border border-input bg-transparent px-3 text-sm outline-none cursor-pointer focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30";

export function FilterDialog({
  filters,
  onChange,
  activeCount,
  onClear,
  ruleOptions,
  protocolOptions,
  onDeleteFiltered,
}: {
  filters: Filters;
  onChange: (f: Filters) => void;
  activeCount: number;
  onClear: () => void;
  ruleOptions: string[];
  protocolOptions?: string[];
  onDeleteFiltered: (f: Filters) => Promise<number>;
}) {
  const [local, setLocal] = useState(filters);
  const [open, setOpen] = useState(false);
  const [ruleDropdownOpen, setRuleDropdownOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const ruleRef = useRef<HTMLDivElement>(null);

  const handleOpenChange = (nextOpen: boolean) => {
    if (nextOpen) setLocal(filters);
    setConfirmDelete(false);
    setOpen(nextOpen);
  };

  const hasAnyFilter = !!(
    local.action ||
    local.proto ||
    local.srcIp ||
    local.srcPort ||
    local.dstIp ||
    local.dstPort ||
    local.rule
  );

  const handleDelete = async () => {
    setDeleting(true);
    try {
      const deleted = await onDeleteFiltered(local);
      setConfirmDelete(false);
      setOpen(false);
      if (deleted > 0) onChange(local);
    } finally {
      setDeleting(false);
    }
  };

  const apply = () => {
    onChange(local);
    setOpen(false);
  };

  const clear = () => {
    setLocal(emptyFilters);
    onChange(emptyFilters);
    onClear();
    setOpen(false);
  };

  const set = (key: keyof Filters, value: string) =>
    setLocal((prev) => ({ ...prev, [key]: value }));

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger render={<Button variant="outline" size="sm" />}>
        <Filter className="size-4" />
        Filters
        {activeCount > 0 && (
          <Badge variant="secondary" className="ml-1 h-4 text-[10px] px-1.5">
            {activeCount}
          </Badge>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Filter Firewall Logs</DialogTitle>
          <DialogDescription>
            Narrow down firewall entries by action, protocol, addresses, and
            ports.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">
                Action
              </label>
              <select
                value={local.action}
                onChange={(e) => set("action", e.target.value)}
                className={selectClass}
              >
                <option value="">All</option>
                <option value="Allow">Allow</option>
                <option value="Drop">Drop</option>
                <option value="Reject">Reject</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">
                Protocol
              </label>
              <select
                value={local.proto}
                onChange={(e) => set("proto", e.target.value)}
                className={selectClass}
              >
                <option value="">All</option>
                {(protocolOptions && protocolOptions.length > 0
                  ? protocolOptions
                  : ["TCP", "UDP", "ICMP"]
                ).map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-muted/20 p-3 space-y-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">
                Source
              </label>
              <div className="grid grid-cols-[1fr_100px] gap-2">
                <Input
                  placeholder="e.g. 192.168.2 or .2.11"
                  value={local.srcIp}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("srcIp", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
                <Input
                  placeholder="Port"
                  value={local.srcPort}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("srcPort", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex-1 h-px bg-border/60" />
              <div className="flex rounded-md border border-input overflow-hidden text-xs font-medium">
                <button
                  type="button"
                  className={cn(
                    "px-3 py-1 transition-colors",
                    local.ipMatch === "and"
                      ? "bg-primary text-primary-foreground"
                      : "bg-transparent text-muted-foreground hover:text-foreground"
                  )}
                  onClick={() => set("ipMatch", "and")}
                >
                  AND
                </button>
                <button
                  type="button"
                  className={cn(
                    "px-3 py-1 transition-colors border-l border-input",
                    local.ipMatch === "or"
                      ? "bg-primary text-primary-foreground"
                      : "bg-transparent text-muted-foreground hover:text-foreground"
                  )}
                  onClick={() => set("ipMatch", "or")}
                >
                  OR
                </button>
              </div>
              <div className="flex-1 h-px bg-border/60" />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">
                Destination
              </label>
              <div className="grid grid-cols-[1fr_100px] gap-2">
                <Input
                  placeholder="e.g. 192.168.2 or .2.11"
                  value={local.dstIp}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("dstIp", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
                <Input
                  placeholder="Port"
                  value={local.dstPort}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    set("dstPort", e.target.value)
                  }
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              Rule
            </label>
            <div className="relative" ref={ruleRef}>
              <Input
                placeholder="e.g. LAN_IN, WAN_OUT..."
                value={local.rule}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                  set("rule", e.target.value);
                  setRuleDropdownOpen(true);
                }}
                onFocus={() => setRuleDropdownOpen(true)}
                onBlur={(e: React.FocusEvent) => {
                  if (
                    !ruleRef.current?.contains(e.relatedTarget as Node)
                  ) {
                    setRuleDropdownOpen(false);
                  }
                }}
                autoComplete="off"
                data-1p-ignore
                data-lpignore="true"
              />
              {ruleDropdownOpen &&
                (() => {
                  const filtered = ruleOptions.filter(
                    (r) =>
                      !local.rule ||
                      r.toLowerCase().includes(local.rule.toLowerCase())
                  );
                  if (filtered.length === 0) return null;
                  return (
                    <div className="absolute z-50 mt-1 w-full max-h-48 overflow-y-auto rounded-md border border-border bg-popover py-1 shadow-md">
                      {filtered.map((r) => (
                        <button
                          key={r}
                          type="button"
                          className="w-full px-3 py-1.5 text-left text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer truncate"
                          onMouseDown={(e) => e.preventDefault()}
                          onClick={() => {
                            set("rule", r);
                            setRuleDropdownOpen(false);
                          }}
                        >
                          {r}
                        </button>
                      ))}
                    </div>
                  );
                })()}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">
              Search (message)
            </label>
            <Input
              placeholder="e.g. DNS, 443..."
              value={local.search}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                set("search", e.target.value)
              }
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
          </div>
        </div>

        <div className="flex items-center justify-between pt-2">
          <Button variant="ghost" size="sm" onClick={clear}>
            Clear all
          </Button>
          <div className="flex items-center gap-2">
            {confirmDelete ? (
              <>
                <span className="text-xs text-destructive">
                  Delete all matching?
                </span>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleDelete}
                  disabled={deleting}
                >
                  {deleting ? "Deleting..." : "Confirm"}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setConfirmDelete(false)}
                >
                  Cancel
                </Button>
              </>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="text-destructive border-destructive/30 hover:bg-destructive/10"
                onClick={() => setConfirmDelete(true)}
                disabled={!hasAnyFilter}
                title={
                  hasAnyFilter
                    ? "Delete logs matching current filters"
                    : "Set at least one filter to delete"
                }
              >
                Delete Matching
              </Button>
            )}
            <Button size="sm" onClick={apply}>
              Apply filters
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function FilterBadges({
  filters,
  onRemove,
  onClearAll,
  activeCount,
}: {
  filters: Filters;
  onRemove: (key: keyof Filters) => void;
  onClearAll: () => void;
  activeCount: number;
}) {
  const badges: { label: string; key: keyof Filters }[] = [];
  if (filters.action)
    badges.push({ label: `Action: ${filters.action}`, key: "action" });
  if (filters.proto)
    badges.push({ label: `Proto: ${filters.proto}`, key: "proto" });
  const hasSrc = !!(filters.srcIp || filters.srcPort);
  const hasDst = !!(filters.dstIp || filters.dstPort);
  const orMode = filters.ipMatch === "or" && hasSrc && hasDst;
  if (filters.srcIp)
    badges.push({ label: `Src: ${filters.srcIp}`, key: "srcIp" });
  if (filters.srcPort)
    badges.push({ label: `Src Port: ${filters.srcPort}`, key: "srcPort" });
  if (orMode) badges.push({ label: "OR", key: "ipMatch" });
  if (filters.dstIp)
    badges.push({ label: `Dst: ${filters.dstIp}`, key: "dstIp" });
  if (filters.dstPort)
    badges.push({ label: `Dst Port: ${filters.dstPort}`, key: "dstPort" });
  if (filters.rule)
    badges.push({ label: `Rule: ${filters.rule}`, key: "rule" });
  if (filters.search)
    badges.push({ label: `"${filters.search}"`, key: "search" });

  if (badges.length === 0) return null;

  return (
    <>
      {badges.map(({ label, key }) =>
        key === "ipMatch" ? (
          <span
            key={key}
            className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider"
          >
            or
          </span>
        ) : (
          <Badge key={key} variant="outline" className="gap-1 pr-1">
            {label}
            <button
              onClick={() => onRemove(key)}
              className="ml-0.5 rounded-full hover:bg-muted p-0.5"
            >
              <X className="size-3" />
            </button>
          </Badge>
        )
      )}
      {activeCount > 0 && (
        <Button variant="ghost" size="xs" onClick={onClearAll}>
          Clear all
        </Button>
      )}
    </>
  );
}
