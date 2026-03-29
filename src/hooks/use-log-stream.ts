"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { SyslogEntry } from "@/types/syslog";

const MAX_LIVE_LOGS = 500;

interface UseLogStreamOptions {
  firewallOnly?: boolean;
}

export function useLogStream(options: UseLogStreamOptions = {}) {
  const { firewallOnly = false } = options;
  const [liveLogs, setLiveLogs] = useState<SyslogEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(true);
  const [retryCount, setRetryCount] = useState(0);
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connectStream = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }
    setIsConnecting(true);

    const params = new URLSearchParams({ stream: "true" });
    if (firewallOnly) params.set("firewall", "true");

    const es = new EventSource(`/api/logs?${params}`);
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setIsConnecting(false);
      setRetryCount(0);
    };

    es.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "init") {
        setLiveLogs(data.logs);
      } else if (data.type === "log") {
        setLiveLogs((prev) => {
          const next = [data.entry, ...prev];
          if (next.length > MAX_LIVE_LOGS) return next.slice(0, MAX_LIVE_LOGS);
          return next;
        });
      }
    };

    es.onerror = () => {
      setConnected(false);
      setIsConnecting(false);
      es.close();
      setRetryCount((prev) => {
        const next = prev + 1;
        const delay = Math.min(1000 * Math.pow(2, next), 30000);
        retryTimeoutRef.current = setTimeout(connectStream, delay);
        return next;
      });
    };
  }, [firewallOnly]);

  useEffect(() => {
    connectStream();
    return () => {
      eventSourceRef.current?.close();
      if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
    };
  }, [connectStream]);

  const clearLive = useCallback(() => setLiveLogs([]), []);

  return {
    liveLogs,
    connected,
    isConnecting,
    retryCount,
    clearLive,
  };
}
