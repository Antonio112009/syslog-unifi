"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { SyslogEntry, StreamState, PaginatedResponse } from "@/types/syslog";

const MAX_LOGS = 5000;
const INIT_SIZE = 200;
const PAGE_SIZE = 100;

export function useLogStream() {
  const [logs, setLogs] = useState<SyslogEntry[]>([]);
  const [streamState, setStreamState] = useState<StreamState>("running");
  const [connected, setConnected] = useState(false);
  const [bufferedCount, setBufferedCount] = useState(0);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [totalInDb, setTotalInDb] = useState(0);

  const eventSourceRef = useRef<EventSource | null>(null);
  const bufferRef = useRef<SyslogEntry[]>([]);
  const nextPageRef = useRef(Math.ceil(INIT_SIZE / PAGE_SIZE) + 1);
  const idSetRef = useRef(new Set<string>());
  const streamStateRef = useRef<StreamState>("running");
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connectStream = useCallback(() => {
    eventSourceRef.current?.close();
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }

    const es = new EventSource("/api/logs?stream=true");
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnected(true);
    };

    es.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "init") {
        const initLogs: SyslogEntry[] = (data.logs as SyslogEntry[]).reverse();
        const ids = new Set(initLogs.map((l) => l.id));
        idSetRef.current = ids;
        setLogs(initLogs);
        nextPageRef.current = Math.ceil(INIT_SIZE / PAGE_SIZE) + 1;

        fetch(`/api/logs?page=1&pageSize=1`)
          .then((r) => r.json())
          .then((d: PaginatedResponse) => {
            setTotalInDb(d.total);
            setHasMore(d.total > initLogs.length);
          })
          .catch(() => {});
      } else if (data.type === "log") {
        const entry = data.entry as SyslogEntry;
        if (idSetRef.current.has(entry.id)) return;
        idSetRef.current.add(entry.id);

        if (streamStateRef.current === "paused") {
          bufferRef.current.push(entry);
          setBufferedCount(bufferRef.current.length);
        } else {
          setLogs((prev) => {
            const next = [...prev, entry];
            if (next.length > MAX_LOGS) {
              const trimmed = next.slice(next.length - MAX_LOGS);
              const newIds = new Set(trimmed.map((l) => l.id));
              idSetRef.current = newIds;
              setHasMore(true);
              return trimmed;
            }
            return next;
          });
        }
      }
    };

    es.onerror = () => {
      setConnected(false);
      es.close();
      retryTimeoutRef.current = setTimeout(connectStream, 3000);
    };
  }, []);

  const start = useCallback(() => {
    streamStateRef.current = "running";
    setStreamState("running");
    setBufferedCount(0);
    bufferRef.current = [];
    connectStream();
  }, [connectStream]);

  const pause = useCallback(() => {
    streamStateRef.current = "paused";
    setStreamState("paused");
  }, []);

  const resume = useCallback(() => {
    streamStateRef.current = "running";
    setStreamState("running");
    if (bufferRef.current.length > 0) {
      setLogs((prev) => {
        const next = [...prev, ...bufferRef.current];
        bufferRef.current = [];
        setBufferedCount(0);
        if (next.length > MAX_LOGS) {
          const trimmed = next.slice(next.length - MAX_LOGS);
          const newIds = new Set(trimmed.map((l) => l.id));
          idSetRef.current = newIds;
          setHasMore(true);
          return trimmed;
        }
        return next;
      });
    } else {
      setBufferedCount(0);
    }
  }, []);

  const stop = useCallback(() => {
    streamStateRef.current = "stopped";
    setStreamState("stopped");
    eventSourceRef.current?.close();
    eventSourceRef.current = null;
    setConnected(false);
    bufferRef.current = [];
    setBufferedCount(0);
  }, []);

  const loadMore = useCallback(async () => {
    if (isLoadingMore || !hasMore) return;
    setIsLoadingMore(true);
    try {
      const params = new URLSearchParams();
      params.set("page", String(nextPageRef.current));
      params.set("pageSize", String(PAGE_SIZE));
      const res = await fetch(`/api/logs?${params}`);
      const data: PaginatedResponse = await res.json();

      const newLogs = data.logs
        .reverse()
        .filter((l) => !idSetRef.current.has(l.id));
      for (const l of newLogs) idSetRef.current.add(l.id);

      if (newLogs.length > 0) {
        setLogs((prev) => [...newLogs, ...prev]);
      }

      nextPageRef.current++;
      setHasMore(nextPageRef.current <= data.totalPages);
      setTotalInDb(data.total);
    } finally {
      setIsLoadingMore(false);
    }
  }, [isLoadingMore, hasMore]);

  const clearLogs = useCallback(() => {
    setLogs([]);
    idSetRef.current.clear();
    bufferRef.current = [];
    setBufferedCount(0);
    setHasMore(false);
    setTotalInDb(0);
    nextPageRef.current = Math.ceil(INIT_SIZE / PAGE_SIZE) + 1;
  }, []);

  useEffect(() => {
    connectStream();
    return () => {
      eventSourceRef.current?.close();
      if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
    };
  }, [connectStream]);

  return {
    logs,
    streamState,
    connected,
    start,
    pause,
    resume,
    stop,
    loadMore,
    hasMore,
    bufferedCount,
    isLoadingMore,
    clearLogs,
    totalInDb,
  };
}
