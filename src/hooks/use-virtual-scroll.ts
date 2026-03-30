"use client";

import { useEffect, useRef, useState, useCallback, useMemo } from "react";

const OVERSCAN = 10;

export function useVirtualScroll<T>(
  items: T[],
  rowHeight: number,
  opts?: { autoScrollToBottom?: boolean }
) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewHeight, setViewHeight] = useState(800);
  const prevItemCountRef = useRef(0);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) =>
      setViewHeight(entry.contentRect.height)
    );
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Auto-scroll to bottom when new items are appended and user is near bottom
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !opts?.autoScrollToBottom) return;

    const prevCount = prevItemCountRef.current;
    const newCount = items.length;
    prevItemCountRef.current = newCount;

    if (newCount <= prevCount) return;

    // Items were appended (new logs at bottom)
    const wasNearBottom =
      el.scrollHeight - el.scrollTop - el.clientHeight < rowHeight * 3;
    if (wasNearBottom) {
      requestAnimationFrame(() => {
        el.scrollTop = el.scrollHeight;
      });
    }
  }, [items.length, opts?.autoScrollToBottom, rowHeight]);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setScrollTop(el.scrollTop);
  }, []);

  const totalHeight = items.length * rowHeight;
  const isNearTop = scrollTop < rowHeight * 3;
  const isNearBottom = totalHeight - scrollTop - viewHeight < rowHeight * 3;

  const virtualData = useMemo(() => {
    const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
    const endIdx = Math.min(
      items.length,
      Math.ceil((scrollTop + viewHeight) / rowHeight) + OVERSCAN
    );
    const offsetTop = startIdx * rowHeight;
    return {
      totalHeight,
      offsetTop,
      startIdx,
      visible: items.slice(startIdx, endIdx),
    };
  }, [items, scrollTop, viewHeight, rowHeight, totalHeight]);

  const scrollToBottom = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    requestAnimationFrame(() => {
      el.scrollTop = el.scrollHeight;
    });
  }, []);

  const scrollToTop = useCallback(() => {
    scrollRef.current?.scrollTo(0, 0);
  }, []);

  const adjustScrollForPrepend = useCallback(
    (count: number) => {
      const el = scrollRef.current;
      if (!el) return;
      el.scrollTop += count * rowHeight;
    },
    [rowHeight]
  );

  return {
    scrollRef,
    handleScroll,
    virtualData,
    isNearTop,
    isNearBottom,
    scrollToTop,
    scrollToBottom,
    adjustScrollForPrepend,
  };
}
