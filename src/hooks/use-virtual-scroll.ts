"use client";

import { useEffect, useRef, useState, useCallback, useMemo } from "react";

const OVERSCAN = 10;

export function useVirtualScroll<T>(
  items: T[],
  rowHeight: number,
  opts?: { autoScrollToTop?: boolean; autoScrollDep?: unknown }
) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewHeight, setViewHeight] = useState(800);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) =>
      setViewHeight(entry.contentRect.height)
    );
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (opts?.autoScrollToTop && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [opts?.autoScrollToTop, opts?.autoScrollDep]);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setScrollTop(el.scrollTop);
  }, []);

  const isNearTop = scrollTop < rowHeight * 2;

  const virtualData = useMemo(() => {
    const totalHeight = items.length * rowHeight;
    const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
    const endIdx = Math.min(
      items.length,
      Math.ceil((scrollTop + viewHeight) / rowHeight) + OVERSCAN
    );
    const offsetTop = startIdx * rowHeight;
    return {
      totalHeight,
      offsetTop,
      visible: items.slice(startIdx, endIdx),
    };
  }, [items, scrollTop, viewHeight, rowHeight]);

  const scrollToTop = useCallback(() => {
    scrollRef.current?.scrollTo(0, 0);
  }, []);

  return {
    scrollRef,
    handleScroll,
    virtualData,
    isNearTop,
    scrollToTop,
  };
}
