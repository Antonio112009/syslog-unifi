"use client";

import { Radio, History, ChevronLeft, ChevronRight } from "lucide-react";
import { useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

export function StatusFooter({
  mode,
  totalCount,
  historyPage,
  historyTotalPages,
  onPageChange,
  onBrowseHistory,
  onGoLive,
}: {
  mode: "live" | "history";
  totalCount: number;
  historyPage: number;
  historyTotalPages: number;
  onPageChange: (page: number) => void;
  onBrowseHistory: () => void;
  onGoLive: () => void;
}) {
  const paginationPages = useMemo(() => {
    const pages: (number | "...")[] = [];
    const w = 2;
    for (let i = 1; i <= historyTotalPages; i++) {
      if (
        i === 1 ||
        i === historyTotalPages ||
        (i >= historyPage - w && i <= historyPage + w)
      ) {
        pages.push(i);
      } else if (pages.length > 0 && pages[pages.length - 1] !== "...") {
        pages.push("...");
      }
    }
    return pages;
  }, [historyPage, historyTotalPages]);

  return (
    <div className="flex items-center justify-between px-6 py-2 bg-card/60 backdrop-blur-sm border-t border-border/50 text-sm shrink-0">
      <span className="text-muted-foreground tabular-nums" suppressHydrationWarning>
        {totalCount.toLocaleString()} total entries
        {mode === "history" &&
          ` · Page ${historyPage} of ${historyTotalPages}`}
      </span>
      <div className="flex items-center gap-1.5">
        {mode === "history" && (
          <>
            <Button
              size="xs"
              variant="outline"
              onClick={() => onPageChange(historyPage - 1)}
              disabled={historyPage <= 1}
              className="gap-1"
            >
              <ChevronLeft className="size-3" />
              Newer
            </Button>
            {paginationPages.map((p, i) =>
              p === "..." ? (
                <span
                  key={`e${i}`}
                  className="text-muted-foreground px-1"
                >
                  ...
                </span>
              ) : (
                <Button
                  key={p}
                  size="xs"
                  variant={p === historyPage ? "default" : "outline"}
                  onClick={() => onPageChange(p as number)}
                >
                  {p}
                </Button>
              )
            )}
            <Button
              size="xs"
              variant="outline"
              onClick={() => onPageChange(historyPage + 1)}
              disabled={historyPage >= historyTotalPages}
              className="gap-1"
            >
              Older
              <ChevronRight className="size-3" />
            </Button>
            <Separator orientation="vertical" className="h-4 mx-1" />
          </>
        )}
        {mode === "live" ? (
          <Button variant="outline" size="sm" onClick={onBrowseHistory} className="gap-1.5">
            <History className="size-3" />
            Browse History
          </Button>
        ) : (
          <Button
            size="sm"
            onClick={onGoLive}
            className="bg-emerald-700 hover:bg-emerald-600 text-white border-emerald-700 gap-1.5"
          >
            <Radio className="size-3" />
            Go Live
          </Button>
        )}
      </div>
      <span className="text-xs text-muted-foreground/50">
        Made by Antonio112009
      </span>
    </div>
  );
}
