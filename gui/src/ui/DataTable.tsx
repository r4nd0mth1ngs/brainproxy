// A dense, virtualized, sortable table with resizable columns and keyboard selection.
// Rows have a fixed height, so only the visible slice is rendered.

import { useEffect, useLayoutEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from "react";

export interface Column<T> {
  key: string;
  label: string;
  width: number;
  /** Value used for sorting (and for display when there is no render). */
  value: (row: T) => string | number | null;
  render?: (row: T) => ReactNode;
  align?: "right";
}

interface Props<T> {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => number | string;
  selected?: number | string | null;
  onSelect?: (row: T) => void;
  onActivate?: (row: T) => void;
  onContextMenu?: (row: T, e: MouseEvent) => void;
  rowClass?: (row: T) => string | undefined;
  initialSort?: { key: string; desc: boolean };
  empty?: ReactNode;
}

const ROW = 24;

export function DataTable<T>(p: Props<T>) {
  const [sort, setSort] = useState(p.initialSort ?? { key: p.columns[0].key, desc: false });
  const [widths, setWidths] = useState<Record<string, number>>({});
  const [scroll, setScroll] = useState(0);
  const [height, setHeight] = useState(400);
  const box = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const el = box.current!;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const sorted = useMemo(() => {
    const col = p.columns.find((c) => c.key === sort.key);
    if (!col) return p.rows;
    const out = [...p.rows].sort((a, b) => {
      const x = col.value(a);
      const y = col.value(b);
      if (x == null) return y == null ? 0 : 1;
      if (y == null) return -1;
      return x < y ? -1 : x > y ? 1 : 0;
    });
    return sort.desc ? out.reverse() : out;
  }, [p.rows, p.columns, sort]);

  const template = p.columns.map((c) => `${widths[c.key] ?? c.width}px`).join(" ") + " minmax(0,1fr)";
  const first = Math.max(0, Math.floor(scroll / ROW) - 10);
  const last = Math.min(sorted.length, Math.ceil((scroll + height) / ROW) + 10);
  const index = p.selected == null ? -1 : sorted.findIndex((r) => p.rowKey(r) === p.selected);

  // The selection last scrolled into view. Only a new selection (by keyboard, click or a view
  // picking one) scrolls: rows added around it (a poll, newest first) move its index, and
  // following that would pull the list back from wherever it was scrolled to on every poll.
  const revealed = useRef<number | string | null>(null);
  useEffect(() => {
    const el = box.current;
    // Not in the list (filtered out, or none): shown again when it comes back.
    if (index < 0) revealed.current = null;
    if (!el || index < 0 || revealed.current === p.selected) return;
    revealed.current = p.selected ?? null;
    const top = index * ROW;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + ROW * 2 > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW * 2 - el.clientHeight;
  }, [index, p.selected]);

  const onKey = (e: React.KeyboardEvent) => {
    if (!sorted.length || !p.onSelect) return;
    const step = { ArrowDown: 1, ArrowUp: -1, PageDown: 20, PageUp: -20 }[e.key];
    // A move with Ctrl, ⌘ or Alt is a shortcut (Replay's next tab, say), left to it.
    if (step && (e.ctrlKey || e.metaKey || e.altKey)) return;
    if (step) {
      e.preventDefault();
      p.onSelect(sorted[Math.min(sorted.length - 1, Math.max(0, (index < 0 ? -1 : index) + step))]);
    } else if (e.key === "Enter" && index >= 0) {
      p.onActivate?.(sorted[index]);
    }
  };

  const startResize = (key: string, startX: number, startW: number) => {
    const move = (e: globalThis.MouseEvent) => setWidths((w) => ({ ...w, [key]: Math.max(32, startW + e.clientX - startX) }));
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  return (
    <div className="table" tabIndex={0} onKeyDown={onKey}>
      <div className="table-head" style={{ gridTemplateColumns: template }}>
        {p.columns.map((c) => (
          <div
            key={c.key}
            className={`th ${c.align ?? ""} ${sort.key === c.key ? "sorted" : ""}`}
            onClick={() => setSort((s) => ({ key: c.key, desc: s.key === c.key ? !s.desc : false }))}
          >
            {c.label}
            {sort.key === c.key && <span className="sort">{sort.desc ? "▾" : "▴"}</span>}
            <span
              className="resize"
              onClick={(e) => e.stopPropagation()}
              onMouseDown={(e) => {
                e.preventDefault();
                startResize(c.key, e.clientX, widths[c.key] ?? c.width);
              }}
            />
          </div>
        ))}
        <div className="th" />
      </div>
      <div className="table-body" ref={box} onScroll={(e) => setScroll(e.currentTarget.scrollTop)}>
        {sorted.length === 0 ? (
          <div className="empty">{p.empty ?? "Nothing here yet."}</div>
        ) : (
          <div style={{ height: sorted.length * ROW, position: "relative" }}>
            {sorted.slice(first, last).map((row, i) => {
              const key = p.rowKey(row);
              return (
                <div
                  key={key}
                  className={`tr ${key === p.selected ? "selected" : ""} ${p.rowClass?.(row) ?? ""}`}
                  style={{ gridTemplateColumns: template, top: (first + i) * ROW }}
                  onMouseDown={() => p.onSelect?.(row)}
                  onDoubleClick={() => p.onActivate?.(row)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    p.onSelect?.(row);
                    p.onContextMenu?.(row, e);
                  }}
                >
                  {p.columns.map((c) => (
                    <div key={c.key} className={`td ${c.align ?? ""}`}>
                      {c.render ? c.render(row) : c.value(row)}
                    </div>
                  ))}
                  <div className="td" />
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
