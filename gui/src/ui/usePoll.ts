import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Calls `apply` with each promise's value, except one that settles after a later call's value was
 * applied: polls can overlap, and a slow older one must not undo a newer answer.
 */
export function inOrder<T>(apply: (value: T) => void): (p: Promise<T>) => void {
  let issued = 0;
  let applied = 0;
  return (p) => {
    const n = ++issued;
    p.then(
      (v) => {
        if (n < applied) return;
        applied = n;
        apply(v);
      },
      () => {},
    );
  };
}

/** Calls `load` now and every `ms` while the window is visible; returns [data, refreshNow]. */
export function usePoll<T>(load: () => Promise<T>, ms: number, enabled = true): [T | null, () => void] {
  const [data, setData] = useState<T | null>(null);
  const loader = useRef(load);
  loader.current = load;
  const [accept] = useState(() => inOrder<T>(setData));
  const refresh = useCallback(() => {
    accept(loader.current());
  }, [accept]);
  useEffect(() => {
    if (!enabled) return;
    refresh();
    const t = setInterval(() => document.visibilityState === "visible" && refresh(), ms);
    return () => clearInterval(t);
  }, [ms, enabled, refresh]);
  return [data, refresh];
}
