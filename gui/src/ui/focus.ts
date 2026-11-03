// Keeping keyboard focus inside a modal dialog.

/** What can take focus by Tab inside a dialog, in document order. */
export const FOCUSABLE = "button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex='-1'])";

/**
 * Where Tab (or Shift+Tab when `back`) moves focus among `count` focusable elements from the one
 * at `at` (-1 when focus is on none of them), or null when the browser's own move stays inside.
 */
export function trapTab(at: number, count: number, back: boolean): number | null {
  if (count === 0) return null;
  if (at < 0) return back ? count - 1 : 0;
  if (back && at === 0) return count - 1;
  if (!back && at === count - 1) return 0;
  return null;
}

/** A keydown handler's part for Tab: keeps focus inside `box`. */
export function keepFocusIn(box: HTMLElement | null, e: { key: string; shiftKey: boolean; preventDefault: () => void }) {
  if (e.key !== "Tab" || !box) return;
  const list = Array.from(box.querySelectorAll<HTMLElement>(FOCUSABLE));
  const next = trapTab(list.indexOf(document.activeElement as HTMLElement), list.length, e.shiftKey);
  if (next == null) return;
  e.preventDefault();
  list[next].focus();
}
