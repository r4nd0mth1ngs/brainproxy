// Keyboard focus in the app's own dialogs (Confirm, New finding): Tab and Shift+Tab stay inside
// the dialog, and when it closes focus goes back to what had it before, such as the button
// that opened it.

import { useEffect, useState, type RefObject } from "react";

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])';

/** Where Tab goes among `count` focusable elements from `current` (-1: none of them has focus). */
export function nextFocus(current: number, count: number, back: boolean): number {
  if (count === 0) return -1;
  if (current < 0) return back ? count - 1 : 0;
  return (current + (back ? count - 1 : 1)) % count;
}

/**
 * Whether focus was lost (nothing, or the page itself, has it), so a dialog that closed gives
 * it back. Not when something else took it meanwhile, such as the next dialog's field.
 */
export const focusLost = (active: Element | null, body: Element | null) => active == null || active === body;

/**
 * The dialogs open now, latest last. A question asked over a dialog (a confirmation, say) traps
 * Tab on its own: only the latest dialog moves focus, so the one under it doesn't take it back.
 */
const open: object[] = [];
export const dialogOpened = (d: object) => void open.push(d);
export const dialogClosed = (d: object) => {
  const i = open.lastIndexOf(d);
  if (i >= 0) open.splice(i, 1);
};
export const isTopDialog = (d: object) => open[open.length - 1] === d;

/** Keeps Tab inside `ref` while the component is mounted, and gives focus back when it unmounts. */
export function useDialogFocus(ref: RefObject<HTMLElement | null>) {
  // Read while rendering, before an autoFocus in the dialog moves focus.
  const [before] = useState(() => (typeof document === "undefined" ? null : (document.activeElement as HTMLElement | null)));
  useEffect(() => {
    const dialog = ref.current;
    // Its own token: the element can be absent, and the same one may mount twice (Strict Mode).
    const me = {};
    dialogOpened(me);
    const onKey = (e: KeyboardEvent) => {
      const el = ref.current;
      if (e.key !== "Tab" || !el || !isTopDialog(me)) return;
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const next = nextFocus(items.indexOf(document.activeElement as HTMLElement), items.length, e.shiftKey);
      if (next < 0) return;
      e.preventDefault();
      items[next].focus();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      dialogClosed(me);
      // Only once the dialog is gone: Strict Mode runs this cleanup and the setup again on mount,
      // with the dialog still there and its autoFocus done.
      setTimeout(() => {
        if (!dialog?.isConnected && before?.isConnected && focusLost(document.activeElement, document.body)) before.focus();
      });
    };
  }, [ref, before]);
}
