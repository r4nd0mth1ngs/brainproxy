// React's side of the action registry (actions.ts): views add their actions while mounted, and
// the window's key presses run the bound ones.

import { useEffect, useRef, useSyncExternalStore } from "react";
import { actionFor, actions, actionsChanged, actionsVersion, bindingOf, currentOverrides, register, subscribeActions, subscribeBindings, type Action, type Overrides } from "./actions.ts";
import { chordOf, formatChord, isMac } from "./chords.ts";

/**
 * Adds `list` to the registry while the component is mounted. Each use reads the latest render's
 * actions, so titles, `disabled` and `run` stay current without registering again; only a
 * change in which ids are listed does.
 */
export function useActions(list: Action[]): void {
  const ref = useRef(list);
  ref.current = list;
  const ids = list.map((a) => a.id).join("\n");
  // What the palette and Settings show of them: when it changes, they show it again.
  const shown = JSON.stringify(list.map((a) => [a.title, a.disabled, a.hidden]));
  const lastShown = useRef(shown);
  useEffect(() => {
    if (shown === lastShown.current) return;
    lastShown.current = shown;
    actionsChanged();
  }, [shown]);
  useEffect(() => {
    if (!ids) return;
    return register(
      ids.split("\n").map((id) => ({
        id,
        // Gone from the latest render but not yet unregistered: hidden.
        get: () => ref.current.find((a) => a.id === id) ?? { id, title: id, group: "", hidden: true },
      })),
    );
  }, [ids]);
}

/** Every registered action, again whenever one is added or removed. */
export function useActionList(): Action[] {
  useSyncExternalStore(subscribeActions, actionsVersion);
  return actions();
}

/** The person's changed bindings, again whenever they change. */
export function useOverrides(): Overrides {
  return useSyncExternalStore(subscribeBindings, currentOverrides);
}

/** Whether a modal dialog (the palette, a confirmation, ...) or a right-click menu is open: shortcuts wait for it to close. */
const dialogOpen = () => typeof document !== "undefined" && !!document.querySelector('[aria-modal="true"], .menu');

/**
 * Runs the action bound to each key press in the window, for the view that shows. A press
 * another handler took (preventDefault), one while composing text (an IME), and held keys
 * repeating don't run anything.
 */
export function useShortcuts(view: string, mac: boolean): void {
  const viewRef = useRef(view);
  viewRef.current = view;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing) return;
      const chord = chordOf(e, mac);
      if (!chord || dialogOpen()) return;
      const a = actionFor(actions(), currentOverrides(), chord, viewRef.current, e.target as HTMLElement | null, mac);
      if (!a) return;
      e.preventDefault();
      if (e.repeat || a.disabled) return;
      a.run?.();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mac]);
}

/** The action's shortcut as this platform shows it ("⌘↩", "Ctrl+Enter"), or "" for none: for button tooltips. */
export function useKeyLabel(id: string): string {
  const overrides = useOverrides();
  const a = useActionList().find((x) => x.id === id);
  const chord = a ? bindingOf(a, overrides) : null;
  return chord ? formatChord(chord, isMac()) : "";
}

/** `text`, with the action's shortcut after it in brackets when it has one. */
export const withKey = (text: string, key: string) => (key ? `${text} (${key})` : text);
