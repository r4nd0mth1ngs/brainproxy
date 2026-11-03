// Replay state that outlives a tab's view: switching Replay tabs remounts the view, but a
// send's CLI process keeps running, so its call id (for Stop) and its result are kept here,
// keyed by tab. Tab keys start again at 1 in each opened project, so the project's shell
// clears all of it (stopping what is still in flight) when it closes.

import { useCallback, useSyncExternalStore } from "react";

/** One value per Replay tab, with a default for tabs that have none yet. */
export interface TabSlot<S> {
  get(key: number): S;
  update(key: number, f: (s: S) => S): void;
  /** The tabs that have a value of their own. */
  keys(): number[];
  subscribe(listener: () => void): () => void;
}

const slots: { clear(key?: number): void }[] = [];

export function tabSlot<S>(initial: S): TabSlot<S> {
  const values = new Map<number, S>();
  const listeners = new Set<() => void>();
  const notify = () => listeners.forEach((l) => l());
  slots.push({
    clear(key) {
      if (key == null) values.clear();
      else values.delete(key);
      notify();
    },
  });
  return {
    get: (key) => (values.has(key) ? (values.get(key) as S) : initial),
    update(key, f) {
      values.set(key, f(values.has(key) ? (values.get(key) as S) : initial));
      notify();
    },
    keys: () => [...values.keys()],
    subscribe(l) {
      listeners.add(l);
      return () => listeners.delete(l);
    },
  };
}

/** A tab's value in a slot and its updater; the view re-renders when it changes. */
export function useTabSlot<S>(slot: TabSlot<S>, key: number): [S, (f: (s: S) => S) => void] {
  const value = useSyncExternalStore(
    slot.subscribe,
    () => slot.get(key),
    () => slot.get(key),
  );
  const update = useCallback((f: (s: S) => S) => slot.update(key, f), [slot, key]);
  return [value, update];
}

/** The id of each tab's send in flight (null when there is none), so Stop finds it after a remount. */
export const replayCalls = tabSlot<string | null>(null);

let seq = 0;

/** Starts a tab's send: a fresh call id, recorded for the tab, to pass to `run`. */
export function beginCall(key: number, prefix: string): string {
  const call = `${prefix}-${key}-${Date.now()}-${++seq}`;
  replayCalls.update(key, () => call);
  return call;
}

/**
 * Ends a tab's send. True when it is still the tab's call, so its result belongs to the tab;
 * false when the tab or the project was closed meanwhile, and the result is dropped.
 */
export function endCall(key: number, call: string): boolean {
  if (replayCalls.get(key) !== call) return false;
  replayCalls.update(key, () => null);
  return true;
}

/** Stops a tab's send still waiting, if there is one. */
export function stopCall(key: number, cancel: (call: string) => Promise<void>): void {
  const call = replayCalls.get(key);
  if (call) cancel(call).catch(() => {});
}

/** How many tabs (or, given a key, whether that tab) have a send in flight. */
export function sendsInFlight(key?: number): number {
  const keys = key == null ? replayCalls.keys() : [key];
  return keys.filter((k) => replayCalls.get(k) != null).length;
}

/**
 * What a stopped send says. Stop kills the CLI, which records only once it is done (`send`
 * after the response, `ws send` at the end of the run), so a stopped send is usually missing
 * from history; but the request may already be on the wire, so it doesn't read as "not sent".
 * Stopped just after the CLI recorded, it is in history after all, hence "may".
 */
export function stoppedText(kind: "http" | "ws"): string {
  return kind === "http"
    ? "Stopped: the request may already have reached the server, and may not be in history"
    : "Stopped: the handshake and messages may already have reached the server, and may not be in history";
}

/** What a failed send says: the stopped text when it was stopped, otherwise the error. */
export function failureText(e: { kind?: string; message?: string }, kind: "http" | "ws"): string {
  return e.kind === "cancelled" ? stoppedText(kind) : String(e.message ?? e);
}

/**
 * The question to ask before closing a tab (given its key) or the project while sends are in
 * flight, or null when nothing is running. Closing stops them the same way Stop does.
 */
export function closeQuestion(key?: number): { title: string; message: string } | null {
  const n = sendsInFlight(key);
  if (!n) return null;
  const what = key != null ? "this tab" : "the project";
  const sends = n === 1 ? "A Replay send is" : `${n} Replay sends are`;
  return {
    title: `Stop ${n === 1 ? "the send" : "the sends"} still running?`,
    message: `${sends} still waiting. Closing ${what} stops ${n === 1 ? "it" : "them"}: the server may already have the request, and it may not be in history.`,
  };
}

/** Forgets a closed tab: its send is stopped, and nothing it returns lands anywhere. */
export function forgetTab(key: number, cancel: (call: string) => Promise<void>): void {
  stopCall(key, cancel);
  slots.forEach((s) => s.clear(key));
}

/** Stops every send in flight and waits until each is cancelled (before the app quits, say). */
export async function stopAllCalls(cancel: (call: string) => Promise<void>): Promise<void> {
  const calls = replayCalls.keys().map((k) => replayCalls.get(k)).filter((c): c is string => c != null);
  await Promise.all(calls.map((c) => cancel(c).catch(() => {})));
}

/** Forgets every tab, stopping their sends: the project closed, and the next one reuses the keys. */
export function clearReplayTabs(cancel: (call: string) => Promise<void>): void {
  for (const key of replayCalls.keys()) stopCall(key, cancel);
  slots.forEach((s) => s.clear());
}
