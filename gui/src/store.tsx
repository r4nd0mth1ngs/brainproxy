// App-wide state: the open project, the active tool tab, cross-tool "send to" actions,
// and toasts. Each view keeps its own data and fetches it through api.ts.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { run } from "./api";
import { proxyControl, type ProxyControl } from "./views/proxyPort";
import { LIST_ARGS, SAVE_ARGS, fromSaved, saver, toSaved } from "./views/replayTabs";

export type Tab =
  | "dashboard"
  | "target"
  | "proxy"
  | "repeater"
  | "fuzzer"
  | "scanner"
  | "access"
  | "findings"
  | "oob"
  | "decoder"
  | "comparer"
  | "settings";

/** A request handed from one tool to another: raw HTTP text plus where to send it. */
export interface Handoff {
  raw: string;
  target: string; // scheme://host[:port]
  title?: string;
  /** `raw` holds a binary body, one char per byte (see `bodyText`); send it with `textBytes(raw, true)`. */
  binary?: boolean;
  /** A WebSocket handshake: Replay opens it in WebSocket mode with these messages to send. */
  ws?: string[];
}

export interface RepeaterTab extends Handoff {
  key: number;
  title: string;
  /** A WebSocket tab's Listen seconds and Until regex. */
  wsWait?: number;
  wsUntil?: string;
}

interface Toast {
  id: number;
  text: string;
  kind: "info" | "error";
  /** Runs when the toast is clicked. */
  onClick?: () => void;
}

/** An open temporary project: deleted when the user discards it. Not RAM-backed where the OS has no RAM folder. */
export interface TempInfo {
  ramBacked: boolean;
}

interface State {
  project: string;
  /** Set when the project is temporary. */
  temp: TempInfo | null;
  /** Saves a temporary project to a file the user picks, then switches to it. */
  saveAs: () => Promise<void>;
  /** Saves Replay's tabs to the project now instead of after the usual pause (the window is closing). */
  flushReplayTabs: () => Promise<void>;
  tab: Tab;
  setTab: (t: Tab) => void;
  repeater: RepeaterTab[];
  setRepeater: (f: (tabs: RepeaterTab[]) => RepeaterTab[]) => void;
  repeaterActive: number;
  setRepeaterActive: (key: number) => void;
  sendToRepeater: (h: Handoff) => void;
  fuzzerInput: Handoff | null;
  sendToFuzzer: (h: Handoff) => void;
  comparer: string[];
  sendToComparer: (text: string) => void;
  setComparer: (items: string[]) => void;
  toasts: Toast[];
  toast: (text: string, kind?: Toast["kind"], onClick?: () => void) => void;
  /** The guided scan on the Overview, opened on request (it also shows by itself until a project has a scan). */
  wizardOpen: boolean;
  openWizard: (open: boolean) => void;
  /** The proxy the app started in this project (stopped when it closes); pass it to proxyPort.ts's helpers. */
  proxy: ProxyControl;
}

const Ctx = createContext<State | null>(null);

// Keys of tabs and toasts. Not per project: Replay keeps send history by tab key while the app runs.
let nextKey = 1;
const newKey = () => nextKey++;

/** How long Replay's tabs stay unchanged before they are saved to the project. */
const SAVE_TABS_AFTER_MS = 1000;

export function useApp(): State {
  const s = useContext(Ctx);
  if (!s) throw new Error("useApp outside AppProvider");
  return s;
}

export function AppProvider({
  project,
  temp,
  saveAs,
  children,
}: {
  project: string;
  temp: TempInfo | null;
  saveAs: () => Promise<void>;
  children: ReactNode;
}) {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [repeater, setRepeaterState] = useState<RepeaterTab[]>([]);
  const [repeaterActive, setRepeaterActive] = useState(0);
  const [fuzzerInput, setFuzzerInput] = useState<Handoff | null>(null);
  const [comparer, setComparer] = useState<string[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [wizardOpen, setWizardOpen] = useState(false);
  // Mutated in place: the views read it when they act, nothing renders from it.
  const proxy = useRef(proxyControl()).current;

  const toast = useCallback((text: string, kind: Toast["kind"] = "info", onClick?: () => void) => {
    const id = newKey();
    setToasts((t) => [...t, { id, text, kind, onClick }]);
    // Long messages (instructions) stay up long enough to read.
    const ms = Math.max(kind === "error" ? 7000 : 3500, text.length * 60);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), ms);
  }, []);

  const setRepeater = useCallback((f: (tabs: RepeaterTab[]) => RepeaterTab[]) => setRepeaterState(f), []);

  // Replay's tabs live in the project file (`replay tabs list/save`): restored when it opens,
  // saved a moment after they change and when it closes. Nothing is saved until they have been
  // read, so a failed read never replaces the saved ones.
  const [tabsLoaded, setTabsLoaded] = useState(false);
  const toastRef = useRef(toast);
  toastRef.current = toast;
  const saverRef = useRef<ReturnType<typeof saver> | null>(null);
  saverRef.current ??= saver({
    save: (body) => run(SAVE_ARGS, { stdin: body, project }),
    delay: SAVE_TABS_AFTER_MS,
    onError: (e) => toastRef.current(`Replay tabs weren't saved to the project: ${e.message}. They stay open here.`, "error"),
  });
  const tabSaver = saverRef.current;
  const tempRef = useRef(temp);
  tempRef.current = temp;
  useEffect(() => {
    let cancelled = false;
    run(LIST_ARGS, { project })
      .then((data) => {
        if (cancelled) return;
        const saved = fromSaved(data, newKey);
        tabSaver.loaded(JSON.stringify(toSaved(saved.tabs, saved.activeKey ?? 0)));
        // Tabs sent here while they loaded stay, after the saved ones.
        setRepeaterState((cur) => [...saved.tabs, ...cur]);
        if (saved.activeKey != null) setRepeaterActive((cur) => cur || saved.activeKey!);
        setTabsLoaded(true);
      })
      .catch((e) => {
        if (!cancelled) toastRef.current(`Replay tabs weren't restored: ${e.message}. Changes to them aren't saved until the project is opened again.`, "error");
      });
    return () => {
      cancelled = true;
      // A temporary project is being discarded, or was just saved elsewhere (which saves first).
      if (tempRef.current) tabSaver.cancel();
      else void tabSaver.flush();
    };
  }, [project, tabSaver]);
  useEffect(() => {
    if (tabsLoaded) tabSaver.schedule(JSON.stringify(toSaved(repeater, repeaterActive)));
  }, [tabsLoaded, repeater, repeaterActive, tabSaver]);
  const flushReplayTabs = useCallback(() => tabSaver.flush(), [tabSaver]);
  const saveAsWithTabs = useCallback(async () => {
    await tabSaver.flush();
    await saveAs();
  }, [tabSaver, saveAs]);

  const sendToRepeater = useCallback((h: Handoff) => {
    const key = newKey();
    setRepeaterState((tabs) => [...tabs, { ...h, key, title: h.title ?? String(tabs.length + 1) }]);
    setRepeaterActive(key);
    setTab("repeater");
  }, []);

  const sendToFuzzer = useCallback((h: Handoff) => {
    setFuzzerInput({ ...h });
    setTab("fuzzer");
  }, []);

  const openWizard = useCallback((open: boolean) => {
    setWizardOpen(open);
    if (open) setTab("dashboard");
  }, []);

  const sendToComparer = useCallback(
    (text: string) => {
      setComparer((items) => [...items, text].slice(-12));
      toast("Sent to Diff");
    },
    [toast],
  );

  const value = useMemo<State>(
    () => ({
      project,
      temp,
      saveAs: saveAsWithTabs,
      flushReplayTabs,
      tab,
      setTab,
      repeater,
      setRepeater,
      repeaterActive,
      setRepeaterActive,
      sendToRepeater,
      fuzzerInput,
      sendToFuzzer,
      comparer,
      sendToComparer,
      setComparer,
      toasts,
      toast,
      wizardOpen,
      openWizard,
      proxy,
    }),
    [project, temp, saveAsWithTabs, flushReplayTabs, tab, repeater, setRepeater, repeaterActive, sendToRepeater, fuzzerInput, sendToFuzzer, comparer, sendToComparer, toasts, toast, wizardOpen, openWizard, proxy],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** scheme://host[:port] of a URL, used as a Repeater/Fuzzer target. */
export function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

export const AUTO_PROXY = "auto-proxy";

/** Whether the proxy starts when a project opens (Settings > Project; on by default). */
export function autoProxy(): boolean {
  try {
    return localStorage.getItem(AUTO_PROXY) !== "off";
  } catch {
    return true;
  }
}
