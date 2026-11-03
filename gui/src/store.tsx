// App-wide state: the open project, the active tool tab, cross-tool "send to" actions,
// and toasts. Each view keeps its own data and fetches it through api.ts.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { cancelCli, run } from "./api";
import { proxyControl, type ProxyControl } from "./views/proxyPort";
import { clearReplayTabs } from "./views/replayCalls";
import type { ReplayOptions } from "./views/replayOptions";
import { LIST_ARGS, NEWER, closingSaves, fromSaved, newerFormat, revisions, saver, toSaved } from "./views/replayTabs";
import type { HistoryPick } from "./views/trafficActions";

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
  /** Send options (HTTP/2, as typed, SNI, ...); missing means the CLI's defaults. */
  options?: Partial<ReplayOptions>;
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
  /**
   * Saves Replay's tabs to the project now instead of after the usual pause (the project or the
   * window is closing). Rejects if they couldn't be saved.
   */
  flushReplayTabs: () => Promise<void>;
  tab: Tab;
  setTab: (t: Tab) => void;
  repeater: RepeaterTab[];
  setRepeater: (f: (tabs: RepeaterTab[]) => RepeaterTab[]) => void;
  /**
   * An open Replay editor's way to pass its text up at once (it does so 300 ms after typing
   * otherwise), called before Replay's tabs are saved on close. Returns the undo.
   */
  addReplayEditor: (commit: () => void) => () => void;
  repeaterActive: number;
  setRepeaterActive: (key: number) => void;
  sendToRepeater: (h: Handoff) => void;
  fuzzerInput: Handoff | null;
  sendToFuzzer: (h: Handoff) => void;
  /** Requests handed to Access to test as other users; a new array each time. */
  accessInput: HistoryPick[] | null;
  sendToAccess: (picks: HistoryPick[]) => void;
  /** A job to show in Scans › Tasks; a new object each time, so the same job can be shown again. */
  jobFocus: { id: number } | null;
  showJob: (id: number) => void;
  comparer: string[];
  sendToComparer: (text: string) => void;
  setComparer: (items: string[]) => void;
  toasts: Toast[];
  toast: (text: string, kind?: Toast["kind"], onClick?: () => void) => void;
  /** The guided scan on the Overview, opened on request (it also shows by itself until a project has a scan). */
  wizardOpen: boolean;
  openWizard: (open: boolean) => void;
  /** Import API, opened in the Site map from elsewhere (the guided API scan) with the definition typed there. */
  apiImport: { source: string; graphql: boolean; key: number } | null;
  openApiImport: (source: string, graphql: boolean) => void;
  /** Proxy › Traffic, opened from elsewhere showing one source's requests (an import's). */
  traffic: { source: string; key: number } | null;
  openTraffic: (source: string) => void;
  /** The proxy the app started in this project (stopped when it closes); pass it to proxyPort.ts's helpers. */
  proxy: ProxyControl;
}

const Ctx = createContext<State | null>(null);

/** How long Replay's tabs stay unchanged before they are saved to the project. */
const SAVE_TABS_AFTER_MS = 1000;

// Replay tabs being saved by projects that just closed; one opened again reads its tabs after.
const closing = closingSaves();

export function useApp(): State {
  const s = useContext(Ctx);
  if (!s) throw new Error("useApp outside AppProvider");
  return s;
}

export function AppProvider({
  project,
  temp,
  saveAs,
  notice,
  children,
}: {
  project: string;
  temp: TempInfo | null;
  saveAs: () => Promise<void>;
  /** Toasted once when the project opens, e.g. what Save as… couldn't take along. */
  notice?: string;
  children: ReactNode;
}) {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [repeater, setRepeaterState] = useState<RepeaterTab[]>([]);
  const [repeaterActive, setRepeaterActiveState] = useState(0);
  const [fuzzerInput, setFuzzerInput] = useState<Handoff | null>(null);
  const [accessInput, setAccessInput] = useState<HistoryPick[] | null>(null);
  const [jobFocus, setJobFocus] = useState<{ id: number } | null>(null);
  const [comparer, setComparer] = useState<string[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [apiImport, setApiImport] = useState<State["apiImport"]>(null);
  const [traffic, setTraffic] = useState<State["traffic"]>(null);
  // Mutated in place: the views read it when they act, nothing renders from it.
  const proxy = useRef(proxyControl()).current;
  // Keys of tabs and toasts, from 1 in each project. Replay keeps sends in flight and results
  // outside its views, keyed by tab; the next project's tabs reuse the keys, so they go (and
  // the sends stop) with this project. The shell keys the provider by project, so a project
  // change always unmounts it.
  const nextKey = useRef(1);
  const newKey = useRef(() => nextKey.current++).current;
  useEffect(() => () => clearReplayTabs(cancelCli), []);

  const toast = useCallback((text: string, kind: Toast["kind"] = "info", onClick?: () => void) => {
    const id = newKey();
    setToasts((t) => [...t, { id, text, kind, onClick }]);
    // Long messages (instructions) stay up long enough to read.
    const ms = Math.max(kind === "error" ? 7000 : 3500, text.length * 60);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), ms);
  }, []);

  const noticed = useRef("");
  useEffect(() => {
    if (notice && noticed.current !== notice) {
      noticed.current = notice;
      toast(notice, "error");
    }
  }, [notice, toast]);

  // Replay's tabs as of the last change, before React renders it: a save on close reads them
  // right after the editors pass their text up.
  const repeaterRef = useRef<RepeaterTab[]>([]);
  const activeRef = useRef(0);
  const setRepeater = useCallback((f: (tabs: RepeaterTab[]) => RepeaterTab[]) => {
    repeaterRef.current = f(repeaterRef.current);
    setRepeaterState(repeaterRef.current);
  }, []);
  const setRepeaterActive = useCallback((key: number) => {
    activeRef.current = key;
    setRepeaterActiveState(key);
  }, []);
  const editors = useRef(new Set<() => void>());
  const addReplayEditor = useCallback((commit: () => void) => {
    editors.current.add(commit);
    return () => void editors.current.delete(commit);
  }, []);

  // Replay's tabs live in the project file (`replay tabs list/save`): restored when it opens,
  // saved a moment after they change and when it closes. Nothing is saved until they have been
  // read, so a failed read never replaces the saved ones. Tabs saved elsewhere meanwhile (an
  // agent's) are added here, when a save finds them or the window comes back to the front.
  const [tabsLoaded, setTabsLoaded] = useState(false);
  const tabsLoadedRef = useRef(false);
  const toastRef = useRef(toast);
  toastRef.current = toast;
  // Made only when a save is due, not on every change: it can be large.
  const tabsBody = useCallback(() => JSON.stringify(toSaved(repeaterRef.current, activeRef.current)), []);
  const revsRef = useRef<ReturnType<typeof revisions> | null>(null);
  revsRef.current ??= revisions({
    cli: (args, stdin) => run(args, stdin == null ? { project } : { stdin, project }),
    body: tabsBody,
    add: (tabs) => {
      setRepeater((cur) => [...cur, ...tabs]);
      const n = tabs.length;
      toastRef.current(`${n} Replay tab${n === 1 ? " was" : "s were"} added to the project from elsewhere (an agent or the command line)`);
    },
    count: () => repeaterRef.current.length,
    nextKey: newKey,
  });
  const tabRevs = revsRef.current;
  const saverRef = useRef<ReturnType<typeof saver> | null>(null);
  saverRef.current ??= saver({
    save: tabRevs.save,
    delay: SAVE_TABS_AFTER_MS,
    onError: (e) => toastRef.current(`Replay tabs weren't saved to the project: ${e.message}. They stay open here.`, "error"),
  });
  const tabSaver = saverRef.current;
  const tempRef = useRef(temp);
  tempRef.current = temp;
  // Closing, switching project, or Save as: the editors' last keystrokes first, then save.
  const flushReplayTabs = useCallback(() => {
    editors.current.forEach((commit) => commit());
    if (tabsLoadedRef.current) tabSaver.schedule(tabsBody);
    return tabSaver.flush();
  }, [tabSaver, tabsBody]);
  useEffect(() => {
    let cancelled = false;
    closing
      .wait(project)
      .then(() => (cancelled ? null : run(LIST_ARGS, { project })))
      .then((data) => {
        if (cancelled) return;
        const saved = fromSaved(data, newKey);
        tabSaver.loaded(JSON.stringify(toSaved(saved.tabs, saved.activeKey ?? 0)));
        tabRevs.loaded(data);
        // Tabs sent here while they loaded stay, after the saved ones.
        setRepeater((cur) => [...saved.tabs, ...cur]);
        if (saved.activeKey != null && !activeRef.current) setRepeaterActive(saved.activeKey);
        // Shown, but saving would drop what the newer version keeps.
        if (newerFormat(data)) return toastRef.current(`Replay tabs aren't saved to this project: ${NEWER}.`, "error");
        tabsLoadedRef.current = true;
        setTabsLoaded(true);
      })
      .catch((e) => {
        if (!cancelled) toastRef.current(`Replay tabs weren't restored: ${e.message}. Changes to them aren't saved until the project is opened again.`, "error");
      });
    return () => {
      cancelled = true;
      // A temporary project is being discarded, or was just saved elsewhere (which saves first).
      // Otherwise saved, and reopening it waits for that (switching project already asked
      // if the tabs couldn't be saved).
      if (tempRef.current) tabSaver.cancel();
      else closing.add(project, flushReplayTabs());
    };
  }, [project, tabSaver, tabRevs, setRepeater, setRepeaterActive, flushReplayTabs]);
  useEffect(() => {
    if (tabsLoaded) tabSaver.schedule(tabsBody);
  }, [tabsLoaded, repeater, repeaterActive, tabSaver, tabsBody]);
  // Back from the terminal where an agent saved tabs: they show up without waiting for a save.
  // A failure here is left to the next save, which reports it.
  useEffect(() => {
    if (!tabsLoaded) return;
    const check = () => void tabRevs.check().catch(() => {});
    window.addEventListener("focus", check);
    return () => window.removeEventListener("focus", check);
  }, [tabsLoaded, tabRevs]);
  // The copy holds what the project holds, and the temporary one is deleted after: with tabs
  // that couldn't be saved it stays open, so they aren't lost.
  const saveAsWithTabs = useCallback(async () => {
    await flushReplayTabs().catch((e) => {
      throw new Error(`Replay tabs couldn't be saved first (${e.message}), so the temporary engagement stays open`);
    });
    await saveAs();
  }, [flushReplayTabs, saveAs]);

  const sendToRepeater = useCallback((h: Handoff) => {
    const key = newKey();
    setRepeater((tabs) => [...tabs, { ...h, key, title: h.title ?? String(tabs.length + 1) }]);
    setRepeaterActive(key);
    setTab("repeater");
  }, [setRepeater, setRepeaterActive]);

  const sendToFuzzer = useCallback((h: Handoff) => {
    setFuzzerInput({ ...h });
    setTab("fuzzer");
  }, []);

  const sendToAccess = useCallback((picks: HistoryPick[]) => {
    setAccessInput([...picks]);
    setTab("access");
  }, []);

  const showJob = useCallback((id: number) => {
    setJobFocus({ id });
    setTab("scanner");
  }, []);

  const openWizard = useCallback((open: boolean) => {
    setWizardOpen(open);
    if (open) setTab("dashboard");
  }, []);

  const openApiImport = useCallback((source: string, graphql: boolean) => {
    setApiImport({ source, graphql, key: newKey() });
    setTab("target");
  }, []);

  const openTraffic = useCallback((source: string) => {
    setTraffic({ source, key: newKey() });
    setTab("proxy");
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
      addReplayEditor,
      repeaterActive,
      setRepeaterActive,
      sendToRepeater,
      fuzzerInput,
      sendToFuzzer,
      accessInput,
      sendToAccess,
      jobFocus,
      showJob,
      comparer,
      sendToComparer,
      setComparer,
      toasts,
      toast,
      wizardOpen,
      openWizard,
      apiImport,
      openApiImport,
      traffic,
      openTraffic,
      proxy,
    }),
    [project, temp, saveAsWithTabs, flushReplayTabs, tab, repeater, setRepeater, addReplayEditor, repeaterActive, setRepeaterActive, sendToRepeater, fuzzerInput, sendToFuzzer, accessInput, sendToAccess, jobFocus, showJob, comparer, sendToComparer, toasts, toast, wizardOpen, openWizard, apiImport, openApiImport, traffic, openTraffic, proxy],
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
