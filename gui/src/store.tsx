// App-wide state: the open project, the active tool tab, cross-tool "send to" actions,
// and toasts. Each view keeps its own data and fetches it through api.ts.

import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

export type Tab =
  | "dashboard"
  | "target"
  | "proxy"
  | "repeater"
  | "fuzzer"
  | "scanner"
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
}

export interface RepeaterTab extends Handoff {
  key: number;
  title: string;
}

interface Toast {
  id: number;
  text: string;
  kind: "info" | "error";
}

/** An open temporary project: wiped when it closes. Not RAM-backed where the OS has no RAM folder. */
export interface TempInfo {
  ramBacked: boolean;
}

interface State {
  project: string;
  /** Set when the project is temporary. */
  temp: TempInfo | null;
  /** Saves a temporary project to a file the user picks, then switches to it. */
  saveAs: () => Promise<void>;
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
  toast: (text: string, kind?: Toast["kind"]) => void;
  /** The guided scan on the Overview, opened on request (it also shows by itself until a project has a scan). */
  wizardOpen: boolean;
  openWizard: (open: boolean) => void;
}

const Ctx = createContext<State | null>(null);

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
  const nextKey = useRef(1);

  const toast = useCallback((text: string, kind: Toast["kind"] = "info") => {
    const id = nextKey.current++;
    setToasts((t) => [...t, { id, text, kind }]);
    // Long messages (instructions) stay up long enough to read.
    const ms = Math.max(kind === "error" ? 7000 : 3500, text.length * 60);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), ms);
  }, []);

  const setRepeater = useCallback((f: (tabs: RepeaterTab[]) => RepeaterTab[]) => setRepeaterState(f), []);

  const sendToRepeater = useCallback((h: Handoff) => {
    const key = nextKey.current++;
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
      saveAs,
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
    }),
    [project, temp, saveAs, tab, repeater, setRepeater, repeaterActive, sendToRepeater, fuzzerInput, sendToFuzzer, comparer, sendToComparer, toasts, toast, wizardOpen, openWizard],
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
