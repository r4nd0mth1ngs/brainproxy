// A finding written up by hand: the form behind "New finding…" (Findings) and "Create
// finding…" (Traffic, Replay), and the `findings add` call it becomes. Nothing is sent.

import type { Risk } from "../api";

/** What another tool hands over: where the issue is and the history entries that show it. */
export interface FindingDraft {
  url?: string;
  method?: string;
  history?: number[];
}

export interface FindingForm {
  title: string;
  risk: Risk;
  confidence: "low" | "medium" | "high";
  method: string;
  url: string;
  param: string;
  cwe: string;
  /** History ids, separated by commas or spaces. */
  history: string;
  description: string;
  solution: string;
  evidence: string;
}

export function formFromDraft(d: FindingDraft | null): FindingForm {
  return {
    title: "",
    risk: "medium",
    confidence: "medium",
    method: d?.method ?? "GET",
    url: d?.url ?? "",
    param: "",
    cwe: "",
    history: (d?.history ?? []).join(", "),
    description: "",
    solution: "",
    evidence: "",
  };
}

/** History ids from the form, or null when something in it isn't one. */
export function historyIds(text: string): number[] | null {
  const parts = text.split(/[\s,]+/).filter(Boolean).map((p) => p.replace(/^#/, ""));
  if (parts.some((p) => !/^[1-9]\d*$/.test(p))) return null;
  return [...new Set(parts.map(Number))];
}

/** Why the form can't be saved yet, or null. The CLI checks everything again. */
export function formProblem(f: FindingForm): string | null {
  if (!f.title.trim()) return "Give the finding a title.";
  if (!/[\p{L}\p{N}]/u.test(f.title)) return "The title needs at least one letter or digit.";
  const ids = historyIds(f.history);
  if (!ids) return "History entries are numbers, such as 12, 15.";
  if (!f.url.trim() && !ids.length) return "Give the URL where the issue is, or a history entry.";
  if (f.url.trim()) {
    let u: URL;
    try {
      u = new URL(f.url.trim());
    } catch {
      return "The URL must be absolute, such as https://app.example.com/orders/7.";
    }
    if (!["http:", "https:", "ws:", "wss:"].includes(u.protocol) || !u.hostname) return "The URL must start with http://, https://, ws:// or wss://.";
  }
  if (f.url.trim() && !/^[A-Za-z0-9_-]+$/.test(f.method.trim())) return "The method is one word, such as GET or POST.";
  if (f.cwe.trim() && !/^[1-9]\d*$/.test(f.cwe.trim())) return "The CWE is a number, such as 639.";
  return null;
}

/**
 * The `findings add` call. The description, the longest text, goes on stdin, so it stays off the
 * command line (limited in size on Windows); the rest are flags.
 */
export function findingAddArgs(f: FindingForm): { args: string[]; stdin?: string } {
  const args = ["findings", "add", `--title=${f.title.trim()}`, `--risk=${f.risk}`, `--confidence=${f.confidence}`];
  // Without a URL, the CLI takes the first history entry's URL and method.
  if (f.url.trim()) args.push(`--url=${f.url.trim()}`, `--method=${f.method.trim().toUpperCase()}`);
  const ids = historyIds(f.history) ?? [];
  if (ids.length) args.push(`--history-id=${ids.join(",")}`);
  if (f.param) args.push(`--param=${f.param}`);
  if (f.cwe.trim()) args.push(`--cwe=${f.cwe.trim()}`);
  if (f.solution.trim()) args.push(`--solution=${f.solution.trim()}`);
  if (f.evidence) args.push(`--evidence=${f.evidence}`);
  if (!f.description.trim()) return { args };
  return { args: [...args, "--description-file=-"], stdin: f.description.trim() };
}

/** A draft from a Replay tab: its last response's history entry if there is one, else the request line. */
export function draftFromRequest(raw: string, target: string, historyId?: number, url?: string): FindingDraft {
  const [method, path] = (raw.split(/\r?\n/, 1)[0] ?? "").split(/\s+/);
  let where = url ?? "";
  if (!where && target && path) {
    try {
      where = new URL(path, target).toString();
    } catch {
      where = "";
    }
  }
  return { method: method || undefined, url: where || undefined, history: historyId != null ? [historyId] : [] };
}
