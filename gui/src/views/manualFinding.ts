// A finding written up by hand: the form behind "New finding…" (Findings) and "Create
// finding…" (Traffic, Replay), and the `findings add` call it becomes; and the same form
// editing one ("Edit…" in Findings), with the `findings edit` call. Nothing is sent.

import type { Finding, Risk } from "../api";

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
  /** Replace the description and solution that findings with this title share (`--replace-text`). */
  replaceText: boolean;
}

/**
 * How a finding added with `findings add` came in, by its `origin`: an agent's (MCP) isn't a
 * person's manual testing, so it never reads as "by hand", as the reports say.
 */
export function addedBy(origin: string | null | undefined): { tag: string; text: string } {
  return origin === "mcp" ? { tag: "via MCP", text: "Added via MCP (an agent)" } : { tag: "by hand", text: "Added by hand" };
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
    replaceText: false,
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
    if (u.username || u.password) return "Leave the user name and password out of the URL: they would show in every report.";
  }
  if (f.url.trim() && !/^[A-Za-z0-9_-]+$/.test(f.method.trim())) return "The method is one word, such as GET or POST.";
  if (f.cwe.trim() && !/^[1-9]\d*$/.test(f.cwe.trim())) return "The CWE is a number, such as 639.";
  return null;
}

/**
 * The `findings add` call. The URL, method, description, solution and evidence go on stdin as
 * JSON (`--input-json`): a URL from Traffic may carry a token in its query, evidence is often
 * copied from a response, and arguments are visible in the process list. The rest are flags.
 */
export function findingAddArgs(f: FindingForm): { args: string[]; stdin?: string } {
  const args = ["findings", "add", `--title=${f.title.trim()}`, `--risk=${f.risk}`, `--confidence=${f.confidence}`];
  const ids = historyIds(f.history) ?? [];
  if (ids.length) args.push(`--history-id=${ids.join(",")}`);
  if (f.param) args.push(`--param=${f.param}`);
  if (f.cwe.trim()) args.push(`--cwe=${f.cwe.trim()}`);
  if (f.replaceText) args.push("--replace-text");
  const input: Record<string, string> = {};
  // Without a URL, the CLI takes the first history entry's URL and method.
  if (f.url.trim()) {
    input.url = f.url.trim();
    input.method = f.method.trim().toUpperCase();
  }
  if (f.description.trim()) input.description = f.description.trim();
  if (f.solution.trim()) input.solution = f.solution.trim();
  if (f.evidence) input.evidence = f.evidence;
  if (!Object.keys(input).length) return { args };
  return { args: [...args, "--input-json"], stdin: JSON.stringify(input) };
}

/** Whether `findings add` refused because the description or solution differs from the one
 * findings with this title share, so the form can offer to replace it. */
export function asksToReplace(error: string): boolean {
  return error.includes("--replace-text");
}

/**
 * A draft from a Replay tab: its last response's history entry if there is one, else the
 * request line. The path is kept as written: resolving it as a URL would turn
 * `/public/%2e%2e/admin` into `/admin`, and that path is often the finding.
 */
export function draftFromRequest(raw: string, target: string, historyId?: number, url?: string): FindingDraft {
  const [method, path] = (raw.split(/\r?\n/, 1)[0] ?? "").split(/\s+/);
  let where = url ?? "";
  if (!where && path) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path)) where = path;
    else if (target && path.startsWith("/")) {
      try {
        const t = new URL(target);
        where = `${t.protocol}//${t.host}${path}`;
      } catch {
        where = "";
      }
    }
  }
  return { method: method || undefined, url: where || undefined, history: historyId != null ? [historyId] : [] };
}

/** The form holding a finding added by hand, to edit it. */
export function formFromFinding(f: Finding): FindingForm {
  const confidence = (["low", "medium", "high"] as const).find((c) => c === f.confidence) ?? "medium";
  return {
    title: f.name,
    risk: f.risk,
    confidence,
    method: f.method,
    url: f.url,
    param: f.param ?? "",
    cwe: f.cwe != null ? String(f.cwe) : "",
    history: (f.history_ids ?? []).join(", "),
    description: f.description ?? "",
    solution: f.solution ?? "",
    evidence: f.evidence ?? "",
    replaceText: false,
  };
}

/** Why the edited form can't be saved yet, or null. A finding always has a URL. */
export function editProblem(f: FindingForm): string | null {
  if (!f.url.trim()) return "Give the URL where the issue is.";
  return formProblem(f);
}

/** The fields an edit changes, as `findings edit` names them: what differs from the finding as it was. */
export function formChanges(before: FindingForm, after: FindingForm): string[] {
  const same = (a: number[] | null, b: number[] | null) => JSON.stringify(a) === JSON.stringify(b);
  const changed: [string, boolean][] = [
    ["title", after.title.trim() !== before.title.trim()],
    ["risk", after.risk !== before.risk],
    ["confidence", after.confidence !== before.confidence],
    ["method", after.method.trim().toUpperCase() !== before.method.trim().toUpperCase()],
    ["url", after.url.trim() !== before.url.trim()],
    ["param", after.param !== before.param],
    ["cwe", after.cwe.trim() !== before.cwe.trim()],
    ["history_ids", !same(historyIds(after.history), historyIds(before.history))],
    ["evidence", after.evidence !== before.evidence],
    ["description", after.description.trim() !== before.description.trim()],
    ["solution", after.solution.trim() !== before.solution.trim()],
  ];
  return changed.filter(([, c]) => c).map(([k]) => k);
}

/**
 * The `findings edit` call for what changed, or null when nothing did. As for `findings add`,
 * the URL, method and texts go on stdin as JSON. A changed description or solution passes
 * --replace-text when the title stays: the dialog says they are shared by every finding with
 * it. With a new title they would replace the write-up of the findings it joins, which the
 * dialog didn't name, so that is asked first, as for a new finding (`replaceText`). The
 * revision makes a finding changed elsewhere since it was opened fail rather than be overwritten.
 */
export function findingEditArgs(id: number, before: FindingForm, after: FindingForm, revision?: string): { args: string[]; stdin?: string } | null {
  const changed = new Set(formChanges(before, after));
  if (!changed.size) return null;
  const args = ["findings", "edit", String(id)];
  if (changed.has("title")) args.push(`--title=${after.title.trim()}`);
  if (changed.has("risk")) args.push(`--risk=${after.risk}`);
  if (changed.has("confidence")) args.push(`--confidence=${after.confidence}`);
  if (changed.has("param")) args.push(`--param=${after.param}`);
  if (changed.has("cwe")) args.push(`--cwe=${after.cwe.trim() || "0"}`);
  if (changed.has("history_ids")) {
    const ids = historyIds(after.history) ?? [];
    args.push(ids.length ? `--history-id=${ids.join(",")}` : "--no-history");
  }
  const texts = changed.has("description") || changed.has("solution");
  if (after.replaceText || (texts && !changed.has("title"))) args.push("--replace-text");
  if (revision) args.push(`--if-revision=${revision}`);
  const input: Record<string, string> = {};
  if (changed.has("url")) input.url = after.url.trim();
  if (changed.has("method")) input.method = after.method.trim().toUpperCase();
  if (changed.has("description")) input.description = after.description.trim();
  if (changed.has("solution")) input.solution = after.solution.trim();
  if (changed.has("evidence")) input.evidence = after.evidence;
  if (!Object.keys(input).length) return { args };
  return { args: [...args, "--input-json"], stdin: JSON.stringify(input) };
}
