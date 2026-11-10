// Access control across users (`authz`): the arguments for a run, and `authz matrix` as a grid
// of requests by identities, each cell coloured by its verdict.

import { authzOptIns, type HistoryPick } from "./trafficActions.ts";

export interface MatrixCell {
  verdict: string;
  confidence: string | null;
  status: number | null;
  history_id: number | null;
}

export interface MatrixRequest {
  source_id: number | null;
  method: string;
  url: string;
  owner: string;
  baseline_history_id: number | null;
  baseline_status: number | null;
  cells: Record<string, MatrixCell>;
  /** Why there is nothing to compare (`skipped: …`, `error: …`). */
  skipped?: string;
  /** Why it is noise (`authz matrix --all`): a static asset, or a request matching a skip path. */
  hidden?: string;
}

export interface Matrix {
  run_id: number;
  identities: string[];
  requests: MatrixRequest[];
  truncated: boolean;
  /** Requests left out as noise (without `--all`). */
  hidden_requests?: { static_assets: number; skip_paths: number };
}

export interface AuthzRun {
  run_id: number;
  time: string;
  state: string;
  args: string[];
  verdicts: Record<string, number>;
}

export type CellKind = "bypass-high" | "bypass-medium" | "bypass-low" | "public" | "different" | "inconclusive" | "enforced" | "error" | "none";

/** Most severe first: the order of the legend and of "worst first" sorting. */
export const KINDS: CellKind[] = ["bypass-high", "bypass-medium", "bypass-low", "public", "different", "inconclusive", "enforced", "error", "none"];

export const KIND_LABEL: Record<CellKind, string> = {
  "bypass-high": "bypass (high)",
  "bypass-medium": "bypass (medium)",
  "bypass-low": "bypass (low)",
  public: "public",
  different: "different",
  inconclusive: "inconclusive",
  enforced: "enforced",
  error: "error",
  none: "not sent",
};

export function cellKind(c: MatrixCell | undefined): CellKind {
  if (!c) return "none";
  if (c.verdict === "bypass") return c.confidence === "high" ? "bypass-high" : c.confidence === "medium" ? "bypass-medium" : "bypass-low";
  if (c.verdict === "public" || c.verdict === "different" || c.verdict === "inconclusive" || c.verdict === "enforced" || c.verdict === "error") return c.verdict;
  return "none";
}

export interface GridCell {
  identity: string;
  kind: CellKind;
  /** Short text in the cell. */
  text: string;
  historyId: number | null;
}

export interface GridRow {
  key: string;
  /** Why it is noise, or null. */
  hidden: string | null;
  method: string;
  url: string;
  owner: string;
  baselineId: number | null;
  baselineStatus: number | null;
  skipped: string | null;
  cells: GridCell[];
  /** The most severe of its cells (`none` for a skipped row). */
  worst: CellKind;
}

export interface Grid {
  /** Identities as columns: `anonymous` first, then the order the run used. */
  columns: string[];
  rows: GridRow[];
  /** Cells per kind, skipped rows and noise not included (noise is when it is shown). */
  counts: Record<CellKind, number>;
  skipped: number;
  /** Noise rows (static assets, skip paths), shown or not: marked ones, or those the matrix left out. */
  hidden: number;
  /** Rows left out because they show no issue (`issuesOnly`). */
  quiet: number;
}

const rank = (k: CellKind) => KINDS.indexOf(k);

/** What counts as an issue: a bypass, or a response anyone gets without a session. */
export const ISSUE_KINDS: CellKind[] = ["bypass-high", "bypass-medium", "bypass-low", "public"];

/** Rows `issuesOnly` keeps: an issue, or an error (nothing was compared, so it isn't "no issue"). */
const kept = (r: GridRow) => ISSUE_KINDS.includes(r.worst) || r.cells.some((c) => c.kind === "error");

export interface GridOptions {
  /** Only rows with a cell of this kind (overrides `issuesOnly`). */
  only?: CellKind | null;
  worstFirst?: boolean;
  /** Only rows with an issue (ISSUE_KINDS) or an error. */
  issuesOnly?: boolean;
  /** Also rows that are noise: static assets and requests matching a skip path. */
  showHidden?: boolean;
}

/**
 * The matrix as rows of cells: without noise unless `showHidden`, only rows with an issue when
 * `issuesOnly`, only rows with a cell of `only`, and worst rows first.
 */
export function grid(m: Matrix, opts: GridOptions = {}): Grid {
  const columns = [...m.identities.filter((i) => i === "anonymous"), ...m.identities.filter((i) => i !== "anonymous")];
  const counts = Object.fromEntries(KINDS.map((k) => [k, 0])) as Record<CellKind, number>;
  let skipped = 0;
  const left = m.hidden_requests ? m.hidden_requests.static_assets + m.hidden_requests.skip_paths : 0;
  const hidden = m.requests.filter((r) => r.hidden).length + left;
  const requests = opts.showHidden ? m.requests : m.requests.filter((r) => !r.hidden);
  let rows: GridRow[] = requests.map((r, i) => {
    const cells = columns.map((identity): GridCell => {
      const c = r.cells[identity];
      const kind = cellKind(c);
      const text = !c ? (identity === r.owner ? "owner" : "–") : c.status != null ? `${KIND_LABEL[kind].replace(/ \(.*/, "")} ${c.status}` : KIND_LABEL[kind];
      return { identity, kind, text, historyId: c?.history_id ?? null };
    });
    if (r.skipped) skipped++;
    else for (const c of cells) counts[c.kind]++;
    const worst = r.skipped ? "none" : cells.reduce<CellKind>((w, c) => (rank(c.kind) < rank(w) ? c.kind : w), "none");
    return {
      key: `${i}:${r.source_id ?? ""}:${r.method} ${r.url}`,
      hidden: r.hidden ?? null,
      method: r.method,
      url: r.url,
      owner: r.owner,
      baselineId: r.baseline_history_id,
      baselineStatus: r.baseline_status,
      skipped: r.skipped ?? null,
      cells,
      worst,
    };
  });
  let quiet = 0;
  if (opts.only) rows = rows.filter((r) => r.cells.some((c) => c.kind === opts.only));
  else if (opts.issuesOnly) {
    const all = rows.length;
    rows = rows.filter(kept);
    quiet = all - rows.length;
  }
  if (opts.worstFirst) rows = rows.map((r, i) => [r, i] as const).sort((a, b) => rank(a[0].worst) - rank(b[0].worst) || a[1] - b[1]).map(([r]) => r);
  return { columns, rows, counts, skipped, hidden, quiet };
}

/** A run's `skipped` counts (its summary) or a live run's progress, as what wasn't tested and why. */
export function notTested(counts: Record<string, unknown> | null | undefined): string {
  if (!counts) return "";
  const n = (...keys: string[]) => keys.reduce((sum, k) => sum + (typeof counts[k] === "number" ? (counts[k] as number) : 0), 0);
  const parts: [number, string][] = [
    [n("static_assets", "skipped_static"), "static assets"],
    [n("skip_paths", "skipped_skip_paths"), "skip paths"],
    [n("head_options", "skipped_head_options"), "HEAD/OPTIONS"],
    [n("excluded_paths", "skipped_excluded_paths"), "logout paths"],
    [n("methods", "skipped_methods"), "other methods"],
    [n("no_credentials", "skipped_no_credentials"), "no credentials"],
  ];
  const text = parts.filter(([k]) => k > 0).map(([k, what]) => `${k} ${what}`);
  return text.length ? `not tested: ${text.join(" · ")}` : "";
}

/** Skip paths as typed, one per line: trimmed, without blanks or repeats. */
export function parseSkipPaths(text: string): string[] {
  return [...new Set(text.split("\n").map((l) => l.trim()).filter(Boolean))];
}

/** `authz skip set` for these paths; none clears the list. */
export function skipSetArgs(paths: string[]): string[] {
  return paths.length ? ["authz", "skip", "set", "--", ...paths] : ["authz", "skip", "set"];
}

/** What a run picker shows for a run: id, live or not, state and the bypass count. */
export function runLabel(r: AuthzRun): string {
  const live = r.args[0] === "proxy" ? " · live (proxy)" : "";
  const bypasses = r.verdicts.bypass ?? 0;
  const time = r.time.replace("T", " ").slice(0, 16);
  return `#${r.run_id} · ${time}${live} · ${r.state}${bypasses ? ` · ${bypasses} bypass${bypasses === 1 ? "" : "es"}` : ""}`;
}

/** `history`: the requests handed over from Traffic. */
export type Selection = "all" | "host" | "tag" | "where" | "history";

export interface RunForm {
  identities: string[];
  anonymous: boolean;
  /** Empty: worked out per request. */
  owner: string;
  select: Selection;
  host: string;
  tag: string;
  where: string;
  /** Requests picked in Traffic (right-click › Test access control…), tested whatever their method or path. */
  history: HistoryPick[];
  /** Comma-separated cookie names that aren't credentials. */
  keepCookies: string;
  rate: string;
  /** Test static assets too (left out by default). */
  includeStatic: boolean;
}

/** The form once a run has started: the requests from Traffic are dropped, so the next run doesn't start on them. */
export function afterStart(f: RunForm): RunForm {
  return { ...f, select: f.select === "history" ? "all" : f.select, history: [] };
}

const q = (s: string) => `'${s.replace(/'/g, "''")}'`;

const cookieNames = (s: string) => s.split(",").map((c) => c.trim()).filter(Boolean);

/** The rate as typed, or null for none; throws unless it is a number of 0 or more. */
function rateOf(s: string): string | null {
  const t = s.trim();
  if (!t) return null;
  const n = Number(t);
  if (!Number.isFinite(n) || n < 0) throw new Error("Rate must be a number of requests per second (0 or more)");
  return t;
}

/** A host from what was typed: a bare host, host:port, or a URL. */
export function hostOf(text: string): string {
  const t = text.trim();
  if (!t) return "";
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `http://${t}`).hostname;
  } catch {
    return t;
  }
}

/** Throws with a message to show when the form can't make a run. */
export function runArgs(f: RunForm, confirmed = false): string[] {
  if (!f.identities.length && !f.anonymous) throw new Error("Pick at least one identity, or keep the anonymous control on");
  const args = ["authz", "run"];
  if (f.identities.length) args.push(`--as=${f.identities.join(",")}`);
  if (f.owner) args.push(`--owner=${f.owner}`);
  if (!f.anonymous) args.push("--no-anonymous");
  if (f.select === "host") {
    const host = hostOf(f.host);
    if (!host) throw new Error("Enter the site's host");
    args.push(`--where=host = ${q(host)}`);
  } else if (f.select === "tag") {
    if (!f.tag.trim()) throw new Error("Enter a tag");
    args.push(`--tag=${f.tag.trim()}`);
  } else if (f.select === "where") {
    if (!f.where.trim()) throw new Error("Enter a SQL condition on history");
    args.push(`--where=${f.where.trim()}`);
  } else if (f.select === "history") {
    if (!f.history.length) throw new Error("No request picked: right-click one in Proxy › Traffic");
    for (const h of f.history) args.push(`--history-id=${h.id}`);
    // authz refuses a named request that can change data or looks like a logout unless it is
    // opted in to, which only the user's yes to `accessConfirm` does.
    if (confirmed) args.push(...authzOptIns(f.history));
  }
  const cookies = cookieNames(f.keepCookies);
  if (cookies.length) args.push(`--keep-cookie=${cookies.join(",")}`);
  const rate = rateOf(f.rate);
  if (rate != null) args.push(`--rate=${rate}`);
  // Requests from Traffic are tested as they are, static or not.
  if (f.includeStatic && f.select !== "history") args.push("--include-static");
  return args;
}

/** `proxy start` options for live testing with the form's identities, cookies, rate and static assets. Throws like `runArgs`. */
export function liveArgs(f: Pick<RunForm, "identities" | "anonymous" | "keepCookies" | "rate" | "includeStatic">): string[] {
  if (!f.identities.length && !f.anonymous) throw new Error("Pick at least one identity, or keep the anonymous control on");
  const args = [`--authz=${[...(f.anonymous ? ["anonymous"] : []), ...f.identities].join(",")}`];
  const cookies = cookieNames(f.keepCookies);
  if (cookies.length) args.push(`--authz-keep-cookie=${cookies.join(",")}`);
  const rate = rateOf(f.rate);
  if (rate != null) args.push(`--authz-rate=${rate}`);
  if (f.includeStatic) args.push("--authz-include-static");
  return args;
}

/** `proxy run` options that take a value; the others (--verify-tls, --no-http2, --invisible) are flags. */
const VALUE_OPTIONS = ["--listen", "--timeout", "--wait", "--log", "--auth", "--redirect", "--authz", "--authz-rate", "--authz-queue", "--authz-exclude", "--authz-keep-cookie", "--authz-skip-path"];

/** Live options the form sets whether on or off: an old one goes when the form leaves it off. */
const FORM_FLAGS = ["--authz-include-static"];

/**
 * The options a running proxy was started with (its `proxy run` arguments, from `proxy status`), as
 * `--name=value`, to start it again with them: without the address and log, which the restart sets.
 */
export function proxyOptions(args: string[]): string[] {
  const rest = args[0] === "proxy" ? args.slice(2) : args;
  const out: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const eq = a.startsWith("--") ? a.indexOf("=") : -1;
    const name = eq > 0 ? a.slice(0, eq) : a;
    const value = eq > 0 ? a.slice(eq + 1) : VALUE_OPTIONS.includes(a) ? (rest[++i] ?? "") : null;
    if (name === "--listen" || name === "--log" || name === "--wait") continue;
    out.push(value == null ? name : `${name}=${value}`);
  }
  return out;
}

/** `options` from `proxyOptions` with `live` from `liveArgs` on top: what `live` doesn't set (the queue, the exclude, skip paths) stays. */
export function withLive(options: string[], live: string[]): string[] {
  const names = [...live.map((o) => o.split("=", 1)[0]), ...FORM_FLAGS];
  return [...options.filter((o) => !names.includes(o.split("=", 1)[0])), ...live];
}
