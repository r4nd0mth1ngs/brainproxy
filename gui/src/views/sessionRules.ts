// Session handling for auth profiles (macros and session rules): the shapes `auth show`
// returns, and the `auth macro` / `auth rule` arguments the Settings view builds.

export type Tool = "proxy" | "send" | "fuzz" | "crawl" | "scan" | "checks";
export const TOOLS: Tool[] = ["proxy", "send", "fuzz", "crawl", "scan", "checks"];

export type ExtractFrom = "regex" | "json" | "header" | "cookie" | "input";
export const EXTRACT_FROM: { id: ExtractFrom; label: string; hint: string }[] = [
  { id: "input", label: "HTML input", hint: "csrf_token" },
  { id: "json", label: "JSON path", hint: "data.token" },
  { id: "regex", label: "Regex (group 1)", hint: 'name="csrf" value="([^"]+)"' },
  { id: "header", label: "Header", hint: "X-CSRF-Token" },
  { id: "cookie", label: "Cookie", hint: "XSRF-TOKEN" },
];

/** A macro as `auth show` lists it. */
export interface MacroSummary {
  name: string;
  steps: number;
  vars: string[];
  /** "METHOD URL" per step. */
  requests: string[];
}

export type Action =
  | { action: "check"; every: number }
  | { action: "run_macro"; macro: string; every: number }
  | { action: "update"; params: [string, string][] }
  | { action: "login" }
  | { action: "sign"; signer: string };

export interface SessionRule {
  id: number;
  description?: string;
  /** Empty: every tool. */
  tools: Tool[];
  url?: string;
  actions: Action[];
  invalid?: string;
}

/** One step of `auth macro run`. */
export interface StepRun {
  step: number;
  method: string;
  url: string;
  status: number | null;
  history_id: number | null;
  extracted: { var: string; value: string | null }[];
  error?: string;
}

export interface MacroRun {
  name: string;
  run: number;
  steps: StepRun[];
  missing: string[];
}

export interface ExtractRow {
  /** 1-based step. */
  step: number;
  var: string;
  from: ExtractFrom;
  expr: string;
}

/** The `--action` spec of an action. */
export function actionSpec(a: Action): string {
  switch (a.action) {
    case "check":
      return a.every > 1 ? `check:${a.every}` : "check";
    case "run_macro":
      return a.every === 0 ? `macro:${a.macro}` : a.every === 1 ? `macro:${a.macro}:each` : `macro:${a.macro}:${a.every}`;
    case "update":
      return a.params.length ? `update:${a.params.map(([p, v]) => (p === v ? p : `${p}=${v}`)).join(",")}` : "update";
    case "login":
      return "login";
    case "sign":
      return `sign:${a.signer}`;
  }
}

/** An action in plain words. */
export function actionLabel(a: Action): string {
  switch (a.action) {
    case "check":
      return a.every > 1 ? `check the session every ${a.every} requests` : "check the session";
    case "run_macro":
      return a.every === 0
        ? `run ${a.macro} (cached until stale)`
        : a.every === 1
          ? `run ${a.macro} on every request`
          : `run ${a.macro} every ${a.every} requests`;
    case "update":
      return a.params.length
        ? `update ${a.params.map(([p, v]) => (p === v ? p : `${p} ← ${v}`)).join(", ")}`
        : "update parameters named like this rule's macro values";
    case "login":
      return "log in again if not logged in";
    case "sign":
      return `sign the request with ${a.signer}`;
  }
}

/** "csrf, X-Token=tok" → [["csrf","csrf"],["X-Token","tok"]]. */
export function parseParams(text: string): [string, string][] {
  return text
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf("=");
      return i < 0 ? [p, p] : [p.slice(0, i).trim(), p.slice(i + 1).trim()];
    });
}

/** `auth macro add` arguments: steps are history ids, in order. Values go as --flag=value, names after "--". */
export function macroAddArgs(profile: string, name: string, steps: number[], extract: ExtractRow[]): string[] {
  const args = ["auth", "macro", "add"];
  for (const id of steps) args.push(`--step=${id}`);
  for (const x of extract) {
    if (x.var.trim() && x.expr) args.push(`--extract=${x.step}:${x.var.trim()}=${x.from}:${x.expr}`);
  }
  args.push("--", profile, name.trim());
  return args;
}

export interface RuleForm {
  tools: Tool[];
  url: string;
  invalid: string;
  description: string;
  actions: Action[];
}

/** `auth rule add` arguments. */
export function ruleAddArgs(profile: string, r: RuleForm): string[] {
  const args = ["auth", "rule", "add"];
  for (const a of r.actions) args.push(`--action=${actionSpec(a)}`);
  if (r.tools.length && r.tools.length < TOOLS.length) args.push(`--tool=${r.tools.join(",")}`);
  if (r.url.trim()) args.push(`--url=${r.url.trim()}`);
  if (r.invalid.trim()) args.push(`--invalid=${r.invalid.trim()}`);
  if (r.description.trim()) args.push(`--description=${r.description.trim()}`);
  args.push("--", profile);
  return args;
}

/** Problems that keep a rule from saving, in plain words (empty when it can be saved). */
export function ruleProblems(r: RuleForm, macros: string[], hasCheckUrl: boolean, hasLogin: boolean): string[] {
  const out: string[] = [];
  if (!r.actions.length) out.push("Add at least one action.");
  r.actions.forEach((a, i) => {
    if (a.action === "update" && !a.params.length && !r.actions.slice(0, i).some((b) => b.action === "run_macro"))
      out.push("Update with no parameters needs a macro before it.");
    if (a.action === "check" && !hasCheckUrl) out.push("A session check needs the profile's check URL.");
    if (a.action === "login" && !hasLogin) out.push("Log in needs a profile with a login URL.");
    if (a.action === "run_macro" && !macros.includes(a.macro)) out.push(`No macro named "${a.macro}".`);
  });
  return [...new Set(out)];
}
