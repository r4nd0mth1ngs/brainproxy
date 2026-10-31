// Session handling for auth profiles (macros, session rules and request signers): the shapes
// `auth show` returns, and the `auth macro` / `auth rule` / `auth sign` arguments the Settings
// view builds.

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
export function ruleProblems(r: RuleForm, macros: string[], signers: string[], hasCheckUrl: boolean, hasLogin: boolean): string[] {
  const out: string[] = [];
  if (!r.actions.length) out.push("Add at least one action.");
  r.actions.forEach((a, i) => {
    if (a.action === "update" && !a.params.length && !r.actions.slice(0, i).some((b) => b.action === "run_macro"))
      out.push("Update with no parameters needs a macro before it.");
    if (a.action === "check" && !hasCheckUrl) out.push("A session check needs the profile's check URL.");
    if (a.action === "login" && !hasLogin) out.push("Log in needs a profile with a login URL.");
    if (a.action === "run_macro" && !macros.includes(a.macro)) out.push(`No macro named "${a.macro}".`);
    if (a.action === "sign" && !signers.includes(a.signer)) out.push(`No signer named "${a.signer}".`);
  });
  return [...new Set(out)];
}

export const HMAC_HASHES = ["sha1", "sha256", "sha384", "sha512"] as const;
export const HMAC_OUTPUTS = ["hex", "base64", "base64url"] as const;
export const JWT_ALGS = ["HS256", "HS384", "HS512", "RS256"] as const;
export const KEY_ENCODINGS = ["raw", "hex", "base64"] as const;

/** A signer as `auth show` lists it: where its key is, never the key. */
export type Signer = {
  name: string;
  key: { env: string } | { file: string };
  key_encoding?: (typeof KEY_ENCODINGS)[number];
  origins: string[];
  to: { header: string } | { query: string };
  format?: string;
  headers?: [string, string][];
} & (
  | { kind: "hmac"; alg: (typeof HMAC_HASHES)[number]; canonical: string; output?: (typeof HMAC_OUTPUTS)[number] }
  | { kind: "jwt"; alg: (typeof JWT_ALGS)[number]; claims: string; ttl?: number; kid?: string; resign?: boolean }
);

export interface SignerForm {
  name: string;
  keyFrom: "env" | "file";
  /** The variable's name or the file's path, never the key. */
  key: string;
  keyEncoding: (typeof KEY_ENCODINGS)[number];
  origins: string;
  toKind: "header" | "query";
  toName: string;
  wrap: string;
  /** "NAME: TEMPLATE", one per line. */
  headers: string;
  kind: "hmac" | "jwt";
  canonical: string;
  hash: (typeof HMAC_HASHES)[number];
  output: (typeof HMAC_OUTPUTS)[number];
  jwtAlg: (typeof JWT_ALGS)[number];
  claims: string;
  ttl: string;
  kid: string;
  resign: boolean;
}

export const EMPTY_SIGNER: SignerForm = {
  name: "",
  keyFrom: "env",
  key: "",
  keyEncoding: "raw",
  origins: "",
  toKind: "header",
  toName: "",
  wrap: "",
  headers: "",
  kind: "hmac",
  canonical: "",
  hash: "sha256",
  output: "hex",
  jwtAlg: "HS256",
  claims: "",
  ttl: "",
  kid: "",
  resign: false,
};

/** The form to edit a signer. */
export function signerForm(s: Signer): SignerForm {
  const f: SignerForm = {
    ...EMPTY_SIGNER,
    name: s.name,
    keyFrom: "env" in s.key ? "env" : "file",
    key: "env" in s.key ? s.key.env : s.key.file,
    keyEncoding: s.key_encoding ?? "raw",
    origins: s.origins.join("\n"),
    toKind: "header" in s.to ? "header" : "query",
    toName: "header" in s.to ? s.to.header : s.to.query,
    wrap: s.format ?? "",
    headers: (s.headers ?? []).map(([k, v]) => `${k}: ${v}`).join("\n"),
    kind: s.kind,
  };
  if (s.kind === "hmac") return { ...f, canonical: s.canonical, hash: s.alg, output: s.output ?? "hex" };
  return { ...f, jwtAlg: s.alg, claims: s.claims, ttl: s.ttl == null ? "" : String(s.ttl), kid: s.kid ?? "", resign: !!s.resign };
}

const lines = (text: string) =>
  text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

/**
 * `auth sign add` arguments, which add a signer or replace the one of that name, running it last
 * unless `keepPlace`. Values go as --flag=value, names after "--". Templates go as typed: a
 * canonical string's spaces are signed.
 */
export function signerAddArgs(profile: string, f: SignerForm, keepPlace = false): string[] {
  const args = ["auth", "sign", "add", f.keyFrom === "env" ? `--secret-env=${f.key.trim()}` : `--secret-file=${f.key.trim()}`];
  if (keepPlace) args.push("--keep-place");
  if (f.keyEncoding !== "raw") args.push(`--secret-encoding=${f.keyEncoding}`);
  for (const o of lines(f.origins)) args.push(`--origin=${o}`);
  args.push(`--to=${f.toKind}:${f.toName.trim()}`);
  if (f.toKind === "header" && f.wrap) args.push(`--wrap=${f.wrap}`);
  for (const h of lines(f.headers)) args.push(`--set-header=${h}`);
  if (f.kind === "hmac") {
    args.push(`--canonical=${f.canonical}`, `--hash=${f.hash}`, `--output=${f.output}`);
  } else {
    args.push(`--jwt=${f.jwtAlg}`);
    if (f.claims.trim()) args.push(`--claims=${f.claims}`);
    if (f.ttl.trim()) args.push(`--ttl=${f.ttl.trim()}`);
    if (f.kid) args.push(`--kid=${f.kid}`);
    if (f.resign) args.push("--resign");
  }
  args.push("--", profile, f.name.trim());
  return args;
}

/**
 * Problems that keep a signer from saving, in plain words (empty when it can be saved). The CLI
 * checks templates and origins itself. None of these repeat the key field: a key pasted there
 * by mistake stops here, off the screen and out of the project.
 */
export function signerProblems(f: SignerForm, taken: string[]): string[] {
  const out: string[] = [];
  const name = f.name.trim();
  const key = f.key.trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) out.push("Name the signer with letters, digits, '_', '-' and '.'.");
  if (taken.includes(name)) out.push(`A signer named "${name}" already exists.`);
  if (f.keyFrom === "env" && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) out.push("Give the name of the environment variable that holds the key, not the key.");
  // Read by whichever process signs, each with its own working directory.
  if (f.keyFrom === "file" && !/^(\/|[A-Za-z]:[\\/]|\\\\)/.test(key)) out.push("Give the full path of the file that holds the key.");
  if (!lines(f.origins).length) out.push("Name at least one origin it may sign for.");
  if (!f.toName.trim()) out.push(`Name the ${f.toKind} the value goes in.`);
  if (f.toKind === "header" && f.wrap && f.wrap.split("{{signature}}").length !== 2) out.push("The header format needs {{signature}} once.");
  if (lines(f.headers).some((h) => !h.includes(":"))) out.push("Write each header to set as NAME: TEMPLATE.");
  if (f.kind === "hmac" && !f.canonical) out.push("Say what to sign.");
  if (f.kind === "jwt" && f.ttl.trim() && !/^\d+$/.test(f.ttl.trim())) out.push("Give the JWT's lifetime in whole seconds.");
  return out;
}

/** What a signer makes and where its key is, in plain words. */
export function signerLabel(s: Signer): string {
  const made = s.kind === "hmac" ? `HMAC-${s.alg.toUpperCase()} (${s.output ?? "hex"})` : `JWT ${s.alg}${s.resign ? ", re-signed" : ""}`;
  const to = "header" in s.to ? `header ${s.to.header}` : `query ${s.to.query}`;
  const key = "env" in s.key ? `$${s.key.env}` : s.key.file;
  return `${made} → ${to} · key in ${key}`;
}
