// Session handling for auth profiles (macros, session rules and request signers): the shapes
// `auth show` returns, and the `auth macro` / `auth rule` / `auth sign` arguments the Settings
// view builds.

// With their extensions, so node --test can load this module (as the tests import theirs).
import { textBytes } from "../api.ts";
import { withBody } from "../ui/message.ts";

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
  /** What `auth macro edit --if-revision` checks. */
  revision?: string;
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

/** A CLI call with the request files its `--step=…@request:I` arguments name (see `CliInput.requestFiles`). */
export interface MacroCall {
  args: string[];
  requestFiles: Uint8Array[];
}

/**
 * The `--step` value of a step: step:N for one of the macro's own, a history id for a Traffic
 * row, and for a request given as text ORIGIN=@request:I, where I is the private file the app
 * stages its bytes in (added to `files`). The origin is said, so it goes where it went before
 * rather than where its Host header and one scheme for every step would send it.
 */
function stepArg(s: EditorStep, files: Uint8Array[]): string {
  if (s.kind === "kept") return `--step=step:${s.n}`;
  if (s.kind === "history") return `--step=${s.id}`;
  files.push(textBytes(s.request));
  return `--step=${s.target}=@request:${files.length - 1}`;
}

/** `auth macro add` arguments: steps in order (Traffic rows, or requests given as text). Values go as --flag=value, names after "--". */
export function macroAddArgs(profile: string, name: string, steps: EditorStep[], extract: ExtractRow[]): MacroCall {
  const requestFiles: Uint8Array[] = [];
  const args = ["auth", "macro", "add", ...steps.map((s) => stepArg(s, requestFiles))];
  for (const x of extract) {
    if (x.var.trim() && x.expr) args.push(`--extract=${x.step}:${x.var.trim()}=${x.from}:${x.expr}`);
  }
  args.push("--", profile, name.trim());
  return { args, requestFiles };
}

/** A macro as `auth macro show` gives it, with the revision an edit passes back. */
export interface MacroDetail {
  name: string;
  steps: { target: string; request: string; history_id?: number; extract: { var: string; from: ExtractFrom; expr: string }[] }[];
  origin?: string;
}

/**
 * A step in the macro editor: one of the macro's own (`n`, from 1), a Traffic row to add, or a
 * request given as text (one of those edited, or one pasted) that goes to `target`, an origin.
 * `key` stays with it as it moves, and as its text is edited, so its extractors stay with it.
 */
export type EditorStep = { key: string; line: string } & (
  | { kind: "kept"; n: number }
  | { kind: "history"; id: number }
  | { kind: "text"; target: string; request: string }
);

/** An extractor in the editor, on the step whose `key` it names. */
export interface EditorExtract {
  key: string;
  var: string;
  from: ExtractFrom;
  expr: string;
}

/** "METHOD URL" of a macro step, as `auth macro list` says it. */
export function stepLine(s: { target: string; request: string }): string {
  const [method = "", path = ""] = (s.request.split(/\r?\n/, 1)[0] ?? "").split(" ");
  return /^https?:\/\//.test(path) ? `${method} ${path}` : `${method} ${s.target.replace(/\/$/, "")}${path}`;
}

/** The editor's steps and extractors for a macro as it is. */
export function macroEditor(m: MacroDetail): { steps: EditorStep[]; extract: EditorExtract[] } {
  const steps: EditorStep[] = m.steps.map((s, i) => ({ key: `step${i + 1}`, kind: "kept", n: i + 1, line: stepLine(s) }));
  const extract = m.steps.flatMap((s, i) => s.extract.map((x) => ({ key: `step${i + 1}`, var: x.var, from: x.from, expr: x.expr })));
  return { steps, extract };
}

/** Why the edited macro can't be saved yet; null when it can. The CLI checks the rest. */
export function macroEditProblem(steps: EditorStep[], extract: EditorExtract[], name?: string): string | null {
  if (name !== undefined && !name.trim()) return "Give the macro a name.";
  if (!steps.length) return "A macro needs at least one step.";
  if (extract.some((x) => !steps.some((s) => s.key === x.key))) return "An extractor is on a step that was taken out.";
  if (extract.some((x) => !x.var.trim() || !x.expr)) return "Give each extractor a variable and what to look for, or take it out.";
  return null;
}

/**
 * `auth macro edit` for the editor's steps, extractors and name, or null when they are what
 * `start` was. Every step and extractor is said, so the result doesn't depend on what is
 * carried: a kept step as step:N, a Traffic row as its history id, a request given as text in
 * a staged file. The revision makes a macro changed elsewhere since the editor opened fail
 * rather than be overwritten. A new name (`rename`, trimmed) goes as --rename.
 */
export function macroEditArgs(
  profile: string,
  name: string,
  start: { steps: EditorStep[]; extract: EditorExtract[] },
  steps: EditorStep[],
  extract: EditorExtract[],
  revision?: string,
  rename?: string,
): MacroCall | null {
  const body = (st: EditorStep[], ex: EditorExtract[], files: Uint8Array[]) => {
    const args = st.map((s) => stepArg(s, files));
    const rows = ex.map((x) => `--extract=${st.findIndex((s) => s.key === x.key) + 1}:${x.var.trim()}=${x.from}:${x.expr}`);
    return [...args, ...(rows.length ? rows : ["--no-extract"])];
  };
  const requestFiles: Uint8Array[] = [];
  const now = body(steps, extract, requestFiles);
  const renamed = rename !== undefined && rename.trim() !== name ? [`--rename=${rename.trim()}`] : [];
  // A step given as text is always a change: the editor makes one only when the text changed.
  if (!renamed.length && !requestFiles.length && now.join("\n") === body(start.steps, start.extract, []).join("\n")) return null;
  return { args: ["auth", "macro", "edit", ...now, ...renamed, ...(revision ? [`--if-revision=${revision}`] : []), "--", profile, name], requestFiles };
}

/** A step's request to edit: its origin and text. */
export interface StepText {
  target: string;
  request: string;
}

/**
 * The step after its request was edited to `now`: as it was when that is still `was` (its
 * original text, so a step opened and saved unchanged stays one of the macro's own or a Traffic
 * row), and otherwise a step given as text, with the same key so its extractors stay on it.
 */
export function editedStep(s: EditorStep, now: StepText, was: StepText | null): EditorStep {
  if (was && s.kind !== "text" && now.target === was.target && now.request === was.request) return s;
  return { key: s.key, kind: "text", target: now.target, request: now.request, line: stepLine(now) };
}

/** The origin ("https://host:port") a raw request goes to: its absolute URL's, or its Host header's over `scheme`; "" when it names neither. */
export function inferOrigin(request: string, scheme = "https"): string {
  const lines = request.split(/\r?\n/);
  const path = (lines[0] ?? "").split(" ")[1] ?? "";
  try {
    if (/^https?:\/\//i.test(path)) return new URL(path).origin;
  } catch {
    return "";
  }
  for (const line of lines.slice(1)) {
    if (!line) break;
    const m = /^host:\s*(\S+)\s*$/i.exec(line);
    if (!m) continue;
    try {
      return new URL(`${scheme}://${m[1]}`).origin;
    } catch {
      return "";
    }
  }
  return "";
}

/** `text` as an origin ("https://app.test:8443"): lower-cased, with a default port or a trailing slash dropped; trimmed as it is when it isn't one. */
export function cleanOrigin(text: string): string {
  const s = text.trim();
  try {
    const u = new URL(s);
    const bare = u.pathname === "/" && !u.search && !u.hash && !u.username && !u.password && !/[?#]$/.test(s);
    if (/^https?:$/.test(u.protocol) && u.hostname && bare) return u.origin;
  } catch {
    // Not a URL: said by stepTextProblem.
  }
  return s;
}

/** Why a step's origin and request can't be used; null when they can. The CLI checks the rest. */
export function stepTextProblem(t: StepText): string | null {
  if (!/^https?:\/\/[^/?#@\s]+$/i.test(t.target) || cleanOrigin(t.target) !== t.target)
    return "Give the origin the request goes to, such as https://app.test or http://127.0.0.1:8000.";
  const line = t.request.split(/\r?\n/, 1)[0] ?? "";
  if (!/^\S+ \S+ HTTP\/\d(\.\d)?$/.test(line.trim())) return "The request starts with a request line, such as GET /path HTTP/1.1.";
  return null;
}

/**
 * The variables a step can use as {{name}}: those extracted by the steps before `key` (every
 * step for one not in the list yet, a new one going last), then the profile's username and
 * password.
 */
export function varsBefore(steps: EditorStep[], extract: { key: string; var: string }[], key: string | null): string[] {
  const at = key === null ? -1 : steps.findIndex((s) => s.key === key);
  const before = new Set((at < 0 ? steps : steps.slice(0, at)).map((s) => s.key));
  const vars = extract.filter((x) => before.has(x.key)).map((x) => x.var.trim()).filter(Boolean);
  return [...new Set([...vars, "username", "password"])];
}

/**
 * `value` (as the message editor holds it) with {{name}} put over the textarea's selection
 * `start`..`end`, whose offsets count line breaks as \n (the textarea shows CRLF as \n), and
 * where the caret goes after it.
 */
export function insertVar(value: string, start: number, end: number, name: string): { value: string; caret: number } {
  const text = value.replace(/\r\n/g, "\n");
  const [a, b] = [Math.max(0, Math.min(start, text.length)), Math.max(0, Math.min(end, text.length))];
  const put = `{{${name}}}`;
  return { value: withBody(text.slice(0, Math.min(a, b)) + put + text.slice(Math.max(a, b)), value), caret: Math.min(a, b) + put.length };
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
export const JWT_ALGS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"] as const;
export const KEY_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"] as const;
export const KEY_ENCODINGS = ["raw", "hex", "base64"] as const;

/** A signer as `auth show` lists it: where its key is, never the key. */
export type Signer = {
  name: string;
  /** "none": a script that reads no environment. */
  key: { env: string } | { file: string } | "none";
  key_encoding?: (typeof KEY_ENCODINGS)[number];
  origins: string[];
  to: { header: string } | { query: string };
  format?: string;
  headers?: [string, string][];
} & (
  | { kind: "hmac"; alg: (typeof HMAC_HASHES)[number]; canonical: string; output?: (typeof HMAC_OUTPUTS)[number] }
  | { kind: "jwt"; alg: (typeof JWT_ALGS)[number]; claims: string; ttl?: number; kid?: string; resign?: boolean }
  | { kind: "key"; alg: (typeof KEY_ALGS)[number]; canonical: string; output?: (typeof HMAC_OUTPUTS)[number] }
  | { kind: "sigv4"; access_key: { env: string } | { file: string }; session_token?: { env: string } | { file: string }; region: string; service: string }
  | { kind: "script"; file: string; sha256: string; vars?: [string, string][] }
);

export interface SignerForm {
  name: string;
  keyFrom: "env" | "file" | "none";
  /** The variable's name or the file's path, never the key. */
  key: string;
  keyEncoding: (typeof KEY_ENCODINGS)[number];
  origins: string;
  toKind: "header" | "query";
  toName: string;
  wrap: string;
  /** "NAME: TEMPLATE", one per line. */
  headers: string;
  kind: "hmac" | "jwt" | "key" | "sigv4" | "script";
  canonical: string;
  hash: (typeof HMAC_HASHES)[number];
  output: (typeof HMAC_OUTPUTS)[number];
  jwtAlg: (typeof JWT_ALGS)[number];
  claims: string;
  ttl: string;
  kid: string;
  resign: boolean;
  keyAlg: (typeof KEY_ALGS)[number];
  region: string;
  service: string;
  accessFrom: "env" | "file";
  access: string;
  tokenFrom: "env" | "file";
  /** Optional. */
  token: string;
  scriptFile: string;
  scriptSha: string;
  scriptVars: string[];
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
  keyAlg: "ES256",
  region: "",
  service: "",
  accessFrom: "env",
  access: "",
  tokenFrom: "env",
  token: "",
  scriptFile: "",
  scriptSha: "",
  scriptVars: [],
};

/** The form to edit a signer. */
export function signerForm(s: Signer): SignerForm {
  const f: SignerForm = {
    ...EMPTY_SIGNER,
    name: s.name,
    keyFrom: s.key === "none" ? "none" : "env" in s.key ? "env" : "file",
    key: s.key === "none" ? "" : "env" in s.key ? s.key.env : s.key.file,
    keyEncoding: s.key_encoding ?? "raw",
    origins: s.origins.join("\n"),
    toKind: "header" in s.to ? "header" : "query",
    toName: "header" in s.to ? s.to.header : s.to.query,
    wrap: s.format ?? "",
    headers: (s.headers ?? []).map(([k, v]) => `${k}: ${v}`).join("\n"),
    kind: s.kind,
  };
  if (s.kind === "hmac") return { ...f, canonical: s.canonical, hash: s.alg, output: s.output ?? "hex" };
  if (s.kind === "key") return { ...f, canonical: s.canonical, keyAlg: s.alg, output: s.output ?? "hex" };
  if (s.kind === "sigv4")
    return {
      ...f,
      region: s.region,
      service: s.service,
      accessFrom: "env" in s.access_key ? "env" : "file",
      access: "env" in s.access_key ? s.access_key.env : s.access_key.file,
      tokenFrom: s.session_token && "file" in s.session_token ? "file" : "env",
      token: !s.session_token ? "" : "env" in s.session_token ? s.session_token.env : s.session_token.file,
    };
  if (s.kind === "script") return { ...f, scriptFile: s.file, scriptSha: s.sha256, scriptVars: (s.vars ?? []).map(([k, v]) => `${k}=${v}`) };
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
  const args = ["auth", "sign", "add"];
  if (f.keyFrom !== "none") args.push(f.keyFrom === "env" ? `--secret-env=${f.key.trim()}` : `--secret-file=${f.key.trim()}`);
  if (keepPlace) args.push("--keep-place");
  if (f.keyEncoding !== "raw" && f.kind !== "script") args.push(`--secret-encoding=${f.keyEncoding}`);
  for (const o of lines(f.origins)) args.push(`--origin=${o}`);
  if (f.kind !== "sigv4" && f.kind !== "script") {
    args.push(`--to=${f.toKind}:${f.toName.trim()}`);
    if (f.toKind === "header" && f.wrap) args.push(`--wrap=${f.wrap}`);
    for (const h of lines(f.headers)) args.push(`--set-header=${h}`);
  }
  if (f.kind === "hmac") {
    args.push(`--canonical=${f.canonical}`, `--hash=${f.hash}`, `--output=${f.output}`);
  } else if (f.kind === "key") {
    args.push(`--key-alg=${f.keyAlg}`, `--canonical=${f.canonical}`, `--output=${f.output}`);
  } else if (f.kind === "sigv4") {
    args.push(`--sigv4-region=${f.region.trim()}`, `--sigv4-service=${f.service.trim()}`);
    args.push(f.accessFrom === "env" ? `--access-key-env=${f.access.trim()}` : `--access-key-file=${f.access.trim()}`);
    if (f.token.trim()) args.push(f.tokenFrom === "env" ? `--session-token-env=${f.token.trim()}` : `--session-token-file=${f.token.trim()}`);
  } else if (f.kind === "script") {
    args.push(`--script=${f.scriptFile}`, `--script-sha256=${f.scriptSha}`);
    for (const v of f.scriptVars) args.push(`--script-var=${v}`);
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
  const envName = /^[A-Za-z_][A-Za-z0-9_]*$/;
  const fullPath = /^(\/|[A-Za-z]:[\\/]|\\\\)/;
  if (f.kind === "sigv4") {
    if (!f.region.trim() || !f.service.trim()) out.push("Give the AWS region and service, like us-east-1 and execute-api.");
    const access = f.access.trim();
    if (f.accessFrom === "env" ? !envName.test(access) : !fullPath.test(access)) out.push("Say where the access key id is: an environment variable's name or a file's full path.");
    const token = f.token.trim();
    if (token && (f.tokenFrom === "env" ? !envName.test(token) : !fullPath.test(token))) out.push("Say where the session token is: an environment variable's name or a file's full path.");
  }
  if (f.keyFrom === "env" && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) out.push("Give the name of the environment variable that holds the key, not the key.");
  // Read by whichever process signs, each with its own working directory.
  if (f.keyFrom === "file" && !/^(\/|[A-Za-z]:[\\/]|\\\\)/.test(key)) out.push("Give the full path of the file that holds the key.");
  if (!lines(f.origins).length) out.push("Name at least one origin it may sign for.");
  if (f.kind !== "sigv4" && f.kind !== "script") {
    if (!f.toName.trim()) out.push(`Name the ${f.toKind} the value goes in.`);
    if (f.toKind === "header" && f.wrap && f.wrap.split("{{signature}}").length !== 2) out.push("The header format needs {{signature}} once.");
    if (lines(f.headers).some((h) => !h.includes(":"))) out.push("Write each header to set as NAME: TEMPLATE.");
  }
  if ((f.kind === "hmac" || f.kind === "key") && !f.canonical) out.push("Say what to sign.");
  if (f.kind === "jwt" && f.ttl.trim() && !/^\d+$/.test(f.ttl.trim())) out.push("Give the JWT's lifetime in whole seconds.");
  return out;
}

/** What a signer makes and where its key is, in plain words. */
export function signerLabel(s: Signer): string {
  const key = s.key === "none" ? "" : "env" in s.key ? `$${s.key.env}` : s.key.file;
  if (s.kind === "script") return `Postman script from ${s.file}${key ? ` · environment in ${key}` : ""}`;
  if (s.kind === "sigv4") return `AWS SigV4 for ${s.service} in ${s.region} · secret key in ${key}`;
  const made =
    s.kind === "hmac" ? `HMAC-${s.alg.toUpperCase()} (${s.output ?? "hex"})` : s.kind === "key" ? `${s.alg} signature (${s.output ?? "hex"})` : `JWT ${s.alg}${s.resign ? ", re-signed" : ""}`;
  const to = "header" in s.to ? `header ${s.to.header}` : `query ${s.to.query}`;
  return `${made} → ${to} · key in ${key}`;
}
