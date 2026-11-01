// The API guided scan's pure logic: what `import api --dry-run` returns, the arguments the flow
// builds, default selections, summaries and problem checks. No DOM, so bun and node can test it.
// Secrets never pass through an args builder: an API key goes by `keyEnv`, off the command line.

import { depthArgs, type Depth } from "./wizardDepths.ts";
import { ruleAddArgs, EMPTY_SIGNER, type RuleForm, type SessionRule, type SignerForm } from "./sessionRules.ts";

// --- `import api SOURCE --dry-run` ---

export type CredentialKind = "api_key" | "bearer" | "basic" | "oauth2" | "openid" | "mutual_tls" | "other";

export interface ApiServer {
  index: number;
  url: string;
  description?: string | null;
}

export interface ApiVariable {
  name: string;
  /** Null when secret. */
  value: string | null;
  source?: string;
  secret: boolean;
  used: boolean;
}

export interface ApiCredential {
  kind: CredentialKind;
  in: "header" | "query" | "cookie" | null;
  name: string | null;
  source: string;
  /** The document held a value. It is never sent or stored. */
  embedded: boolean;
}

export interface ApiHost {
  host: string;
  port: number;
  in_scope: boolean;
  scope_confirmed: boolean;
}

export interface ApiOperation {
  index: number;
  name: string;
  method: string;
  url: string;
  headers: string[];
  body?: { encoding: "utf8" | "base64"; content: string; length?: number; truncated?: boolean } | null;
  state_changing: boolean;
  in_scope: boolean;
  scope_confirmed: boolean;
  included: boolean;
  excluded_reason: "method" | "scope" | "not_selected" | null;
}

export interface ApiPreview {
  kind: "api";
  format: "openapi3" | "swagger2" | "postman";
  title: string | null;
  version: string | null;
  document_sha256: string;
  servers: ApiServer[];
  base_url_required: boolean;
  variables: ApiVariable[];
  unresolved_variables: string[];
  credentials: ApiCredential[];
  built: number;
  selected: number;
  skipped: { operation: string; reason: string }[];
  warnings: string[];
  hosts: ApiHost[];
  requests_truncated: boolean;
  requests: ApiOperation[];
  hint?: string;
}

/** Which server, and the variable values typed in. */
export interface ApiTarget {
  /** A document server's index; null means the addresses as the document writes them. */
  server: number | null;
  /** Overrides `server` when set. */
  baseUrl: string;
  vars: Record<string, string>;
}

export const EMPTY_TARGET: ApiTarget = { server: null, baseUrl: "", vars: {} };

/** Requests listed by the preview: every operation, up to this many. */
export const PREVIEW_LIMIT = 1000;

const FORMATS: Record<ApiPreview["format"], string> = { openapi3: "OpenAPI 3", swagger2: "Swagger 2", postman: "Postman collection" };

export const formatLabel = (f: ApiPreview["format"]): string => FORMATS[f] ?? f;

/** "Pets 1.0", or the format when the document has no title. */
export const previewTitle = (p: Pick<ApiPreview, "title" | "version" | "format">): string =>
  `${p.title || formatLabel(p.format)}${p.version ? ` ${p.version}` : ""}`;

/** A name that holds a secret by the CLI's own rule, so its value must not go on a command line. */
export function looksSecret(name: string): boolean {
  const n = name.trim().toLowerCase().replace(/_/g, "-");
  return n.startsWith("x-auth") || ["authorization", "cookie", "token", "secret", "api-key", "apikey", "password", "passwd"].some((s) => n.includes(s));
}

const parseUrl = (text: string): URL | null => {
  try {
    return new URL(text);
  } catch {
    return null;
  }
};

/** What's wrong with an http(s) URL that goes on the command line ("" when fine). */
function urlProblem(text: string): string {
  const u = parseUrl(text);
  if (!u || !["http:", "https:"].includes(u.protocol) || !u.hostname) return "Give an address starting with http:// or https://.";
  if (u.username || u.password) return "Take the username and password out of the address. Set them up in the authentication step.";
  if ([...u.searchParams.keys()].some(looksSecret)) return "Take the key or token out of the address. Set it up in the authentication step.";
  return "";
}

export const sourceKind = (source: string): "url" | "file" => (/^https?:\/\//i.test(source.trim()) ? "url" : "file");

/** What's wrong with a definition's source ("" when it can be previewed). A bare "-" would read stdin. */
export function sourceProblem(source: string): string {
  const s = source.trim();
  if (!s) return "Choose a file or paste a URL.";
  if (sourceKind(s) === "url") return urlProblem(s);
  return /^(\/|[A-Za-z]:[\\/]|\\\\)/.test(s) ? "" : "Give the file's full path, or an address starting with http:// or https://.";
}

export const baseUrlProblem = (base: string): string => (base.trim() ? urlProblem(base.trim()) : "");

/** `--server`/`--base-url`/`--var` arguments. A secret-looking variable never gets a value here. */
export function targetArgs(t: ApiTarget): string[] {
  const args: string[] = [];
  const base = t.baseUrl.trim();
  if (base) args.push(`--base-url=${base}`);
  else if (t.server != null) args.push(`--server=${t.server}`);
  for (const [name, value] of Object.entries(t.vars)) {
    if (value !== "" && !looksSecret(name)) args.push(`--var=${name}=${value}`);
  }
  return args;
}

/** `import api --dry-run`: the preview. Sends nothing for a file; fetches a URL, in scope only. */
export const previewArgs = (source: string, t: ApiTarget): string[] => [
  "import",
  "api",
  "--dry-run",
  `--limit=${PREVIEW_LIMIT}`,
  ...targetArgs(t),
  "--",
  source.trim(),
];

/** The target a fresh preview starts on: the document's first server, if it has one. */
export const defaultTarget = (p: Pick<ApiPreview, "servers">): ApiTarget => ({ ...EMPTY_TARGET, server: p.servers[0]?.index ?? null });

export interface VariableInput {
  name: string;
  value: string;
  /** No input for this one: it goes in the authentication step. */
  secret: boolean;
  /** The document has no value. */
  unresolved: boolean;
}

/** The variables to ask about: used ones, unresolved ones, and any already typed (which leave `unresolved`). */
export function variableInputs(p: Pick<ApiPreview, "variables" | "unresolved_variables">, typed: Record<string, string> = {}): VariableInput[] {
  const out = new Map<string, VariableInput>();
  for (const v of p.variables) {
    if (v.used) out.set(v.name, { name: v.name, value: v.value ?? "", secret: v.secret || looksSecret(v.name), unresolved: false });
  }
  for (const name of p.unresolved_variables) out.set(name, { name, value: "", secret: looksSecret(name), unresolved: true });
  for (const name of Object.keys(typed)) if (!out.has(name)) out.set(name, { name, value: "", secret: looksSecret(name), unresolved: true });
  return [...out.values()];
}

/** A host's standing. A name only an IP or CIDR target could allow isn't known until it resolves. */
export const hostScopeText = (h: ApiHost): string =>
  !h.in_scope ? "out of scope, operations skipped" : h.scope_confirmed ? "in scope" : "not listed by name: sent only if it resolves to an address in scope";

export const hostLabel = (h: ApiHost): string => (h.port === 80 || h.port === 443 ? h.host : `${h.host}:${h.port}`);

/** What keeps the Server step from moving on (empty when it can). */
export function serverProblems(p: Pick<ApiPreview, "base_url_required" | "requests" | "hosts">, t: ApiTarget, scope: string[] = []): string[] {
  const out: string[] = [];
  const bad = baseUrlProblem(t.baseUrl);
  if (bad) return [bad];
  if (p.base_url_required && !t.baseUrl.trim()) return ["This definition doesn't say where the API is. Give its base URL."];
  if (!p.requests.some((r) => r.in_scope)) {
    const where = scope.length ? ` (${scope.join(", ")})` : "";
    out.push(`Nothing in this definition is inside the project's approved scope${where}. Choose another server or base URL. The scope can't be widened here.`);
  }
  return out;
}

export const serverSummary = (p: Pick<ApiPreview, "servers">, t: ApiTarget): string =>
  t.baseUrl.trim() || p.servers.find((s) => s.index === t.server)?.url || "the addresses in the definition";

const originOf = (url: string): string | null => {
  const u = parseUrl(url);
  return u && ["http:", "https:"].includes(u.protocol) ? u.origin : null;
};

/** The distinct origins of these operations, in document order. */
export function operationOrigins(ops: Pick<ApiOperation, "url">[]): string[] {
  const out = new Set<string>();
  for (const o of ops) {
    const origin = originOf(o.url);
    if (origin) out.add(origin);
  }
  return [...out];
}

// --- Operations ---

const DEFAULT_METHODS = ["GET", "HEAD", "OPTIONS", "POST"];
const METHOD_ORDER = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

/** Not sent unless asked for: PUT, PATCH, DELETE, and anything else outside the default four. */
export const needsOptIn = (op: Pick<ApiOperation, "method">): boolean => !DEFAULT_METHODS.includes(op.method.toUpperCase());

export const tickable = (op: Pick<ApiOperation, "method" | "in_scope">, optIn: boolean): boolean => op.in_scope && (optIn || !needsOptIn(op));

/** Ticked to begin with: in scope, and a method sent by default. */
/** Operations the scope surely allows; when it can't say for any (only IP or CIDR targets), all it may allow. */
export function likelyInScope<T extends Pick<ApiOperation, "in_scope" | "scope_confirmed">>(ops: T[]): T[] {
  const confirmed = ops.filter((o) => o.in_scope && o.scope_confirmed);
  return confirmed.length ? confirmed : ops.filter((o) => o.in_scope);
}

export const defaultSelection = (ops: ApiOperation[]): number[] => likelyInScope(ops).filter((o) => tickable(o, false)).map((o) => o.index);

export function filterOperations<T extends Pick<ApiOperation, "method" | "name" | "url">>(ops: T[], text: string): T[] {
  const q = text.trim().toLowerCase();
  return q ? ops.filter((o) => `${o.method} ${o.name} ${o.url}`.toLowerCase().includes(q)) : ops;
}

/** Select all or none, of the operations shown. All never ticks what can't be ticked. */
export function selectShown(selected: number[], shown: ApiOperation[], optIn: boolean, on: boolean): number[] {
  const out = new Set(selected);
  for (const o of shown) {
    if (!on) out.delete(o.index);
    else if (tickable(o, optIn)) out.add(o.index);
  }
  return [...out].sort((a, b) => a - b);
}

/** The selection once the opt-in is off: nothing that needed it stays ticked. */
export function dropOptIn(selected: number[], ops: ApiOperation[]): number[] {
  const need = new Set(ops.filter(needsOptIn).map((o) => o.index));
  return selected.filter((i) => !need.has(i));
}

const orderMethods = (methods: Iterable<string>): string[] => {
  const rank = (m: string) => {
    const i = METHOD_ORDER.indexOf(m);
    return i < 0 ? METHOD_ORDER.length : i;
  };
  return [...new Set(methods)].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
};

const ticked = (ops: ApiOperation[], selected: number[]): ApiOperation[] => {
  const on = new Set(selected);
  return ops.filter((o) => on.has(o.index));
};

/** The methods that need opting in to, among all operations in scope: what the opt-in control names. */
export const optInMethods = (ops: ApiOperation[]): string[] => orderMethods(ops.filter((o) => o.in_scope && needsOptIn(o)).map((o) => o.method.toUpperCase()));

/** `--include-methods` values: the opt-in methods actually ticked. */
export const includeMethods = (ops: ApiOperation[], selected: number[]): string[] => orderMethods(ticked(ops, selected).filter(needsOptIn).map((o) => o.method.toUpperCase()));

/** "PUT, PATCH and DELETE". */
export const listWords = (words: string[]): string => (words.length < 2 ? (words[0] ?? "") : `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`);

/** [method, count] of the ticked operations, in a sensible order. */
export function methodCounts(ops: ApiOperation[], selected: number[]): [string, number][] {
  const on = ticked(ops, selected).map((o) => o.method.toUpperCase());
  return orderMethods(on).map((m) => [m, on.filter((x) => x === m).length]);
}

/** "3 GET, 1 POST". */
export const methodSummary = (ops: ApiOperation[], selected: number[]): string =>
  methodCounts(ops, selected)
    .map(([m, n]) => `${n} ${m}`)
    .join(", ") || "none";

export const sendsPost = (ops: ApiOperation[], selected: number[]): boolean => ticked(ops, selected).some((o) => o.method.toUpperCase() === "POST");

export const sendsStateChanging = (ops: ApiOperation[], selected: number[]): boolean => ticked(ops, selected).some((o) => needsOptIn(o) || o.state_changing);

export const operationCount = (n: number): string => `${n} operation${n === 1 ? "" : "s"} will be sent`;

/** Why an operation isn't going, in plain words ("" when there's nothing to say). */
export function excludedText(op: ApiOperation, isTicked: boolean): string {
  if (!op.in_scope || op.excluded_reason === "scope") return "Outside the project's scope. Never sent.";
  if (isTicked) return "";
  if (op.excluded_reason === "method" || needsOptIn(op)) return `${op.method.toUpperCase()} isn't sent unless you allow it.`;
  return "";
}

export const selectionProblems = (selected: number[]): string[] => (selected.length ? [] : ["Tick at least one operation."]);

/**
 * The operation for "Try one request": the first in scope that's GET or HEAD, else the first ticked
 * OPTIONS. POST and anything state-changing is never tried, even if nothing else exists.
 */
export function pickCheckOperation(ops: ApiOperation[], selected: number[]): ApiOperation | null {
  const likely = likelyInScope(ops);
  const safe = (o: ApiOperation, methods: string[]) => likely.includes(o) && !o.state_changing && methods.includes(o.method.toUpperCase());
  return ops.find((o) => safe(o, ["GET", "HEAD"])) ?? ticked(ops, selected).find((o) => safe(o, ["OPTIONS"])) ?? null;
}

// --- Authentication ---

export type AuthMode = "none" | "key" | "profile";
export type KeyKind = "api_key" | "bearer";
export type KeyPlace = "header" | "query";

export interface AuthState {
  mode: AuthMode;
  /** The profile chosen when `mode` is "profile". */
  existing: string;
  keyKind: KeyKind;
  place: KeyPlace;
  keyName: string;
  /** The new profile's name, for a key or a signer that needs one. */
  profileName: string;
  /** Set once the key is saved: the profile that holds it. */
  savedProfile: string;
  signing: boolean;
  signer: { profile: string; name: string } | null;
}

export const EMPTY_AUTH: AuthState = {
  mode: "none",
  existing: "",
  keyKind: "api_key",
  place: "header",
  keyName: "",
  profileName: "",
  savedProfile: "",
  signing: false,
  signer: null,
};

/** The variable an API key travels in, read once by `auth add`. */
export const KEY_ENV = "BRAINPROXY_SECRET_API_KEY";

/** The `env` input for `auth add`. A bearer token's value gets its "Bearer " prefix. */
export function keyEnv(kind: KeyKind, value: string): Record<string, string> {
  const v = value.trim();
  return { [KEY_ENV]: kind === "bearer" && !/^bearer\s/i.test(v) ? `Bearer ${v}` : v };
}

/** Takes a key back out of a message, should an error ever quote it. */
export const scrubSecret = (message: string, secret: string): string => (secret.trim() ? message.split(secret.trim()).join("********") : message);

/** Where a declared credential can be set up by this flow. A cookie key can't. */
const canPrefill = (c: ApiCredential): boolean => (c.kind === "api_key" && (c.in === "header" || c.in === "query") && !!c.name) || c.kind === "bearer";

/** What the key form starts on: the document's first declared key or token, preferring a declared scheme to an embedded value. */
export function keyDefaults(creds: ApiCredential[]): Pick<AuthState, "keyKind" | "place" | "keyName"> {
  const c = creds.find((x) => canPrefill(x) && !x.embedded) ?? creds.find(canPrefill);
  if (c?.kind === "api_key") return { keyKind: "api_key", place: c.in as KeyPlace, keyName: c.name! };
  if (c?.kind === "bearer") return { keyKind: "bearer", place: "header", keyName: "Authorization" };
  return { keyKind: "api_key", place: "header", keyName: "" };
}

/** The form after choosing key or bearer. */
export function keyKindDefaults(creds: ApiCredential[], kind: KeyKind): Pick<AuthState, "keyKind" | "place" | "keyName"> {
  if (kind === "bearer") return { keyKind: "bearer", place: "header", keyName: "Authorization" };
  const c = creds.find((x) => x.kind === "api_key" && canPrefill(x) && !x.embedded) ?? creds.find((x) => x.kind === "api_key" && canPrefill(x));
  return { keyKind: "api_key", place: (c?.in as KeyPlace) ?? "header", keyName: c?.name ?? "" };
}

const NAME_OK = /^[A-Za-z0-9_.][A-Za-z0-9_.-]*$/;

/** A free profile name from the API's title: "Pet Store!" -> "pet-store-api". */
export function defaultProfileName(title: string | null, taken: string[]): string {
  const slug = (title ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const base = !slug ? "api" : /(^|-)api$/.test(slug) ? slug : `${slug}-api`;
  let name = base;
  for (let i = 2; taken.includes(name); i++) name = `${base}-${i}`;
  return name;
}

/** A new profile's name. `auth add` replaces a profile of the same name, so that is refused here. */
export function profileProblems(name: string, taken: string[]): string[] {
  const n = name.trim();
  if (!NAME_OK.test(n)) return ["Name the profile with letters, digits, '_', '-' and '.'."];
  return taken.includes(n) ? [`A profile named "${n}" already exists. Choose another name, or pick it under Existing auth profile.`] : [];
}

/** What keeps a key from being saved. `hasValue`, not the value: none of these repeat it. */
export function keyProblems(a: AuthState, taken: string[], hasValue: boolean, origins: string[]): string[] {
  const out = profileProblems(a.profileName, taken);
  const name = a.keyName.trim();
  if (!name) out.push(a.place === "query" ? "Name the query parameter the key goes in." : "Name the header the key goes in.");
  else if (a.place === "header" && !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) out.push("That isn't a valid header name.");
  else if (a.place === "query" && !/^[A-Za-z0-9._~-]+$/.test(name)) out.push("Use only letters, digits, '-', '.', '_' and '~' in the query parameter's name.");
  if (!hasValue) out.push(a.keyKind === "bearer" ? "Enter the token." : "Enter the key.");
  if (a.place === "query" && !origins.length) out.push("No in-scope address to send the key to.");
  return out;
}

/** `auth add` for a key: its value stays in the environment, named here. `origins` limit a query key. */
export function keyAddArgs(a: AuthState, origins: string[]): string[] {
  const name = a.keyName.trim();
  const args = ["auth", "add"];
  if (a.keyKind === "api_key" && a.place === "query") {
    args.push(`--query-key=${name}=${KEY_ENV}`);
    for (const o of origins) args.push(`--key-origin=${o}`);
  } else {
    args.push(`--header-env=${a.keyKind === "bearer" ? "Authorization" : name}=${KEY_ENV}`);
  }
  args.push("--", a.profileName.trim());
  return args;
}

/** The profile the scan runs with ("" for none). */
export function authProfile(a: AuthState): string {
  if (a.mode === "key") return a.savedProfile;
  if (a.mode === "profile") return a.existing;
  return a.signing && a.signer ? a.signer.profile : "";
}

/** The profile a new signer goes in. */
export function signerHome(a: AuthState): string {
  if (a.mode === "key") return a.savedProfile;
  if (a.mode === "profile") return a.existing;
  return a.profileName.trim();
}

/** What keeps a new signer from being saved, beyond the form's own `signerProblems`. */
export function newSignerProblems(a: AuthState, taken: string[]): string[] {
  if (a.mode === "key") return a.savedProfile ? [] : ["Save the key first: the signer goes in the same profile."];
  if (a.mode === "profile") return a.existing ? [] : ["Choose the profile first: the signer goes in it."];
  return profileProblems(a.profileName, taken);
}

/** What keeps the Authentication step from moving on. No authentication is always fine. */
export function authProblems(a: AuthState): string[] {
  const out: string[] = [];
  if (a.mode === "key" && !a.savedProfile) out.push("Save the key, or choose No authentication.");
  if (a.mode === "profile" && !a.existing) out.push("Choose a profile, or choose No authentication.");
  if (a.signing && !a.signer) out.push('Choose or set up a signer, or untick "Every request must be signed".');
  const profile = authProfile(a);
  if (a.signing && a.signer && profile && a.signer.profile !== profile)
    out.push(`The signer is in profile "${a.signer.profile}", but "${profile}" is selected. A scan uses one profile, so choose that one or set up a new signer.`);
  return out;
}

/** The form for a new signer: origins default to the operations' hosts. */
export const newSignerForm = (origins: string[]): SignerForm => ({ ...EMPTY_SIGNER, origins: origins.join("\n") });

/** A `sign:NAME` session rule for one origin, any tool. */
export const signRuleForm = (signer: string, origin: string): RuleForm => ({
  tools: [],
  url: `${origin}/`,
  invalid: "",
  description: "Signs the API guided scan's requests",
  actions: [{ action: "sign", signer }],
});

/** `auth rule add` per origin. A rule takes one URL, and a signer can sign for several. */
export function signRuleArgs(profile: string, signer: string, origins: string[]): string[][] {
  const clean = new Set(origins.map((o) => originOf(o.trim())).filter((o): o is string => !!o));
  return [...clean].map((o) => ruleAddArgs(profile, signRuleForm(signer, o)));
}

/** Origins out of a signer form's text. */
export const signerFormOrigins = (f: Pick<SignerForm, "origins">): string[] =>
  f.origins
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

/** Whether a rule's `--url` covers a URL: a host pattern or a URL prefix, as the CLI matches it. */
export function urlPatternMatches(pattern: string, url: string): boolean {
  const glob = pattern.trim().replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  if (pattern.includes("://")) return new RegExp(`^${glob}`, "i").test(url);
  const u = parseUrl(url);
  if (!u) return false;
  const wild = glob.startsWith(".*\\.") ? `(.*\\.)?${glob.slice(4)}` : glob;
  return new RegExp(`^${wild}$`, "i").test(u.hostname);
}

export interface SignerCoverage {
  state: "covered" | "no_rule" | "tool_limited" | "url_limited" | "origin_limited";
  /** The plain-words warning ("" when covered). */
  message: string;
  /** Whether a rule would sign "Try one request", which `import api` sends as the crawl tool. */
  checkCovered: boolean;
}

/** Whether a signer's rules make a scan of these URLs sign its requests. */
export function signerCoverage(rules: SessionRule[], signer: { name: string; origins: string[] }, urls: string[]): SignerCoverage {
  const uses = rules.filter((r) => r.actions.some((a) => a.action === "sign" && a.signer === signer.name));
  const forTool = (tool: string) => uses.filter((r) => !r.tools?.length || (r.tools as string[]).includes(tool));
  const reach = (r: SessionRule, u: string) => !r.url || urlPatternMatches(r.url, u);
  const checkCovered = forTool("crawl").length > 0;
  if (!uses.length) return { state: "no_rule", checkCovered, message: `No session rule uses "${signer.name}", so a scan would send unsigned requests.` };
  const scan = forTool("scan");
  if (!scan.length) return { state: "tool_limited", checkCovered, message: `The session rule for "${signer.name}" is limited to other tools, so a scan would send unsigned requests.` };
  if (!urls.every((u) => scan.some((r) => reach(r, u)))) return { state: "url_limited", checkCovered, message: `The session rule for "${signer.name}" doesn't cover every address being scanned, so some requests would go unsigned.` };
  const outside = operationOrigins(urls.map((url) => ({ url }))).filter((o) => !signer.origins.includes(o));
  if (outside.length) return { state: "origin_limited", checkCovered, message: `"${signer.name}" may only sign for ${signer.origins.join(", ")}, so requests to ${outside.join(", ")} would go unsigned. Change its origins in Settings → Auth profiles.` };
  return { state: "covered", checkCovered, message: "" };
}

/** Whether a recorded request carries a signer's placeholder: history never holds the signature. */
export function signerOnRequest(raw: string, profile: string, signer: string): boolean {
  const mark = `«auth:${profile}:sign:${signer}`;
  return raw.includes(`${mark}»`) || raw.includes(`${mark}:`);
}

/** Whether a recorded request carries one of the profile's other placeholders (key, cookie, token). */
export function credentialOnRequest(raw: string, profile: string): boolean {
  const mark = `«auth:${profile}:`;
  return raw.split(mark).slice(1).some((rest) => !rest.startsWith("sign:"));
}

export interface CheckFacts {
  status: number | null;
  /** The transport error, when there's no status. */
  error?: string;
  profile: string;
  signer: string;
  /** From the recorded request; null when it couldn't be read. */
  credentialOn: boolean | null;
  signerOn: boolean | null;
  /** False when a signer's rule doesn't apply to this check, though a scan might sign. */
  signerRuleApplies: boolean;
}

/** What "Try one request" found, in plain words. Holds no value from the request. */
export function checkMeaning(c: CheckFacts): { tone: "ok" | "warn" | "bad"; text: string } {
  const on: string[] = [];
  if (c.profile && c.credentialOn === true) on.push(`The credentials from "${c.profile}" were on it.`);
  if (c.profile && c.credentialOn === false && !c.signer) on.push(`Nothing from "${c.profile}" was on it.`);
  if (c.signer && c.signerOn === true) on.push(`The signature from "${c.signer}" was on it.`);
  if (c.signer && c.signerOn === false)
    on.push(c.signerRuleApplies ? `The signature from "${c.signer}" was not on it.` : `It went unsigned, because the session rule for "${c.signer}" doesn't apply to this check. A scan may still sign.`);
  if (c.credentialOn === null && c.signerOn === null && (c.profile || c.signer)) on.push("The recorded request couldn't be read to confirm what was on it.");
  const tail = on.length ? ` ${on.join(" ")}` : "";
  const s = c.status;
  if (s == null) return { tone: "bad", text: `No response${c.error ? `: ${c.error}` : ""}. Check the server address.${tail}` };
  if (s >= 200 && s < 300) return { tone: "ok", text: `${s}: accepted.${c.profile ? "" : " The API answers this operation without authentication."}${tail}` };
  if ((s === 401 || s === 403) && c.signer && c.signerOn === false && !c.signerRuleApplies) return { tone: "warn", text: `${s}: rejected, which an API that needs signatures does to an unsigned request, so this doesn't show whether the scan will work.${tail}` };
  if (s === 401 || s === 403) return { tone: "bad", text: `${s}: rejected. The API refused this request${c.profile ? ", so check the key and where it goes" : " without authentication"}.${tail}` };
  if (s >= 300 && s < 400) return { tone: "warn", text: `${s}: redirected. The API may be sending this request to a login page.${tail}` };
  if (s >= 500) return { tone: "warn", text: `${s}: the server failed. That says nothing about authentication.${tail}` };
  return { tone: "warn", text: `${s}: the server answered, but not with success. The example values may not exist, so this doesn't show whether authentication works.${tail}` };
}

/** `import api --only N --max-requests 1`: sends one request. */
export function checkArgs(source: string, sha256: string, t: ApiTarget, index: number, profile: string): string[] {
  return [
    "import",
    "api",
    `--only=${index}`,
    "--max-requests=1",
    `--expect-sha256=${sha256}`,
    ...targetArgs(t),
    ...(profile ? [`--auth=${profile}`] : []),
    "--",
    source.trim(),
  ];
}

export function authSummary(a: AuthState): string {
  if (a.mode === "profile") return `existing profile "${a.existing}"`;
  if (a.mode === "key") {
    const what = a.keyKind === "bearer" ? "bearer token" : a.place === "query" ? `API key in query parameter ${a.keyName.trim()}` : `API key in header ${a.keyName.trim()}`;
    return `${what}, saved in profile "${a.savedProfile}"`;
  }
  return a.signing && a.signer ? `no key (profile "${a.signer.profile}" holds the signer)` : "none";
}

export const signingSummary = (a: AuthState): string => (a.signing && a.signer ? `every request signed with "${a.signer.name}"` : "off");

/** A declared or embedded credential, in plain words. Never holds a value: the preview has none. */
export function credentialText(c: ApiCredential): string {
  const where = c.name ? (c.in ? `${c.in} ${c.name}` : c.name) : c.in ?? "";
  const label: Record<CredentialKind, string> = {
    api_key: `API key${where ? ` (${where})` : ""}`,
    bearer: "Bearer token",
    basic: "HTTP Basic",
    oauth2: "OAuth 2",
    openid: "OpenID Connect",
    mutual_tls: "Mutual TLS",
    other: `Other${where ? ` (${where})` : ""}`,
  };
  const head = label[c.kind] ?? c.kind;
  if (c.embedded) return `${head}: the file held this credential. It will not be used. Set one up here if the API needs it.`;
  if (c.kind === "oauth2" || c.kind === "openid" || c.kind === "mutual_tls") return `${head}: can't be set up here. A token obtained elsewhere can be used as a bearer token, if the API accepts one.`;
  if (c.kind === "basic" || c.kind === "other" || (c.kind === "api_key" && c.in === "cookie")) return `${head}: not set up here. Create a profile in Settings → Auth profiles and pick it as an existing profile.`;
  return `${head}: the definition asks for this.`;
}

// --- Depth, start and progress ---

const DEPTH_TEXT: Record<Depth, string> = {
  quick: "Sends each operation and tries the most common attacks with few requests.",
  standard: "A balanced test of every ticked operation, including IDs in their paths. Good for a first assessment, but sends many requests.",
  thorough: "Everything in Standard, but deeper, with many more attack variations. Sends a lot of requests.",
};

/** A depth's text without the crawling words: an API scan sends what the definition lists. */
export const apiDepthText = (d: Depth): string => DEPTH_TEXT[d];

const SPEED_TEXT: Record<string, string> = {
  gentle: "For fragile or shared APIs. Slower.",
  normal: "Suits most APIs.",
  fast: "Not recommended. Can overload the API and disrupt it for real users. Only for test servers you can afford to take down.",
};

export const apiSpeedText = (id: string): string => SPEED_TEXT[id] ?? "";

export interface ScanPlan {
  source: string;
  sha256: string;
  target: ApiTarget;
  operations: ApiOperation[];
  selected: number[];
  profile: string;
  depth: Depth;
  /** The chosen speed's flags. */
  speedArgs: string[];
}

/** `scan active --api`: in one job, baselines then the attacks, on exactly the ticked operations. */
export function scanArgs(p: ScanPlan): string[] {
  const include = includeMethods(p.operations, p.selected);
  return [
    "scan",
    "active",
    `--api=${p.source.trim()}`,
    `--expect-sha256=${p.sha256}`,
    ...targetArgs(p.target),
    `--only=${[...p.selected].sort((a, b) => a - b).join(",")}`,
    ...(include.length ? [`--include-methods=${include.join(",")}`] : []),
    ...(p.profile ? [`--auth=${p.profile}`] : []),
    ...depthArgs(p.depth),
    ...p.speedArgs,
    "--background",
  ];
}

/** Whether a job is a `scan active --api` run. Its args survive a reload; this flow's state doesn't. */
export const isApiJob = (args: string[] | null | undefined): boolean => !!args?.some((a) => a === "--api" || a.startsWith("--api="));

/** The baseline stage of a scan's progress, in API words. */
export const baselineText = (pr: { sent?: number; total?: number }): string =>
  `Sending each operation once to record a normal response: ${pr.sent ?? 0} of ${pr.total ?? 0} sent.`;

export interface ImportSummary {
  sent?: number;
  by_status?: Record<string, number>;
  errors?: number;
  skipped_out_of_scope?: number;
  out_of_scope_hosts?: string[];
  skipped?: { operation: string; reason: string }[];
}

/** What a finished API scan should say besides its findings: a clean result behind 401s isn't clean. */
export function apiResultNotes(r: ImportSummary | null | undefined): string[] {
  if (!r) return [];
  const out: string[] = [];
  const by = r.by_status ?? {};
  const rejected = (by["401"] ?? 0) + (by["403"] ?? 0);
  const n = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
  if (rejected)
    out.push(`${n(rejected, "operation was", "operations were")} rejected (401 or 403) of ${r.sent ?? rejected} sent. They were scanned anyway, but what's behind authentication was not reached, so check the authentication.`);
  if (r.errors) out.push(`${n(r.errors, "operation")} got no response and couldn't be scanned.`);
  if (r.skipped_out_of_scope)
    out.push(`${n(r.skipped_out_of_scope, "operation")} outside the project's scope ${r.skipped_out_of_scope === 1 ? "was" : "were"} skipped${r.out_of_scope_hosts?.length ? ` (${r.out_of_scope_hosts.join(", ")})` : ""}.`);
  if (r.skipped?.length) out.push(`${n(r.skipped.length, "operation")} in the definition couldn't be built.`);
  return out;
}
