// Match & replace rules as the app edits them: what a draft must hold, the `rules add` and
// `rules test` commands made from it, and how a saved rule reads in the table.

/** A rule as `rules list` gives it. */
export interface Rule {
  id: number;
  location: string;
  pattern: string;
  replace: string;
  enabled: boolean;
  comment?: string;
  origin?: string;
  /** regex unless it says literal or whole. */
  matcher?: string;
  /** The header or query parameter it works on. */
  name?: string;
  /** set unless it says add or remove. */
  action?: string;
  /** Absent: the proxy (a ws-message rule: both directions). */
  applies_to?: string[];
  host?: string;
}

/** The rule being written in the editor. */
export interface Draft {
  location: string;
  name: string;
  action: string;
  matcher: string;
  match: string;
  replace: string;
  appliesTo: string[];
  host: string;
  comment: string;
  disabled: boolean;
}

export const EMPTY_DRAFT: Draft = {
  location: "request-header",
  name: "",
  action: "set",
  matcher: "regex",
  match: "",
  replace: "",
  appliesTo: ["proxy"],
  host: "",
  comment: "",
  disabled: false,
};

export const LOCATIONS: { id: string; label: string; group: string }[] = [
  { id: "method", label: "Method", group: "Request" },
  { id: "path", label: "Path", group: "Request" },
  { id: "query-param", label: "Query parameter", group: "Request" },
  { id: "request-header", label: "Request header", group: "Request" },
  { id: "request-body", label: "Request body", group: "Request" },
  { id: "request-line", label: "Request line (raw)", group: "Request" },
  { id: "status", label: "Status code", group: "Response" },
  { id: "response-header", label: "Response header", group: "Response" },
  { id: "response-body", label: "Response body", group: "Response" },
  { id: "ws-message", label: "WebSocket message", group: "WebSocket" },
];

export const MATCHERS = [
  { id: "regex", label: "Regex" },
  { id: "literal", label: "Text" },
  { id: "whole", label: "Whole value" },
];

export const HTTP_ENGINES = [
  { id: "proxy", label: "Proxy" },
  { id: "send", label: "Replay" },
  { id: "fuzz", label: "Fuzzer" },
  { id: "scan", label: "Scans" },
];

export const WS_ENGINES = [
  { id: "ws-to-server", label: "To server" },
  { id: "ws-to-client", label: "To client" },
];

const isWs = (location: string) => location === "ws-message";
const isHeader = (location: string) => location === "request-header" || location === "response-header";

/** Whether a location takes a name: a query parameter must have one, a header may. */
export const takesName = (location: string) => isHeader(location) || location === "query-param";

/** The engines a rule for `location` can apply to. */
export const enginesFor = (location: string) => (isWs(location) ? WS_ENGINES : HTTP_ENGINES);

/** The engines a new rule for `location` applies to unless it says otherwise. */
export const defaultEngines = (location: string) => (isWs(location) ? WS_ENGINES.map((e) => e.id) : ["proxy"]);

/** `draft` moved to another location: what no longer fits is put back to its default. */
export function withLocation(draft: Draft, location: string): Draft {
  const sameKind = isWs(location) === isWs(draft.location);
  return {
    ...draft,
    location,
    name: takesName(location) ? draft.name : "",
    action: takesName(location) ? draft.action : "set",
    appliesTo: sameKind ? draft.appliesTo : defaultEngines(location),
  };
}

/** Whether the draft works on a named header or parameter (and so has an action). */
export const isNamed = (draft: Draft) => takesName(draft.location) && draft.name.trim() !== "";

/**
 * Why the draft can't be added or tried yet; null when it can. The CLI checks the rest. A match
 * typed before the action became Add (or a replacement before Remove) is no problem: it is
 * left out of the command, as the editor's greyed-out field says.
 */
export function draftProblem(draft: Draft): string | null {
  const named = isNamed(draft);
  if (draft.location === "query-param" && !named) return "Name the query parameter.";
  if (!draft.appliesTo.length) return "Choose what the rule applies to.";
  if (named) return null;
  if (!draft.match && !draft.replace) return "Give a match, a replacement, or both.";
  if (draft.location === "status" && !/^[1-9]\d\d( .*)?$/.test(draft.replace) && !(draft.matcher === "regex" && draft.replace.includes("$")))
    return 'A status is a code, with a reason if you like: "404" or "404 Not Found".';
  return null;
}

/** The flags that say what a draft is, shared by `rules add` and `rules test`. */
function specArgs(draft: Draft): string[] {
  const named = isNamed(draft);
  const args = [`--location=${draft.location}`];
  // Add takes no match and remove no replacement: what was typed for another action is left out.
  if (!(named && draft.action === "add")) args.push(`--match=${draft.match}`);
  if (!(named && draft.action === "remove")) args.push(`--replace=${draft.replace}`);
  if (draft.matcher !== "regex") args.push(`--match-kind=${draft.matcher}`);
  if (named) {
    args.push(`--name=${draft.name.trim()}`);
    if (draft.action !== "set") args.push(`--action=${draft.action}`);
  }
  if (draft.host.trim()) args.push(`--host=${draft.host.trim()}`);
  return args;
}

/** `rules add` for a draft. A rule for the default engines says nothing, as rules always did. */
export function addArgs(draft: Draft): string[] {
  const args = ["rules", "add", ...specArgs(draft)];
  const chosen = enginesFor(draft.location)
    .map((e) => e.id)
    .filter((id) => draft.appliesTo.includes(id));
  if (chosen.join() !== defaultEngines(draft.location).join()) args.push(`--applies-to=${chosen.join(",")}`);
  if (draft.comment) args.push(`--comment=${draft.comment}`);
  if (draft.disabled) args.push("--disabled");
  return args;
}

/** What the tester tries: the draft, one saved rule, or every enabled rule as an engine applies them. */
export type TestWhat = { kind: "draft"; draft: Draft } | { kind: "rule"; id: number } | { kind: "engine"; engine: string };

/** What the tester tries it on: text from the box (`message` says what it is) or a history row. */
export interface TestOn {
  /** auto, request, response, ws-to-server or ws-to-client. */
  message: string;
  /** A history id; empty to use the text. */
  history: string;
  /** The host the text is for; empty to use its Host header. */
  host: string;
}

/** `rules test`. With a history id the row's request and response are tried; else the text on stdin. */
export function testArgs(what: TestWhat, on: TestOn): string[] {
  const args = ["rules", "test", "--max-body=2000000"];
  const history = on.history.trim();
  if (history) args.push(`--history=${history}`);
  else {
    args.push("-");
    if (on.message !== "auto") args.push(`--message=${on.message}`);
    if (on.host.trim()) args.push(`--target-host=${on.host.trim()}`);
  }
  if (what.kind === "draft") args.push(...specArgs(what.draft));
  else if (what.kind === "rule") args.push(`--rule=${what.id}`);
  else args.push(`--as=${what.engine}`);
  return args;
}

/** Why the tester can't run yet; null when it can. */
export function testProblem(what: TestWhat, on: TestOn, text: string): string | null {
  if (on.history.trim() && !/^\d+$/.test(on.history.trim())) return "A history id is a number.";
  if (!on.history.trim() && !text) return "Paste a request or response, or give a history id.";
  return what.kind === "draft" ? draftProblem(what.draft) : null;
}

const locationLabel = (id: string) => LOCATIONS.find((l) => l.id === id)?.label ?? id;

/** Where a rule works, for the table: "Query parameter role", "Request header (each line)". */
export function describeWhere(rule: Rule): string {
  if (rule.name) return `${locationLabel(rule.location)} ${rule.name}`;
  return isHeader(rule.location) ? `${locationLabel(rule.location)} (each line)` : locationLabel(rule.location);
}

/** What a rule matches, for the table. */
export function describeMatch(rule: Rule): string {
  if (rule.name && rule.action === "add") return "(add)";
  if (!rule.pattern) {
    if (isHeader(rule.location) && !rule.name) return "(add header)";
    const legacy = (rule.matcher ?? "regex") === "regex" && ["request-line", "request-body", "response-body"].includes(rule.location);
    return legacy ? "(nothing)" : "(whole value)";
  }
  const kind = rule.matcher === "literal" ? "text " : rule.matcher === "whole" ? "is " : "";
  return kind + rule.pattern;
}

/** What a rule writes, for the table: its replacement, or in brackets what an empty one does. */
export function describeReplace(rule: Rule): string {
  if (rule.name && rule.action === "remove") return "(remove)";
  if (rule.replace) return rule.replace;
  // A named header or parameter is set to nothing; a match elsewhere is cut out.
  return rule.name ? "(empty)" : "(remove)";
}

/** What a rule applies to, for the table: "Proxy", "Replay, Fuzzer · host ^api\\." */
export function describeScope(rule: Rule): string {
  const ids = rule.applies_to?.length ? rule.applies_to : defaultEngines(rule.location);
  const names = ids.map((id) => [...HTTP_ENGINES, ...WS_ENGINES].find((e) => e.id === id)?.label ?? id);
  const where = isWs(rule.location) ? `WebSocket: ${names.join(", ").toLowerCase()}` : names.join(", ");
  return rule.host ? `${where} · host ${rule.host}` : where;
}

/** One side of a test's result, as `rules test` gives it. */
export interface Tested {
  changed: boolean;
  rules: number[];
  result: { encoding: "utf8" | "base64"; content: string; truncated?: boolean };
  original?: { encoding: "utf8" | "base64"; content: string };
}

/** What `rules test` answers. */
export interface TestResult {
  request?: Tested;
  response?: Tested;
  message?: Tested;
  host: string;
  tried: number[];
}

/** "Changed by rule 3, 5", "Changed by this rule", or "Unchanged", for a tested message. */
export function testedNote(t: Tested): string {
  if (!t.changed) return "Unchanged";
  const saved = t.rules.filter((id) => id !== 0);
  if (!saved.length) return "Changed by this rule";
  return `Changed by rule ${saved.join(", ")}${saved.length < t.rules.length ? " and this rule" : ""}`;
}

/** The sides a result has, in order: a file's one message, or a history row's request and response. */
export function testedSides(r: TestResult): { id: "request" | "response" | "message"; label: string; tested: Tested }[] {
  const sides = [
    { id: "request" as const, label: "Request", tested: r.request },
    { id: "response" as const, label: "Response", tested: r.response },
    { id: "message" as const, label: "Message", tested: r.message },
  ];
  return sides.filter((s): s is typeof s & { tested: Tested } => !!s.tested);
}

/** "Changed by match-and-replace rule 1, 2", from a row's `edited_by` or `response_edits`. */
export function ruleEditNote(edits: { rule?: number | null }[] | undefined): string {
  const ids = (edits ?? []).map((e) => e.rule).filter((id): id is number => id != null);
  return ids.length ? `Changed by match-and-replace rule ${ids.join(", ")}` : "Changed by a match-and-replace rule";
}
