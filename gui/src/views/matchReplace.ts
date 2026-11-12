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
  /** text unless it says script: then `script` makes the replacement. */
  replacer?: string;
  /** The script file, and the sha256 its text had when the rule was added. */
  script?: { file: string; sha256: string };
}

/** A rule the engines leave out, as `rules list` says: its replacement breaks a head, or its script file changed. */
export interface Skipped {
  id: number;
  reason: string;
}

/** The rule being written in the editor. */
export interface Draft {
  location: string;
  name: string;
  action: string;
  matcher: string;
  match: string;
  replace: string;
  /** What makes the replacement: the text in `replace`, or the script file in `script`. */
  replacer: "text" | "script";
  /** The script file's path. */
  script: string;
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
  replacer: "text",
  script: "",
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
  { id: "request", label: "Whole request (script)", group: "Request" },
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
/** A request rule: its script gets the whole request, and may change, block or answer it. */
export const isRequestRule = (location: string) => location === "request";
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
    // A request rule is a script, nothing else.
    replacer: isRequestRule(location) ? "script" : draft.replacer,
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
  if (isRequestRule(draft.location)) return draft.script.trim() ? null : "Choose the script file: it defines request(req, ctx).";
  if (isScripted(draft)) {
    if (named && draft.action === "remove") return "Remove writes nothing, so it takes no script.";
    // What the script returns is checked when it runs: a status, a header line, anything.
    return draft.script.trim() ? null : "Choose the script file.";
  }
  if (named) return null;
  if (!draft.match && !draft.replace) return "Give a match, a replacement, or both.";
  if (draft.location === "status" && !/^[1-9]\d\d( .*)?$/.test(draft.replace) && !(draft.matcher === "regex" && draft.replace.includes("$")))
    return 'A status is a code, with a reason if you like: "404" or "404 Not Found".';
  return null;
}

/** Whether a script makes the draft's replacement. */
export const isScripted = (draft: Draft) => draft.replacer === "script" || isRequestRule(draft.location);

/** A script file's name without its folders, for a table cell or a question. */
export const scriptName = (file: string) => file.split(/[\\/]/).pop() || file;

/** The flags that say what a draft is, shared by `rules add` and `rules test`. */
function specArgs(draft: Draft): string[] {
  const named = isNamed(draft);
  const args = [`--location=${draft.location}`];
  if (isRequestRule(draft.location)) {
    // The script is given the whole request: nothing to match, nothing to write.
    args.push(`--script=${draft.script.trim()}`);
    if (draft.host.trim()) args.push(`--host=${draft.host.trim()}`);
    return args;
  }
  // Add takes no match and remove no replacement: what was typed for another action is left out.
  if (!(named && draft.action === "add")) args.push(`--match=${draft.match}`);
  // A script makes the replacement in place of the text, which is left out as typed for the other.
  if (isScripted(draft)) args.push(`--script=${draft.script.trim()}`);
  else if (!(named && draft.action === "remove")) args.push(`--replace=${draft.replace}`);
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
  if (isRequestRule(rule.location)) return "(the whole request)";
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
  if (rule.replacer === "script") return `script ${scriptName(rule.script?.file ?? "")}`;
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
  /** Rules whose script failed on the message: each left it as it was. */
  errors?: { id: number; error: string }[];
  /** A request rule's script blocked or answered the request: nothing would be sent. */
  stopped?: Stopped;
  /** This side is a script's answer, not anything the rules were tried on. */
  answer?: boolean;
}

/** What a request rule's script did instead of letting the request go, as `rules test` says. */
export interface Stopped {
  rule: number;
  outcome: "blocked" | "answered";
  reason?: string;
  response?: { encoding: "utf8" | "base64"; content: string; truncated?: boolean };
}

/** What a stopped request's note says: who stopped it, how, and that nothing would be sent. */
export function stoppedNote(s: Stopped): string {
  const who = s.rule === 0 ? "this rule's script" : `rule ${s.rule}'s script`;
  return s.outcome === "answered" ? `Answered by ${who}: nothing would be sent` : `Blocked by ${who}: nothing would be sent`;
}

/** What `rules test` answers. */
export interface TestResult {
  request?: Tested;
  response?: Tested;
  message?: Tested;
  host: string;
  tried: number[];
  /** Rules left out because their script can't run now. */
  skipped?: Skipped[];
}

/** "Changed by rule 3, 5", "Changed by this rule", or "Unchanged", for a tested message. */
export function testedNote(t: Tested): string {
  if (t.answer) return "The script's response, which the target never sent";
  if (t.stopped) return t.changed ? `${stoppedNote(t.stopped)} (changed first by rule ${t.rules.join(", ")})` : stoppedNote(t.stopped);
  if (!t.changed) return "Unchanged";
  const saved = t.rules.filter((id) => id !== 0);
  if (!saved.length) return "Changed by this rule";
  return `Changed by rule ${saved.join(", ")}${saved.length < t.rules.length ? " and this rule" : ""}`;
}

/** What went wrong with scripts in a test, one line each; empty when nothing did. */
export function testedProblems(t: Tested, skipped: Skipped[] = []): string[] {
  const who = (id: number) => (id === 0 ? "This rule's script" : `Rule ${id}'s script`);
  return [...(t.errors ?? []).map((e) => `${who(e.id)} failed, so it changed nothing: ${e.error}`), ...skipped.map((s) => `Rule ${s.id} was left out: ${s.reason}`)];
}

/** The last time a rule's script failed in an engine, as `rules list` says. */
export interface Failure {
  id: number;
  error: string;
  time: string;
  engine: string;
}

/** What a rule's row says of its script's last failure; null when none is noted. */
export function failureNote(rule: Rule, failures: Failure[]): string | null {
  const f = failures.find((x) => x.id === rule.id);
  if (!f) return null;
  const engine = [...HTTP_ENGINES, ...WS_ENGINES].find((e) => e.id === f.engine)?.label ?? f.engine;
  const where = f.engine.startsWith("ws-") ? `a WebSocket message ${engine.toLowerCase()}` : `the ${engine === "Scans" ? "scans" : engine}`;
  return `its script last failed ${f.time.replace("T", " ").replace(/\.\d+Z$/, " UTC")} in ${where}, leaving the message as it was: ${f.error}`;
}

/** Why a saved rule is left out by the engines, for its row; null when it isn't. */
export const skippedReason = (rule: Rule, skipped: Skipped[]) => skipped.find((s) => s.id === rule.id)?.reason ?? null;

/**
 * What an import would bring in, read from clipboard text (`rules list` JSON or a bare list):
 * how many rules, and the script files they would run. Null when the text holds no rules.
 */
export function importSummary(text: string): { count: number; scripts: string[] } | null {
  let list: unknown;
  try {
    const parsed = JSON.parse(text);
    list = Array.isArray(parsed) ? parsed : (parsed?.rules ?? parsed?.data?.rules);
  } catch {
    return null;
  }
  if (!Array.isArray(list) || !list.length) return null;
  const scripts = list.map((r) => r?.script?.file).filter((f): f is string => typeof f === "string" && f !== "");
  return { count: list.length, scripts: [...new Set(scripts)] };
}

/** The question asked before rules are imported; it names the scripts they would run. */
export function importQuestion(summary: { count: number; scripts: string[] }): string {
  const rules = `Add the ${summary.count} rule${summary.count === 1 ? "" : "s"} on the clipboard to this project?`;
  if (!summary.scripts.length) return rules;
  const files = summary.scripts.join(", ");
  return `${rules} ${summary.scripts.length === 1 ? "One runs a script" : "Some run scripts"} on this computer for every match, cut off from your files and the network: ${files}. Read ${summary.scripts.length === 1 ? "it" : "them"} first.`;
}

/** The question asked before a rule with a script is added. */
export const scriptQuestion = (file: string, location = "") =>
  isRequestRule(location)
    ? `${scriptName(file)} will see every request this rule applies to, cut off from your files and the network, and can change it, block it, or answer it with a response of its own so nothing is sent. Read it before you add it. If the file changes later, the rule stops until you add it again.`
    : `${scriptName(file)} will run for every match of this rule, cut off from your files and the network, with the message it works on in reach. Read it before you add it. If the file changes later, the rule stops until you add it again.`;

/** The sides a result has, in order: a file's one message, or a history row's request and response. */
export function testedSides(r: TestResult): { id: "request" | "answer" | "response" | "message"; label: string; tested: Tested }[] {
  const answer = r.request?.stopped?.response;
  const sides = [
    { id: "request" as const, label: "Request", tested: r.request },
    { id: "answer" as const, label: "Script's answer", tested: answer && { changed: false, rules: [], result: answer, answer: true } },
    { id: "response" as const, label: "Response", tested: r.response },
    { id: "message" as const, label: "Message", tested: r.message },
  ];
  return sides.filter((s): s is typeof s & { tested: Tested } => !!s.tested);
}

/** "Changed by match-and-replace rule 1, 2", from a row's `edited_by` or `response_edits`. */
export function ruleEditNote(edits: { rule?: number | null; outcome?: string }[] | undefined): string {
  const ids = (edits ?? []).filter((e) => !e.outcome).map((e) => e.rule).filter((id): id is number => id != null);
  const changed = ids.length ? `Changed by match-and-replace rule ${ids.join(", ")}` : "Changed by a match-and-replace rule";
  const stop = scriptStop(edits);
  if (!stop) return changed;
  return ids.length ? `${changed}. ${stop.note}` : stop.note;
}

/**
 * What a request rule's script did with a row's request, from its `edited_by`: it blocked it,
 * or answered it itself (the row's response is the script's: the target sent nothing). Null
 * for a request that went out.
 */
export function scriptStop(edits: { rule?: number | null; outcome?: string }[] | undefined): { outcome: "blocked" | "answered"; rule: number; note: string } | null {
  const e = (edits ?? []).find((x) => x.outcome === "blocked" || x.outcome === "answered");
  if (!e || e.rule == null) return null;
  return e.outcome === "answered"
    ? { outcome: "answered", rule: e.rule, note: `Answered by the script of rule ${e.rule}: the response is the script's, the target sent nothing` }
    : { outcome: "blocked", rule: e.rule, note: `Blocked by the script of rule ${e.rule}: nothing was sent` };
}

/** Whether a finding's alert type is one raised from a response a request rule's script made up. */
export const isScriptAnswer = (alertRef: string | null | undefined) => (alertRef ?? "").startsWith("script-answer:");

/** What a finding raised from a script's answer says over it. */
export const SCRIPT_ANSWER_NOTE =
  "Found in a response a request rule's script made up, not one the target sent: its host and URL are where the request was going. Send the request to the target to see whether it holds there.";
