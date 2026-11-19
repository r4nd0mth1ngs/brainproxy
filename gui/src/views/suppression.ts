// Suppression rules in Findings (`findings suppress add|list|remove`): an alert on a host, maybe
// only under a path or for one parameter, is a false positive wherever a scan finds it, now and
// later. The CLI does the matching and marking; this builds its arguments and says what it did.

import type { FindingItem } from "../api";

/** A rule, as `findings suppress list` gives it. */
export interface SuppressionRule {
  id: number;
  time: string;
  alert_ref: string;
  /** The host name, lowercased and without its port (see `port`). */
  host: string;
  /** Only findings on this port; null for any. */
  port: number | null;
  /** "" for every path. */
  path_prefix: string;
  param: string | null;
  reason: string;
  /** Who added it, in words (`from the desktop app`, say). */
  by: string;
  origin: string | null;
  /** How many findings it marked that are still false positives by it. */
  findings: number;
}

export interface SuppressionList {
  count: number;
  suppressions: SuppressionRule[];
}

/** The fields of the Suppress… dialog, as typed. */
export interface SuppressDraft {
  alert: string;
  host: string;
  pathPrefix: string;
  param: string;
  reason: string;
}

export const SUPPRESS_LIST_ARGS = ["findings", "suppress", "list"];

const DEFAULT_PORTS: Record<string, string> = { "http:": "80", "https:": "443", "ws:": "80", "wss:": "443" };

/**
 * A path as a rule's prefix is matched against it: percent-encoded as a URL's path is, and
 * without the `;name=value` parameters of its segments (`/a;jsessionid=1/b` is `/a/b`), which
 * the CLI leaves out of the path it matches (`identity_url` in core). A `;` piece with no `=`
 * stays, as there.
 */
export function matchPath(path: string): string {
  let encoded = path;
  try {
    // Joined, not resolved against a base, so a path starting with // stays a path.
    encoded = new URL(`http://host.invalid${path}`).pathname;
  } catch {
    /* left as typed: the CLI says what is wrong with it */
  }
  return encoded
    .split("/")
    .map((segment) => {
      const [first, ...rest] = segment.split(";");
      return [first, ...rest.filter((piece) => !piece.includes("="))].join(";");
    })
    .join("/");
}

/**
 * A rule for one finding as a start: its alert, its host and port, its URL's path and its
 * parameter. The person widens it from there, such as cutting the path back to a directory or
 * taking the port off. The port is always given, the scheme's default too: a rule made on one
 * service (app.test:443) must not hide the same alert on another (app.test:8443) unasked.
 */
export function draftFor(f: Pick<FindingItem, "alert_ref" | "host" | "url" | "param">): SuppressDraft {
  let host = f.host;
  let pathPrefix = "";
  try {
    const u = new URL(f.url);
    // `hostname` is bracketed for IPv6; `port` is "" for the scheme's default.
    const port = u.port || DEFAULT_PORTS[u.protocol] || "";
    if (u.hostname) host = port ? `${u.hostname}:${port}` : u.hostname;
    const path = matchPath(u.pathname);
    pathPrefix = path === "/" ? "" : path;
  } catch {
    /* not a URL (a finding added by hand may have none): the host alone */
  }
  return { alert: f.alert_ref, host, pathPrefix, param: f.param ?? "", reason: "" };
}

/** Why the draft can't be added yet (the CLI's own checks, said before it runs); null when it can. */
export function draftProblem(d: SuppressDraft): string | null {
  const host = d.host.trim();
  const prefix = d.pathPrefix.trim();
  if (!d.alert.trim()) return "Give the alert ref or rule id it suppresses";
  if (!host) return "Give the host";
  if (/[/\s@?#]/.test(host)) return "The host is a name such as app.test, or 127.0.0.1:3000 for that port only";
  if (prefix && !prefix.startsWith("/")) return "A path prefix starts with /";
  // The path matched has no query or fragment, so a prefix holding one would never match.
  if (/[?#]/.test(prefix)) return "A path prefix is part of the path: no ? or #";
  if (!d.reason.trim()) return "Give the reason: it becomes the note of each finding the rule marks";
  return null;
}

/**
 * `findings suppress add` for the draft. Values go as `--flag=value`, so one that starts with
 * "-" (a reason, a parameter) isn't read as a flag. An empty path or parameter matches any. A
 * typed path goes as the CLI matches paths (`matchPath`), so /café/ covers /caf%C3%A9/.
 */
export function suppressAddArgs(d: SuppressDraft): string[] {
  const args = ["findings", "suppress", "add", `--alert=${d.alert.trim()}`, `--host=${d.host.trim()}`];
  const prefix = d.pathPrefix.trim();
  if (prefix) args.push(`--path-prefix=${matchPath(prefix)}`);
  // Trimmed: the CLI matches a parameter exactly, so a stray space would make a rule that never matches.
  const param = d.param.trim();
  if (param) args.push(`--param=${param}`);
  args.push(`--reason=${d.reason.trim()}`);
  return args;
}

export function suppressRemoveArgs(id: number, reopen: boolean): string[] {
  return ["findings", "suppress", "remove", String(id), ...(reopen ? ["--reopen"] : [])];
}

/** Where a rule applies, as one line: `app.test:3000/static/ · parameter id`. */
export function ruleWhere(r: Pick<SuppressionRule, "host" | "port" | "path_prefix" | "param">): string {
  // An IPv6 address is bracketed once a port follows it, as in a URL.
  const name = r.port != null && r.host.includes(":") && !r.host.startsWith("[") ? `[${r.host}]` : r.host;
  const where = `${name}${r.port != null ? `:${r.port}` : ""}${r.path_prefix}`;
  return r.param != null && r.param !== "" ? `${where} · parameter ${r.param}` : where;
}

/** How many findings the rules hold as false positives now. */
export const suppressedCount = (rules: readonly Pick<SuppressionRule, "findings">[]): number => rules.reduce((n, r) => n + r.findings, 0);

const findings = (n: number) => `${n} finding${n === 1 ? "" : "s"}`;

/**
 * What to say once a rule is added. `from`: the finding it was made from, read again after, when
 * the rule left it as it was (someone triaged it before, so it stays theirs).
 */
export function addedNote(id: number, marked: number, from?: Pick<FindingItem, "id" | "state" | "suppressed_by"> | null): string {
  const said = marked
    ? `Suppression rule ${id} added: it marked ${findings(marked)} false positive.`
    : `Suppression rule ${id} added. No open, untriaged finding matched it yet; it marks the ones scans find from now on.`;
  if (!from || from.suppressed_by === id || from.state === "false_positive") return said;
  const why = from.state === "open" ? "the rule doesn't match it, or someone triaged it before" : "someone triaged it";
  return `${said} Finding #${from.id} stays ${from.state.replace(/_/g, " ")}: ${why}, and a rule leaves a person's triage alone. Mark it yourself if it is a false positive too.`;
}

/** What to say once a rule is removed. `held`: how many findings it held when it was removed. */
export function removedNote(id: number, reopened: number, reopen: boolean, held: number): string {
  if (reopen) return `Suppression rule ${id} removed: ${findings(reopened)} open again.`;
  if (!held) return `Suppression rule ${id} removed.`;
  return `Suppression rule ${id} removed. The ${held === 1 ? "finding it marked stays a false positive" : `${held} findings it marked stay false positives`}.`;
}

/**
 * A suppressed finding's rule, as its detail says it. Removing a rule without reopening leaves
 * the id on its findings, so once the rules are read and it isn't among them it is said to be
 * gone, not linked to a list without it. `rules` null: not read yet.
 */
export function suppressedBy(id: number, rules: readonly Pick<SuppressionRule, "id">[] | null | undefined): { text: string; live: boolean } {
  if (rules && !rules.some((r) => r.id === id)) return { text: `by rule ${id}, since removed`, live: false };
  return { text: `by rule ${id}`, live: true };
}

/**
 * What changes the rules' counts, from the findings list: which findings are false positives by
 * which rule. When it changes (a rescan, a triage, a rule added elsewhere marking findings) the
 * rules are read again, rather than polling them often (each read counts every rule's findings).
 */
export function suppressedKey(items: readonly Pick<FindingItem, "id" | "state" | "suppressed_by">[] | null | undefined): string {
  return (items ?? [])
    .filter((f) => f.suppressed_by != null && f.state === "false_positive")
    .map((f) => `${f.id}:${f.suppressed_by}`)
    .join(",");
}

/** The toolbar button's text: the rules, and the findings they hold. */
export function rulesLabel(rules: readonly Pick<SuppressionRule, "findings">[] | null | undefined): string {
  if (!rules?.length) return "Suppression rules…";
  const n = suppressedCount(rules);
  return `Suppression rules (${rules.length}) · ${n} suppressed…`;
}

/** Whether a finding can start a rule: scanners' findings only, since a rule leaves findings added by hand alone. */
export const canSuppress = (f: Pick<FindingItem, "source">) => f.source !== "manual";

/** The rules dialog's opening line: what the rules hold, or how to make one. */
export function rulesSummary(rules: readonly Pick<SuppressionRule, "findings">[]): string {
  if (!rules.length) return "No rules yet. Open a scanner's finding that is a false positive and choose Suppress… to make one.";
  const n = suppressedCount(rules);
  return `${findings(n)} ${n === 1 ? "is a false positive" : "are false positives"} by these rules. Reports count them among the false positives left out.`;
}

/** Alert refs to their names, from the findings loaded, for the rules dialog. */
export function alertNames(items: readonly Pick<FindingItem, "alert_ref" | "name">[]): Map<string, string> {
  const names = new Map<string, string>();
  for (const f of items) if (!names.has(f.alert_ref)) names.set(f.alert_ref, f.name);
  return names;
}
