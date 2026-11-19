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
  /** Who added it, in words (`by you in the app`, say). */
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

/**
 * A rule for one finding as a start: its alert, its host (with the port when the URL names one
 * that isn't the scheme's default, so a rule made on a dev server's port stays on that port),
 * its URL's path and its parameter. The person widens it from there, such as cutting the path
 * back to a directory.
 */
export function draftFor(f: Pick<FindingItem, "alert_ref" | "host" | "url" | "param">): SuppressDraft {
  let host = f.host;
  let pathPrefix = "";
  try {
    const u = new URL(f.url);
    // `host` is name[:port], the port only when it isn't the scheme's default.
    host = u.host || f.host;
    pathPrefix = u.pathname === "/" ? "" : u.pathname;
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
  if (!d.reason.trim()) return "Give the reason: it becomes the note of each finding the rule marks";
  return null;
}

/**
 * `findings suppress add` for the draft. Values go as `--flag=value`, so one that starts with
 * "-" (a reason, a parameter) isn't read as a flag. An empty path or parameter matches any.
 */
export function suppressAddArgs(d: SuppressDraft): string[] {
  const args = ["findings", "suppress", "add", `--alert=${d.alert.trim()}`, `--host=${d.host.trim()}`];
  const prefix = d.pathPrefix.trim();
  if (prefix) args.push(`--path-prefix=${prefix}`);
  // The CLI matches a parameter exactly, spaces and all, so it goes as typed (prefilled from the finding).
  if (d.param.trim()) args.push(`--param=${d.param}`);
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

/** What to say once a rule is removed. */
export function removedNote(id: number, reopened: number, reopen: boolean): string {
  if (!reopen) return `Suppression rule ${id} removed. The findings it marked stay false positives.`;
  return `Suppression rule ${id} removed: ${findings(reopened)} open again.`;
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
