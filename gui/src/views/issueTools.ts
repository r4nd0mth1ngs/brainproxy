// Rearranging issues from Findings: renaming one, merging issues, splitting findings off into a
// new one, rating it with CVSS. The commands and the checks the dialogs make before running
// them; kept apart from the view so they can be tested without a window.

import type { FindingItem, Risk } from "../api.ts";

/** An issue as `findings issues` lists it (the fields the view uses). */
export interface IssueInfo {
  id: number;
  alert_ref: string;
  /** Its own title, else its alert's name. */
  title: string;
  /** True when it has a title of its own (`findings issue title`). */
  titled: boolean;
  risk: Risk;
  /** The hosts of its findings, joined. */
  host: string;
  instances: number;
  cvss: { vector: string; score: number; severity: string } | null;
}

/**
 * The command that lists the issues of findings in `states`, as many as the view holds
 * findings, so none of them is cut off by the CLI's default of 200.
 */
export function issuesArgs(states: string, limit: number): string[] {
  return ["findings", "issues", "--state", states, "--limit", String(limit)];
}

/** Issues by id. */
export function issueMap(issues: readonly IssueInfo[] | undefined): Map<number, IssueInfo> {
  return new Map((issues ?? []).map((i) => [i.id, i]));
}

/** An issue in a list of them: its number, title and hosts. */
export function issueLabel(i: IssueInfo): string {
  return `#${i.id} ${i.title}${i.host ? ` · ${i.host}` : ""}`;
}

/** Its CVSS rating in short ("CVSS 8.7 high"), or "". */
export function cvssLabel(i: IssueInfo | undefined): string {
  return i?.cvss ? `CVSS ${i.cvss.score.toFixed(1)} ${i.cvss.severity}` : "";
}

/**
 * The command that names an issue; "" goes back to its alert's name. The title is a
 * positional, so `--` keeps one that starts with "-" from being read as a flag.
 */
export function titleCommand(issue: number, title: string): string[] {
  return ["findings", "issue", "title", String(issue), "--", title.trim()];
}

/** The issues `ids` are findings of, in the order first met, leaving out findings with none. */
export function issuesOfFindings(ids: readonly number[], byId: ReadonlyMap<number, FindingItem>): number[] {
  const out: number[] = [];
  for (const id of ids) {
    const issue = byId.get(id)?.issue_id;
    if (issue != null && !out.includes(issue)) out.push(issue);
  }
  return out;
}

/**
 * The command that moves every finding of `from` into `into`, or null when there is nothing
 * to move (`into` is left out of `from`, and each issue is named once).
 */
export function mergeCommand(into: number, from: readonly number[]): string[] | null {
  const others = [...new Set(from)].filter((i) => i !== into);
  return others.length ? ["findings", "issue", "merge", String(into), ...others.map(String)] : null;
}

/** What a merge leaves out of the report: the other issues' own titles, CVSS ratings and write-ups stay with them, unshown. */
export function mergeWarning(into: IssueInfo | undefined, from: readonly IssueInfo[]): string {
  const lost = from.filter((i) => i.id !== into?.id && (i.titled || i.cvss));
  const alerts = new Set([into, ...from].filter((i) => i != null).map((i) => i.alert_ref));
  const parts: string[] = [];
  if (alerts.size > 1) parts.push("These issues come from different alerts: the merged issue keeps the alert, title and rating of the one you keep.");
  if (lost.length) parts.push(`${lost.map((i) => `#${i.id}`).join(", ")} ${lost.length === 1 ? "has" : "have"} a title or CVSS rating of its own, which the merged issue doesn't take.`);
  return parts.join(" ");
}

/** The command that moves `findings` into a new issue, named `title` (else the alert's name). */
export function splitCommand(findings: readonly number[], title: string): string[] {
  const t = title.trim();
  return ["findings", "issue", "split", ...findings.map(String), ...(t ? [`--title=${t}`] : [])];
}

/** Why the picked findings can't be split off an issue of `total` findings, or "". */
export function splitProblem(picked: number, total: number): string {
  if (picked === 0) return "Pick the findings that move to the new issue.";
  if (picked >= total) return "Leave at least one finding in this issue: moving them all only renumbers it.";
  return "";
}

/** The findings of an issue that start ticked in the split dialog: those ticked in the list. */
export function splitStart(issueFindings: readonly number[], checked: ReadonlySet<number>): Set<number> {
  const picked = issueFindings.filter((id) => checked.has(id));
  // All of them ticked (the whole group): none is a better start, since moving all is refused.
  return new Set(picked.length < issueFindings.length ? picked : []);
}

/** Issues matching words typed in the merge dialog's filter: in the title, alert, hosts or `#id`. */
export function filterIssues(issues: readonly IssueInfo[], text: string): IssueInfo[] {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return [...issues];
  return issues.filter((i) => {
    const hay = [i.title, i.alert_ref, i.host, `#${i.id}`].join("\n").toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}
