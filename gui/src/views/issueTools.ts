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
  /** A triage state set for the whole issue (`findings mark --issue`), which its new findings take. */
  decision?: { state: string } | null;
  /** A risk or confidence set for the whole issue (`findings rate --issue`), which its new findings take. */
  rating?: { risk: string | null; confidence: string | null } | null;
}

/**
 * Most issues the view asks for. Issues are sorted by risk and findings by id, so capping both
 * at the same count could leave a shown finding's issue out; no project has this many.
 */
export const ISSUE_LIMIT = 1_000_000;

/**
 * Issues per merge call and findings per split: each id is an argument, and Windows caps a
 * command line at 32,767 characters (the same reason `markCommands` batches).
 */
export const MERGE_BATCH = 500;
export const SPLIT_MAX = 2000;

/** The command that lists the issues of findings in `states`, past the CLI's default of 200. */
export function issuesArgs(states: string, limit = ISSUE_LIMIT): string[] {
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
 * The commands that move every finding of `from` into `into`, in batches of MERGE_BATCH issues
 * (each a merge of its own, so a batch done stays done); none when there is nothing to move
 * (`into` is left out of `from`, and each issue is named once).
 */
export function mergeCommands(into: number, from: readonly number[]): string[][] {
  const others = [...new Set(from)].filter((i) => i !== into);
  const out: string[][] = [];
  for (let i = 0; i < others.length; i += MERGE_BATCH) out.push(["findings", "issue", "merge", String(into), ...others.slice(i, i + MERGE_BATCH).map(String)]);
  return out;
}

const plural = (ids: IssueInfo[], one: string, many: string) => `${ids.map((i) => `#${i.id}`).join(", ")} ${ids.length === 1 ? one : many}`;

/** What a merge changes that the dialog should say before it runs. */
export function mergeWarning(into: IssueInfo | undefined, from: readonly IssueInfo[]): string {
  const others = from.filter((i) => i.id !== into?.id);
  const alerts = new Set([into, ...from].filter((i) => i != null).map((i) => i.alert_ref));
  const parts: string[] = [];
  // An issue without a title of its own is listed (and reported) under one of its findings'
  // names (the CLI's COALESCE(title, max(name))), which after a mixed merge may be another alert's.
  if (alerts.size > 1)
    parts.push(
      into?.titled
        ? "These issues come from different alerts; the merged issue keeps its title."
        : "These issues come from different alerts, and the one you keep has no title of its own: it may then be listed under another alert's name. Rename it after merging.",
    );
  const lost = others.filter((i) => i.titled || i.cvss);
  if (lost.length) parts.push(`${plural(lost, "has a title or CVSS rating of its own", "have a title or CVSS rating of their own")}, which the merged issue doesn't take.`);
  // New findings of the merged issues' alerts and hosts join the kept issue (issue_for) and take
  // its whole-issue decision and rating (inherit_decision, inherit_rating); the emptied ones' stop.
  if (into && (into.decision || into.rating)) {
    const what = [into.decision && `marked ${into.decision.state.replace(/_/g, " ")}`, into.rating && "rated"].filter(Boolean).join(" and ");
    parts.push(`#${into.id} is ${what} as a whole: new findings of the issues merged into it will arrive ${what} the same way.`);
  }
  const decided = others.filter((i) => i.decision || i.rating);
  if (decided.length) parts.push(`${plural(decided, "is marked or rated as a whole", "are marked or rated as a whole")}; that stops applying to their new findings.`);
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
  if (picked > SPLIT_MAX) return `Move at most ${SPLIT_MAX.toLocaleString("en")} findings at a time; split again for the rest.`;
  return "";
}

/**
 * Why the findings can't be split off `issue` now, or "": they must all still be in it, with
 * at least one left behind. Checked again just before the split, against the issue as the CLI
 * has it then, since `findings issue split` takes the findings and not the issue they came from.
 */
export function staleSplit(issue: number, picked: readonly number[], now: readonly FindingItem[]): string {
  const ids = new Set(now.map((f) => f.id));
  const gone = picked.filter((id) => !ids.has(id));
  if (gone.length) return `Issue #${issue} changed meanwhile: ${gone.map((id) => `#${id}`).join(", ")} ${gone.length === 1 ? "is" : "are"} no longer in it. Check the findings again.`;
  if (picked.length >= now.length) return `Issue #${issue} changed meanwhile: these would be all of its findings now.`;
  return "";
}

/** Why an issue's menu can't merge or split it, or "" when it can. */
export function issueActionProblems(issue: IssueInfo, issueCount: number): { merge: string; split: string } {
  return {
    merge: issueCount < 2 ? "There is no other issue" : "",
    split: issue.instances < 2 ? "It has one finding" : "",
  };
}

/**
 * What the ticked findings (those shown) can do to their issues: merge their issues when they
 * are in two or more, or split off when they are some, not all, of one issue's findings.
 */
export function pickedActions(picked: readonly number[], byId: ReadonlyMap<number, FindingItem>, issues: ReadonlyMap<number, IssueInfo>): { merge: IssueInfo[]; split: IssueInfo | null } {
  const of = issuesOfFindings(picked, byId);
  const known = of.flatMap((id) => issues.get(id) ?? []);
  const merge = of.length > 1 && known.length === of.length ? known : [];
  const one = of.length === 1 ? issues.get(of[0]) : undefined;
  const ticked = picked.filter((id) => byId.get(id)?.issue_id === one?.id).length;
  return { merge, split: one && ticked < one.instances ? one : null };
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
