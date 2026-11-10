// What the Findings view shows and the commands its triage runs. Kept apart from the view so
// it can be tested without a window.

import type { FindingEvent, FindingItem } from "../api";

export type Source = "all" | "passive" | "active" | "authz" | "manual";

export const SOURCES: { id: Source; label: string }[] = [
  { id: "all", label: "Any source" },
  { id: "passive", label: "Passive scan" },
  { id: "active", label: "Active scan" },
  { id: "authz", label: "Access control" },
  { id: "manual", label: "Added by hand" },
];

export interface FindingFilter {
  /** Words that must all appear, in any case, in the finding's name, alert, URL, parameter, evidence or state, or `#id`. */
  text: string;
  source: Source;
  /** "" for every host. */
  host: string;
}

export const NO_FILTER: FindingFilter = { text: "", source: "all", host: "" };

export function matchesFinding(f: FindingItem, filter: FindingFilter): boolean {
  if (filter.source !== "all" && f.source !== filter.source) return false;
  if (filter.host && f.host !== filter.host) return false;
  const words = filter.text.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [f.name, f.alert_ref, f.method, f.url, f.param, f.evidence, f.state.replace("_", " "), `#${f.id}`].join("\n").toLowerCase();
  return words.every((w) => hay.includes(w));
}

/** The hosts findings were raised on, sorted, for the host filter. */
export function hostsOf(items: FindingItem[]): string[] {
  return [...new Set(items.map((f) => f.host))].filter(Boolean).sort();
}

/** Findings marked per command: one call is all or nothing, and a few hundred ids keep it short. */
export const MARK_BATCH = 500;

/** The commands that set the triage state of `ids`, in batches. */
export function markCommands(ids: number[], state: string): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < ids.length; i += MARK_BATCH) {
    out.push(["findings", "mark", ...ids.slice(i, i + MARK_BATCH).map(String), "--state", state]);
  }
  return out;
}

/** The command that sets a finding's note; an empty note clears it. */
export function noteCommand(id: number, note: string): string[] {
  return ["findings", "mark", String(id), `--note=${note.trim()}`];
}

/** Who last wrote a note, and when, in words. */
export function noteBy(origin: string | null | undefined, at: string | null | undefined): string {
  const who = origin === "mcp" ? "an agent (via MCP)" : origin === "cli" ? "the command line" : origin === "gui" ? "the desktop app" : "";
  const when = at ? new Date(at).toLocaleString() : "";
  return [who && `by ${who}`, when && `on ${when}`].filter(Boolean).join(" ");
}

/** Triage states, in the order the buttons show them. */
export const STATES: { id: string; label: string; title: string }[] = [
  { id: "open", label: "open", title: "Still to look at or to fix" },
  { id: "confirmed", label: "confirmed", title: "Checked: it is real" },
  { id: "false_positive", label: "false positive", title: "Not a real issue; left out of reports and gates" },
  { id: "accepted_risk", label: "accepted", title: "Real, but accepted and not to be fixed; left out of gates" },
  { id: "retest_pending", label: "retest pending", title: "Fixed by the developers, waiting for a retest" },
  { id: "fixed", label: "fixed", title: "No longer there; it is open again if a scan sees it again" },
];

/** States that need no more work: hidden with "Hide closed". */
export const CLOSED = new Set(["false_positive", "accepted_risk", "fixed"]);

/** What a finding is grouped under: its issue (alert type and host), or its alert type. */
export function groupKey(f: FindingItem): string {
  return f.issue_id != null ? `issue:${f.issue_id}` : `alert:${f.alert_ref}`;
}

/** The command that retests a finding; `unsafe` lets it send a request that may change data. */
export function retestCommand(id: number, unsafe = false): string[] {
  return ["findings", "retest", String(id), ...(unsafe ? ["--allow-unsafe"] : [])];
}

const said = (s: string | null) => (s ?? "").replace(/_/g, " ");

/** A timeline event in words. */
export function eventText(e: FindingEvent): string {
  switch (e.kind) {
    case "created":
      return e.history_id != null ? `Found in history #${e.history_id}` : "Recorded";
    case "state":
      return e.old ? `Marked ${said(e.new)} (was ${said(e.old)})` : `Marked ${said(e.new)}`;
    case "note":
      return e.text ? `Note: ${e.text}` : "Note cleared";
    case "retest":
      return `Retest: ${e.new === "still_present" ? "still there" : "not reproduced"}${e.text ? ` (${e.text})` : ""}`;
    case "regressed":
      return `Seen again after it was fixed${e.history_id != null ? ` (history #${e.history_id})` : ""}: open again`;
    case "moved":
      return `Moved from issue #${e.old} to #${e.new}`;
    case "risk":
      return `Risk ${said(e.old)} → ${said(e.new)}${e.history_id != null ? ` (history #${e.history_id})` : ""}`;
    case "title":
      return e.new ? `Issue renamed "${e.new}"` : "Issue title reset";
    case "removed":
      return "Removed";
    case "ticket":
      return `${e.new === "jira" ? "Jira" : "GitHub"} ticket filed${e.text ? `: ${e.text}` : ""}`;
    default:
      return `${e.kind} ${said(e.new)}`.trim();
  }
}

/** An issue's write-up and who wrote and reviewed it (`findings issue show`'s narrative). */
export interface Narrative {
  text: string;
  /** What a review names: the hash of exactly this text. */
  hash: string;
  origin: string | null;
  at: string | null;
  reviewed_origin: string | null;
  reviewed_at: string | null;
}

/** `findings trail`, in short. */
export interface Trail {
  agent_involved: boolean;
  requests_total: number;
  reviewed_by: string | null;
  reviewed_at: string | null;
}

/** The command that saves an issue's write-up (a draft until reviewed); "" clears it. */
export function narrativeCommand(issue: number, text: string): string[] {
  return ["findings", "issue", "narrative", String(issue), `--text=${text.trim()}`];
}

/** Who wrote a write-up and whether a person has reviewed it, in words. */
export function narrativeCredit(n: Narrative): string {
  const who = (o: string | null) => (o === "mcp" ? "an agent (via MCP)" : o === "gui" ? "the desktop app" : o === "cli" ? "the command line" : "unknown");
  const day = (t: string | null) => (t ? new Date(t).toLocaleDateString() : "");
  const wrote = `${n.origin === "mcp" ? "Drafted" : "Written"} by ${who(n.origin)}${n.at ? ` on ${day(n.at)}` : ""}`;
  return n.reviewed_at ? `${wrote}; reviewed by ${who(n.reviewed_origin)} on ${day(n.reviewed_at)}.` : `${wrote}; not reviewed, so reports leave it out.`;
}

/** An agent trail in a line, or "" when no agent was involved. */
export function trailLine(t: Trail): string {
  if (!t.agent_involved) return "";
  const sent = `An agent sent ${t.requests_total} request${t.requests_total === 1 ? "" : "s"} for this finding`;
  return t.reviewed_by ? `${sent}; a person looked at it after (${t.reviewed_by}).` : `${sent}; no person has looked at it since.`;
}

/** Where a ticket is filed. */
export type Tracker = "github" | "jira";

/** What `findings ticket` writes (nothing is sent): Jira's payload has the body in a block Jira shows as it is. */
export interface Ticket {
  title: string;
  body: string;
  payload?: { fields?: { description?: string } };
}

/** The command that writes a finding up for a tracker. */
export function ticketCommand(id: number, tracker: Tracker): string[] {
  return ["findings", "ticket", String(id), "--to", tracker];
}

/** The text to paste: the title, then the body in the tracker's own markup (Markdown for
 * GitHub; for Jira the `{noformat}` description, since Jira's wiki markup would render links
 * and images a response quoted). */
export function ticketText(t: Ticket, tracker: Tracker): string {
  const body = tracker === "jira" ? (t.payload?.fields?.description ?? t.body) : t.body;
  return `${t.title}\n\n${body}`;
}

/** Why a filed ticket's link can't be recorded, as the CLI checks it; null when it can. */
export function ticketLinkProblem(url: string): string | null {
  const u = url.trim();
  if (!u) return "Give the ticket's link.";
  if (u.length > 2000 || /[\s\p{Cc}]/u.test(u)) return "Give the ticket's http(s) link.";
  try {
    const p = new URL(u);
    if (p.protocol !== "http:" && p.protocol !== "https:") return "Give the ticket's http(s) link.";
  } catch {
    return "Give the ticket's http(s) link.";
  }
  return null;
}

/** The command that keeps a filed ticket's link on the finding (its timeline and reports).
 * A person does this: MCP refuses it. */
export function recordTicketCommand(id: number, tracker: Tracker, url: string): string[] {
  return ["findings", "ticket", String(id), "--to", tracker, `--record=${url.trim()}`];
}

/** The command that writes a finding's repro pack (request with secrets masked, a curl command,
 * the response around the evidence, what the rule looks for, the command that checks it again). */
export function reproCommand(id: number, path: string, overwrite: boolean): string[] {
  return ["findings", "repro", String(id), "--output", path, ...(overwrite ? ["--force"] : [])];
}
