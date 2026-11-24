// Triage from the keyboard in the Findings view: moving through the findings the list shows
// and marking the open one. Kept apart from the view so it can be tested without a window.

import type { FindingEvent } from "../api.ts";
import type { ActionDef } from "../ui/actions.ts";

/**
 * The finding `dir` steps to from `current` in `order` (the findings the list shows, top to
 * bottom): the first (or, going back, the last) when none of them is open; the same one at
 * either end; null when the list is empty.
 */
export function stepFinding(order: number[], current: number | null, dir: 1 | -1): number | null {
  if (!order.length) return null;
  const at = current == null ? -1 : order.indexOf(current);
  if (at < 0) return dir === 1 ? order[0] : order[order.length - 1];
  return order[Math.min(Math.max(at + dir, 0), order.length - 1)];
}

/**
 * Where triage goes once `current` is marked: the next finding in `order`, else the previous
 * one (it was the last), else null. Worked out before the mark, while `order` still holds the
 * marked finding: "Hide closed" may drop it from the list after.
 */
export function afterMark(order: number[], current: number): number | null {
  const at = order.indexOf(current);
  if (at < 0) return order[0] ?? null;
  return order[at + 1] ?? order[at - 1] ?? null;
}

/** A triage key: the state it marks the open finding with. */
export interface TriageKey extends ActionDef {
  state: string;
}

/** Marking keys, with letters that type nothing outside a text field. */
export const TRIAGE_KEYS: TriageKey[] = [
  { id: "findings.markConfirmed", state: "confirmed", title: "Mark the finding confirmed, then open the next", group: "Findings", keys: "C", where: "findings" },
  { id: "findings.markFalsePositive", state: "false_positive", title: "Mark the finding a false positive, then open the next", group: "Findings", keys: "F", where: "findings" },
  { id: "findings.markAccepted", state: "accepted_risk", title: "Mark the finding an accepted risk, then open the next", group: "Findings", keys: "A", where: "findings" },
  { id: "findings.markFixed", state: "fixed", title: "Mark the finding fixed, then open the next", group: "Findings", keys: "Shift+F", where: "findings" },
  { id: "findings.markRetest", state: "retest_pending", title: "Mark the finding retest pending, then open the next", group: "Findings", keys: "R", where: "findings" },
  { id: "findings.markOpen", state: "open", title: "Mark the finding open again, then open the next", group: "Findings", keys: "O", where: "findings" },
];

/** Moving keys. */
export const NEXT_FINDING: ActionDef = { id: "findings.next", title: "Next finding", group: "Findings", keys: "J", where: "findings", keywords: "down triage" };
export const PREVIOUS_FINDING: ActionDef = { id: "findings.previous", title: "Previous finding", group: "Findings", keys: "K", where: "findings", keywords: "up triage" };

// Unsaved text (a note per finding, a write-up per issue), kept while other findings are
// opened, so clicking away mid-sentence loses nothing. A draft equal to the saved text is no draft.

/** The text the box shows: the draft, else the saved text. */
export function draftOf(drafts: ReadonlyMap<number, string>, key: number, saved: string): string {
  return drafts.get(key) ?? saved;
}

/** The drafts after typing `text` for `key`. */
export function withDraft(drafts: ReadonlyMap<number, string>, key: number, text: string, saved: string): Map<number, string> {
  const next = new Map(drafts);
  if (text === saved) next.delete(key);
  else next.set(key, text);
  return next;
}

/** The drafts once `sent` was saved for `key`: dropped, unless typed on since. */
export function dropDraft(drafts: ReadonlyMap<number, string>, key: number, sent: string): ReadonlyMap<number, string> {
  if (drafts.get(key) !== sent) return drafts;
  const next = new Map(drafts);
  next.delete(key);
  return next;
}

// An agent's suggestions (`findings mark --suggest`, timeline kind `suggested`): proposals for a
// person to accept or dismiss. A suggestion is settled once the finding's state or note changed
// after it (someone decided), or a person dismissed it (`findings dismiss`, kind `dismissed`,
// whose old is the suggestion's event id).

/** The suggestions still waiting on the finding, oldest first. */
export function pendingSuggestions(events: FindingEvent[]): FindingEvent[] {
  const dismissed = new Set(events.filter((e) => e.kind === "dismissed").map((e) => e.old));
  return events.filter((e) => e.kind === "suggested" && !dismissed.has(String(e.id)) && !events.some((l) => l.id > e.id && (l.kind === "state" || l.kind === "note")));
}

/** `findings dismiss`: the suggestion stops waiting, for everyone who opens the project. */
export const dismissArgs = (finding: number, event: number) => ["findings", "dismiss", String(finding), "--event", String(event)];

/**
 * The command that applies a suggestion as the person's own decision: its state and note, only
 * while the finding is still in `shown` (the state on screen), so a change made meanwhile isn't
 * overwritten (kind conflict).
 */
export function acceptCommand(id: number, s: FindingEvent, shown: string): string[] | null {
  if (!s.new && !s.text) return null;
  return ["findings", "mark", String(id), ...(s.new ? ["--state", s.new] : []), ...(s.text ? [`--note=${s.text}`] : []), "--if-state", shown];
}

/** Where an older build remembered the suggestions dismissed in a project (its window's storage). */
export const dismissedKey = (project: string) => `findings.dismissedSuggestions:${project}`;

/** The dismissed suggestions' event ids, from what was stored; anything else reads as none. */
export function parseDismissed(text: string | null): Set<number> {
  try {
    const v: unknown = text ? JSON.parse(text) : [];
    return new Set(Array.isArray(v) ? v.filter((n): n is number => Number.isSafeInteger(n)) : []);
  } catch {
    return new Set();
  }
}

/**
 * The suggestions among `ids` (event ids) still waiting, with their finding: what the move from
 * this window's storage dismisses in the project. Settled ones (decided or dismissed since) are
 * left out. `json_each` takes the ids as one JSON parameter.
 */
export const PENDING_SQL = `SELECT s.finding_id, s.id FROM finding_events s
  WHERE s.kind = 'suggested' AND s.id IN (SELECT value FROM json_each(?1))
    AND NOT EXISTS (SELECT 1 FROM finding_events l WHERE l.finding_id = s.finding_id AND l.id > s.id AND l.kind IN ('state', 'note'))
    AND NOT EXISTS (SELECT 1 FROM finding_events d WHERE d.finding_id = s.finding_id AND d.kind = 'dismissed' AND d.old = CAST(s.id AS TEXT))
  ORDER BY s.id`;

/** The CLI, as the move needs it. */
export type Cli = <T>(args: string[]) => Promise<T>;

/**
 * Moves the suggestions an older build dismissed in this window (`stored`, its localStorage
 * text) into the project: each still waiting gets `findings dismiss`. Resolves to true when all
 * went through (or there was nothing to move), so the stored ids can go; false leaves them for
 * the next time. Dismissing one again records nothing, so a retry is safe.
 */
export async function moveDismissed(cli: Cli, stored: string | null): Promise<boolean> {
  const ids = [...parseDismissed(stored)];
  if (!ids.length) return true;
  try {
    const d = await cli<{ rows: [number, number][] }>(["query", PENDING_SQL, "-p", JSON.stringify(ids), "--limit", String(ids.length)]);
    for (const [finding, event] of d.rows) await cli(dismissArgs(finding, event));
    return true;
  } catch {
    return false;
  }
}
