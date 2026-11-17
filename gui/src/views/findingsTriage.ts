// Triage from the keyboard in the Findings view: moving through the findings the list shows
// and marking the open one. Kept apart from the view so it can be tested without a window.

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
