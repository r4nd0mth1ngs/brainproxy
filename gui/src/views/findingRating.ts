// A person's rating of scanner findings (`findings rate`): a risk and/or confidence in place of
// the scanner's, with a reason. The scanner's own rating is kept beside it and comes back when
// the rating is cleared. Kept apart from the Findings view so it can be tested without a window.

import type { FindingEvent, FindingItem, Rated, Risk } from "../api.ts";
import type { ActionDef } from "../ui/actions.ts";

export type Confidence = "high" | "medium" | "low";

export const RATE_RISKS: Risk[] = ["critical", "high", "medium", "low", "info"];
export const RATE_CONFIDENCES: Confidence[] = ["high", "medium", "low"];

/** Findings per `findings rate` call: each call is one change, all or none. */
export const RATE_BATCH = 500;

/** An issue rated as a whole (`rating` in `findings issue show`): its later findings take it. */
export interface IssueRating {
  /** Null: each finding keeps the one it was found with. */
  risk: Risk | null;
  confidence: string | null;
  reason: string | null;
  by?: string;
  origin: string;
  at: string | null;
}

/** Where a finding's rating is read from: `findings list --all`'s `rated`, or `findings show`'s columns. */
export interface RatedColumns {
  rated?: Rated | null;
  rated_origin?: string | null;
  rated_reason?: string | null;
  rated_at?: string | null;
  scanner_risk?: Risk | null;
  scanner_confidence?: string | null;
}

/** A finding's rating from either `findings list --all` (`rated`) or `findings show` (columns). */
export function ratingOf(f: RatedColumns): Rated | null {
  if (f.rated) return f.rated;
  if (!f.rated_origin) return null;
  return {
    scanner_risk: f.scanner_risk ?? null,
    scanner_confidence: f.scanner_confidence ?? null,
    reason: f.rated_reason ?? null,
    origin: f.rated_origin,
    at: f.rated_at ?? null,
  };
}

/** Whether a person can rate a finding: a scanner finding not removed. One added by hand has its own risk (Edit…). */
export function ratable(f: Pick<FindingItem, "source" | "state">): boolean {
  return f.source !== "manual" && f.state !== "removed";
}

/** The rating dialog's fields. "" leaves that part of each finding's rating as it is. */
export interface RateForm {
  risk: Risk | "";
  confidence: Confidence | "";
  reason: string;
  /** Rate the open finding's whole issue, and the findings it gets later (`--issue`). */
  wholeIssue: boolean;
  /** One finding: its rating when the form opened. Only the parts changed from it are sent. */
  start?: { risk: Risk; confidence: Confidence | "" };
}

/**
 * The form a rating starts from. One finding: its rating now (a person's, with their reason,
 * or the scanner's to change). Several: each part left as it is until one is picked.
 */
export function rateFormFor(findings: (Pick<FindingItem, "risk" | "confidence"> & RatedColumns)[]): RateForm {
  if (findings.length !== 1) return { risk: "", confidence: "", reason: "", wholeIssue: false };
  const f = findings[0];
  const confidence = RATE_CONFIDENCES.find((c) => c === f.confidence) ?? "";
  return { risk: f.risk, confidence, reason: ratingOf(f)?.reason ?? "", wholeIssue: false, start: { risk: f.risk, confidence } };
}

/**
 * The risk and confidence to send: only the parts changed from where one finding's form
 * started, so rating its whole issue's risk doesn't also give every finding of it this one's
 * confidence. With nothing changed (a new reason, or keeping the scanner's rating as the
 * person's), both.
 */
export function ratingParts(f: RateForm): { risk: Risk | ""; confidence: Confidence | "" } {
  const s = f.start;
  if (!s || (f.risk === s.risk && f.confidence === s.confidence)) return { risk: f.risk, confidence: f.confidence };
  return { risk: f.risk === s.risk ? "" : f.risk, confidence: f.confidence === s.confidence ? "" : f.confidence };
}

/** Why the form can't be sent yet, or null. */
export function rateProblem(f: RateForm): string | null {
  if (!f.risk && !f.confidence) return "Pick a risk, a confidence or both";
  if (!f.reason.trim()) return "Say why: reports print the reason beside the rating";
  return null;
}

/**
 * The calls that rate `ids` (or, with `issue`, that whole issue and the findings it gets later),
 * in batches. The reason goes as `--reason=` so one starting with "-" isn't read as a flag.
 */
export function rateCommands(ids: number[], f: RateForm, issue?: number | null): string[][] {
  const { risk, confidence } = ratingParts(f);
  const tail = [...(risk ? ["--risk", risk] : []), ...(confidence ? ["--confidence", confidence] : []), `--reason=${f.reason.trim()}`];
  if (issue != null) return [["findings", "rate", "--issue", String(issue), ...tail]];
  return batches(ids).map((b) => ["findings", "rate", ...b.map(String), ...tail]);
}

/** The calls that give `ids` (or, with `issue`, that whole issue, ending its rating) the scanner's rating back. */
export function clearCommands(ids: number[], issue?: number | null): string[][] {
  if (issue != null) return [["findings", "rate", "--issue", String(issue), "--clear"]];
  return batches(ids).map((b) => ["findings", "rate", ...b.map(String), "--clear"]);
}

function batches(ids: number[]): number[][] {
  const out: number[][] = [];
  for (let i = 0; i < ids.length; i += RATE_BATCH) out.push(ids.slice(i, i + RATE_BATCH));
  return out;
}

/** The findings of `picked` a person can rate (scanner findings) and how many were left out (added by hand). */
export function ratableOf<T extends Pick<FindingItem, "source" | "state">>(picked: T[]): { ids: T[]; skipped: number } {
  const ids = picked.filter(ratable);
  return { ids, skipped: picked.length - ids.length };
}

// Only a person rates (the CLI refuses an agent), so the origin says which of their tools.
const who = (origin: string | null | undefined) => (origin === "gui" ? "from the desktop app" : origin === "cli" ? "from the command line" : "");

/** "medium risk, high confidence", leaving out what isn't known. */
export function ratingWords(risk: string | null | undefined, confidence: string | null | undefined): string {
  return [risk && `${risk} risk`, confidence && `${confidence} confidence`].filter(Boolean).join(", ");
}

/** The detail's line under a rated finding: whose rating it is, why, and what the scanner said. */
export function ratedLine(r: Rated): string {
  const when = r.at ? ` on ${new Date(r.at).toLocaleString()}` : "";
  const by = who(r.origin);
  const scanner = ratingWords(r.scanner_risk, r.scanner_confidence);
  return `Rated by a person${by ? ` ${by}` : ""}${when}${r.reason ? `: ${r.reason}` : ""}.${scanner ? ` The scanner said ${scanner}.` : ""}`;
}

/** The list's tooltip on a rated finding's tag. */
export function ratedTitle(f: Pick<FindingItem, "risk" | "confidence">, r: Rated): string {
  const scanner = ratingWords(r.scanner_risk, r.scanner_confidence);
  return `Rated ${ratingWords(f.risk, f.confidence)} by a person${scanner ? `; the scanner said ${scanner}` : ""}${r.reason ? `. ${r.reason}` : ""}`;
}

/** The line under a finding whose issue is rated as a whole. */
export function issueRatingLine(issue: number, r: IssueRating): string {
  // A part left out of the issue's rating: each finding keeps its own.
  const what = ratingWords(r.risk, r.confidence);
  const by = who(r.origin);
  return `Issue #${issue} is rated ${what} as a whole${by ? ` ${by}` : ""}${r.reason ? `: ${r.reason}` : ""}. Findings it gets later take this rating.`;
}

/** The CLI's text on a `rated` event that gave the scanner's rating back. */
const SCANNER_AGAIN = "the scanner's rating again";

/** A `rated` timeline event in words (old and new are "risk/confidence"). */
export function ratedEventText(e: Pick<FindingEvent, "old" | "new" | "text">): string {
  const words = (s: string | null) => {
    const [risk, confidence] = (s ?? "").split("/");
    return ratingWords(risk, confidence);
  };
  const was = e.old ? ` (was ${words(e.old)})` : "";
  if (e.text === SCANNER_AGAIN) return `The scanner's rating again: ${words(e.new)}${was}`;
  return `Rated ${words(e.new)}${was}${e.text ? `: ${e.text}` : ""}`;
}

/** The toast once rating calls went through: how many changed, and how many already had it. */
export function ratedToast(changed: number, sent: number, cleared: boolean, skipped = 0): string {
  const n = (k: number) => `${k} finding${k === 1 ? "" : "s"}`;
  const head = cleared ? (changed ? `${n(changed)} ${changed === 1 ? "has" : "have"} the scanner's rating again.` : "No finding was rated: nothing changed.") : `Rated ${n(changed)}.`;
  const same = !cleared && sent > changed ? ` ${n(sent - changed)} already had this rating.` : "";
  const left = skipped ? ` ${n(skipped)} added by hand ${skipped === 1 ? "was left out: edit its" : "were left out: edit their"} risk instead.` : "";
  return head + same + left;
}

/** The rating key: opens the rating dialog for the open finding. */
export const RATE_FINDING: ActionDef = {
  id: "findings.rate",
  title: "Rate the finding's risk and confidence…",
  group: "Findings",
  keys: "Shift+R",
  where: "findings",
  keywords: "severity triage rating override",
};
