// "Rate…": a person's risk and confidence for scanner findings (`findings rate`), in place of
// the scanner's, with a reason; or the scanner's rating back. Opened from Findings for the open
// finding (Shift+R) or the ones ticked in the list. Logic in findingRating.ts.

import { useRef, useState } from "react";
import { run, type FindingItem, type Risk } from "../api";
import { useDialogFocus } from "../ui/dialogFocus";
import { Choice } from "./NewFinding";
import {
  clearCommands,
  type Confidence,
  type IssueRating,
  issueRatingLine,
  RATE_CONFIDENCES,
  RATE_RISKS,
  rateCommands,
  ratedLine,
  ratedToast,
  rateFormFor,
  rateProblem,
  ratingOf,
  type RatedColumns,
  runRating,
  withWholeIssue,
} from "./findingRating.ts";

export function RateFindings({
  findings,
  skipped,
  issue,
  issueRating,
  onClose,
  onDone,
}: {
  /** Scanner findings only (ratable). */
  findings: (FindingItem & RatedColumns)[];
  /** Ticked findings left out because they were added by hand. */
  skipped: number;
  /** The one finding's issue, which can be rated as a whole. */
  issue: number | null;
  /** That issue's rating as a whole, if it has one: what ticking "the whole issue" starts from. */
  issueRating: IssueRating | null;
  onClose: () => void;
  /** Once calls went through (some, when one failed): the toast to show. */
  onDone: (toast: string, failed?: string) => void;
}) {
  const one = findings.length === 1 ? findings[0] : null;
  const [form, setForm] = useState(() => rateFormFor(findings));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  useDialogFocus(dialog);
  const ids = findings.map((f) => f.id);
  const rated = findings.filter((f) => ratingOf(f)).map((f) => f.id);
  const problem = rateProblem(form);
  const oneRating = one ? ratingOf(one) : null;

  const whole = form.wholeIssue && issue != null ? issue : null;
  const pick = (p: Partial<typeof form>) => {
    setForm((f) => ({ ...f, ...p }));
    setError(null);
  };

  // Every batch, in turn; a failed one stops there, and what went through is still said.
  const send = async (cmds: string[][], cleared: boolean) => {
    setBusy(true);
    const r = await runRating(cmds, (args) => run<{ ids: number[] }>(args));
    if (r.error && !r.done) {
      setError(r.error);
      setBusy(false);
      return;
    }
    onDone(ratedToast(r.changed, r.sent, cleared, skipped, cleared ? null : whole), r.error ?? undefined);
  };
  const rate = () => {
    if (problem) return setError(problem);
    send(rateCommands(ids, form, whole), false);
  };
  const clear = () => send(clearCommands(rated), true);

  const keep = (v: string) => (v === "" ? <span className="muted">as it is</span> : v);
  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && onClose()}>
      <div ref={dialog} className="confirm-dialog finding-dialog" role="dialog" aria-modal="true" aria-labelledby="rate-title">
        <h2 id="rate-title">{one ? `Rate finding #${one.id}` : `Rate ${findings.length} findings`}</h2>
        <p>
          Your rating takes the scanner's place in the list, filters, reports and gates, and a later scan doesn't change it. The scanner's own rating is kept beside it and
          comes back if you clear yours.
          {skipped > 0 && ` ${skipped} ticked finding${skipped === 1 ? " was" : "s were"} added by hand and keep${skipped === 1 ? "s" : ""} its own risk (Edit…).`}
        </p>
        {oneRating && <p className="muted">{ratedLine(oneRating)}</p>}
        {form.wholeIssue && issue != null && (
          <p className="muted">
            {issueRating ? issueRatingLine(issue, issueRating) : `Issue #${issue} isn't rated as a whole yet.`} The rating you pick here becomes the issue's: a part left as
            it is stays each finding's own.
          </p>
        )}
        <div className="form">
          <Choice<Risk | "">
            label="Risk"
            value={form.risk}
            options={one && !form.wholeIssue ? RATE_RISKS : ["", ...RATE_RISKS]}
            onPick={(risk) => pick({ risk })}
            render={(r) =>
              r === "" ? (
                keep(r)
              ) : (
                <>
                  <span className={`dot-risk risk-${r}`} /> {r}
                </>
              )
            }
          />
          <Choice<Confidence | "">
            label="Confidence"
            value={form.confidence}
            options={one && !form.wholeIssue && form.start?.confidence ? RATE_CONFIDENCES : ["", ...RATE_CONFIDENCES]}
            onPick={(confidence) => pick({ confidence })}
            render={keep}
          />
          <label className="wide">
            <span className="label">Reason</span>
            <textarea
              className="input area"
              autoFocus
              value={form.reason}
              placeholder="Why: only reachable from the internal network, the cookie holds no session, ... Reports print it beside the rating."
              onChange={(e) => pick({ reason: e.target.value })}
            />
          </label>
        </div>
        {one && issue != null && (
          <label className="check">
            <input
              type="checkbox"
              checked={form.wholeIssue}
              onChange={(e) => {
                setForm((f) => withWholeIssue(f, e.target.checked, issueRating));
                setError(null);
              }}
            /> Rate the whole issue #{issue}: every
            scanner finding of it, and those a later scan finds
          </label>
        )}
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <div className="row gap finding-dialog-actions">
          {/* Clearing goes by finding; an issue's own rating is ended from the detail (End it). */}
          {rated.length > 0 && !form.wholeIssue && (
            <button className="btn" disabled={busy} onClick={clear} title="Clear the person's rating: the risk and confidence the scanner gives now come back">
              {one ? "Clear the rating" : `Clear ${rated.length} rating${rated.length === 1 ? "" : "s"}`}
            </button>
          )}
          <div className="toolbar-end">
            <button className="btn" disabled={busy} onClick={onClose}>
              Cancel
            </button>
            <button className="btn primary" disabled={busy || !!problem} title={problem ?? undefined} onClick={rate}>
              {busy ? "Saving…" : "Rate"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
