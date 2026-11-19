// "Rate…": a person's risk and confidence for scanner findings (`findings rate`), in place of
// the scanner's, with a reason; or the scanner's rating back. Opened from Findings for the open
// finding (Shift+R) or the ones ticked in the list. Logic in findingRating.ts.

import { useRef, useState } from "react";
import { run, type FindingItem, type Risk } from "../api";
import { useDialogFocus } from "../ui/dialogFocus";
import { Choice } from "./NewFinding";
import { clearCommands, type Confidence, RATE_CONFIDENCES, RATE_RISKS, rateCommands, ratedLine, ratedToast, rateFormFor, rateProblem, ratingOf, type RatedColumns } from "./findingRating.ts";

export function RateFindings({
  findings,
  skipped,
  issue,
  onClose,
  onDone,
}: {
  /** Scanner findings only (ratable). */
  findings: (FindingItem & RatedColumns)[];
  /** Ticked findings left out because they were added by hand. */
  skipped: number;
  /** The one finding's issue, which can be rated as a whole. */
  issue: number | null;
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

  // Every batch, in turn; a failed one stops there, and what went through is still said.
  const send = async (cmds: string[][], sent: number, cleared: boolean) => {
    setBusy(true);
    let changed = 0;
    try {
      for (const cmd of cmds) changed += (await run<{ ids: number[] }>(cmd)).ids.length;
      onDone(ratedToast(changed, sent, cleared, skipped));
    } catch (e: any) {
      if (changed) onDone(ratedToast(changed, sent, cleared, skipped), e.message);
      else {
        setError(e.message);
        setBusy(false);
      }
    }
  };
  const rate = () => {
    if (problem) return setError(problem);
    const whole = form.wholeIssue && issue != null ? issue : null;
    send(rateCommands(ids, form, whole), whole != null ? 0 : ids.length, false);
  };
  const clear = () => send(clearCommands(rated), rated.length, true);

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
        <div className="form">
          <Choice<Risk | "">
            label="Risk"
            value={form.risk}
            options={one ? RATE_RISKS : ["", ...RATE_RISKS]}
            onPick={(risk) => setForm((f) => ({ ...f, risk }))}
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
            options={one && form.start?.confidence ? RATE_CONFIDENCES : ["", ...RATE_CONFIDENCES]}
            onPick={(confidence) => setForm((f) => ({ ...f, confidence }))}
            render={keep}
          />
          <label className="wide">
            <span className="label">Reason</span>
            <textarea
              className="input area"
              autoFocus
              value={form.reason}
              placeholder="Why: only reachable from the internal network, the cookie holds no session, ... Reports print it beside the rating."
              onChange={(e) => {
                setForm((f) => ({ ...f, reason: e.target.value }));
                setError(null);
              }}
            />
          </label>
        </div>
        {one && issue != null && (
          <label className="check">
            <input type="checkbox" checked={form.wholeIssue} onChange={(e) => setForm((f) => ({ ...f, wholeIssue: e.target.checked }))} /> Rate the whole issue #{issue}: every
            scanner finding of it, and those a later scan finds
          </label>
        )}
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <div className="row gap finding-dialog-actions">
          {rated.length > 0 && (
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
