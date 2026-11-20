// Findings › an issue's CVSS rating, merging issues and splitting findings off into a new one.
// The commands and checks are in cvss.ts and issueTools.ts; these are the dialogs around them.

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { run, type FindingItem } from "../api";
import { useDialogFocus } from "../ui/dialogFocus";
import { BASE_PICKER, cvssCommand, extraMetrics, metricsOf, saveProblem, START_VECTOR, vectorProblem, withMetric } from "./cvss.ts";
import { STATES } from "./findingsFilter";
import { filterIssues, type IssueInfo, issueLabel, mergeCommands, mergeWarning, splitCommand, splitProblem, splitStart, staleSplit } from "./issueTools.ts";

/** The frame the three dialogs share: modal, Tab kept inside, Esc closes unless a command is running. */
function IssueDialog({ title, busy, onClose, className, children }: { title: string; busy: boolean; onClose: () => void; className?: string; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useDialogFocus(ref);
  const id = useId();
  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && onClose()}>
      <div ref={ref} className={`confirm-dialog issue-dialog ${className ?? ""}`} role="dialog" aria-modal="true" aria-labelledby={id}>
        <h2 id={id}>{title}</h2>
        {children}
      </div>
    </div>
  );
}

function Actions({ error, children }: { error: string; children: ReactNode }) {
  return (
    <>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      <div className="row gap issue-dialog-actions">
        <span className="grow" />
        {children}
      </div>
    </>
  );
}

/** Runs a dialog's work: busy while it runs, its error shown in the dialog. */
function useCommand() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const go = async <T,>(work: () => Promise<T>, done: (data: T) => void) => {
    setBusy(true);
    setError("");
    try {
      done(await work());
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };
  return { busy, error, go };
}

export type Cvss = IssueInfo["cvss"];

/** An issue's CVSS 4.0 vector: typed, or picked metric by metric; the CLI scores it when saved. */
export function CvssDialog({ issue, onClose, onSaved }: { issue: IssueInfo; onClose: () => void; onSaved: (cvss: Cvss) => void }) {
  const [text, setText] = useState(issue.cvss?.vector ?? START_VECTOR);
  const { busy, error, go } = useCommand();
  const problem = vectorProblem(text);
  const blocked = saveProblem(text, issue.cvss != null);
  const picked = metricsOf(text);
  const extra = extraMetrics(text);
  const save = (vector: string) => go(() => run<{ cvss: Cvss }>(cvssCommand(issue.id, vector)), (r) => onSaved(r.cvss));
  return (
    <IssueDialog title={`CVSS 4.0 rating · issue #${issue.id}`} busy={busy} onClose={onClose} className="cvss-dialog">
      <p>
        {issue.title}.{" "}
        {issue.cvss ? (
          <>
            Rated <strong>{issue.cvss.score.toFixed(1)}</strong> ({issue.cvss.severity}) now.
          </>
        ) : (
          "Not rated yet."
        )}{" "}
        Reports show the score, its severity and the vector; SARIF's security-severity is the score. Brainproxy scores the vector when you save it.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!blocked && !busy) save(text);
        }}
      >
        <label className="cvss-vector">
          <span className="label">Vector</span>
          <input
            className="input mono"
            autoFocus
            spellCheck={false}
            value={text}
            aria-invalid={problem ? true : undefined}
            aria-describedby={problem ? "cvss-problem" : undefined}
            onChange={(e) => setText(e.target.value)}
          />
        </label>
        {problem && (
          <p id="cvss-problem" className="warn-text cvss-problem">
            {problem}
          </p>
        )}
        <div className="cvss-picker">
          {BASE_PICKER.map((p) => (
            <MetricRow key={p.metric} name={p.name} metric={p.metric} values={p.values} value={picked.get(p.metric)} onPick={(v) => setText(withMetric(text, p.metric, v))} />
          ))}
        </div>
        {extra.length > 0 && <p className="muted cvss-extra">Also set, and kept as typed: {extra.join(" ")}</p>}
        {!problem && blocked && <p className="muted cvss-extra">{blocked}.</p>}
        <Actions error={error}>
          {issue.cvss && (
            <button type="button" className="btn" disabled={busy} onClick={() => save("")} title="Take the rating off this issue">
              Remove rating
            </button>
          )}
          <button type="button" className="btn" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={busy || !!blocked} title={blocked || undefined}>
            {busy ? "Saving…" : "Save"}
          </button>
        </Actions>
      </form>
    </IssueDialog>
  );
}

function MetricRow({ name, metric, values, value, onPick }: { name: string; metric: string; values: readonly [string, string][]; value?: string; onPick: (v: string) => void }) {
  const id = useId();
  return (
    <>
      <span className="label" id={id} title={metric}>
        {name}
      </span>
      <div className="seg" role="group" aria-labelledby={id}>
        {values.map(([v, words]) => (
          <button key={v} type="button" aria-pressed={value === v} className={value === v ? "on" : ""} title={`${metric}:${v}`} onClick={() => onPick(v)}>
            {words}
          </button>
        ))}
      </div>
    </>
  );
}

/**
 * Moves every finding of the `from` issues into one picked from `targets`. From an issue's menu
 * `from` is that issue and `targets` the others; from ticked findings both are their issues.
 */
export function MergeDialog({
  from,
  targets,
  onClose,
  onMerged,
  onPartial,
}: {
  from: IssueInfo[];
  targets: IssueInfo[];
  onClose: () => void;
  onMerged: (into: number, moved: number) => void;
  /** A later batch failed after earlier ones went through: the list should show what moved. */
  onPartial?: () => void;
}) {
  const [into, setInto] = useState<number | null>(from.length > 1 ? from[0].id : null);
  const [filter, setFilter] = useState("");
  const { busy, error, go } = useCommand();
  const keep = targets.find((i) => i.id === into);
  const cmds = into == null ? [] : mergeCommands(into, from.map((i) => i.id));
  const total = cmds.reduce((n, c) => n + c.length - 4, 0);
  // Batch after batch; one that fails stops there, and what moved before it stays moved, so the
  // error says how many issues were merged and the list is read again to show them.
  const merge = () =>
    go(async () => {
      let moved = 0;
      let merged = 0;
      for (const cmd of cmds) {
        try {
          moved += (await run<{ moved: number }>(cmd)).moved;
        } catch (e: any) {
          if (!merged) throw e;
          onPartial?.();
          throw new Error(`${merged} of ${total} issues were merged into #${into} before this; the rest weren't: ${e.message}`);
        }
        // The command is `findings issue merge INTO FROM...`.
        merged += cmd.length - 4;
      }
      return moved;
    }, (moved) => into != null && onMerged(into, moved));
  const warning = mergeWarning(keep, from);
  const shown = filterIssues(targets, filter);
  const one = from.length === 1;
  return (
    <IssueDialog title={one ? `Merge issue #${from[0].id} into…` : `Merge ${from.length} issues`} busy={busy} onClose={onClose} className="merge-dialog">
      <p>
        {one ? `Every finding of “${from[0].title}” moves into the issue you pick: one bug seen in several places.` : "Pick the issue to keep: every finding of the others moves into it, not only the ticked ones."}{" "}
        The emptied issues keep their write-ups but leave the findings and reports.
      </p>
      {targets.length > 8 && (
        <input className="input merge-filter" autoFocus placeholder="Filter: title, alert, host, #id" aria-label="Filter issues" value={filter} onChange={(e) => setFilter(e.target.value)} />
      )}
      <div className="issue-pick" role="radiogroup" aria-label={one ? "Issue to merge into" : "Issue to keep"}>
        {shown.length === 0 && <div className="muted">{targets.length ? "No issue matches." : "There is no other issue to merge into."}</div>}
        {shown.map((i) => (
          <label key={i.id} className="check">
            <input type="radio" name="merge-into" checked={into === i.id} onChange={() => setInto(i.id)} />
            <span className={`dot-risk risk-${i.risk}`} />
            <span className="ellipsis">{issueLabel(i)}</span>
            <span className="muted">{i.instances}</span>
          </label>
        ))}
      </div>
      {warning && <p className="warn-text">{warning}</p>}
      <Actions error={error}>
        <button type="button" className="btn" disabled={busy} onClick={onClose}>
          Cancel
        </button>
        {/* The issue picked may be filtered out of the list; the button names it. */}
        <button type="button" className="btn primary" disabled={busy || !cmds.length} onClick={merge}>
          {busy ? "Merging…" : into != null && cmds.length ? `Merge into #${into}` : "Merge"}
        </button>
      </Actions>
    </IssueDialog>
  );
}

/** Moves the findings picked here out of `issue` into a new issue (two bugs that share a rule and host). */
export function SplitDialog({ issue, checked, onClose, onSplit }: { issue: IssueInfo; checked: ReadonlySet<number>; onClose: () => void; onSplit: (issue: number, moved: number[]) => void }) {
  // Every finding of the issue, not only those the list's filters show.
  const [findings, setFindings] = useState<FindingItem[] | null>(null);
  const [picked, setPicked] = useState(new Set<number>());
  const [title, setTitle] = useState("");
  const { busy, error, go } = useCommand();
  const [loadError, setLoadError] = useState("");
  const read = () => run<{ findings: FindingItem[] }>(["findings", "issue", "show", String(issue.id)]);
  useEffect(() => {
    let live = true;
    read().then(
      (i) => {
        if (!live) return;
        setFindings(i.findings);
        setPicked(splitStart(i.findings.map((f) => f.id), checked));
      },
      (e) => live && setLoadError(e.message),
    );
    return () => {
      live = false;
    };
    // The ticked findings are read once, as the dialog opens.
  }, [issue.id]);
  const ids = (findings ?? []).filter((f) => picked.has(f.id)).map((f) => f.id);
  const problem = findings ? splitProblem(ids.length, findings.length) : "";
  // The issue as it is now: findings moved elsewhere meanwhile would be split out of that issue.
  // ponytail: a move between this read and the split still slips through; closing that needs
  // `findings issue split` to take the issue the findings come from and check it in its transaction.
  const split = () =>
    go(async () => {
      const now = (await read()).findings;
      const stale = staleSplit(issue.id, ids, now);
      if (stale) {
        setFindings(now);
        setPicked((p) => new Set([...p].filter((id) => now.some((f) => f.id === id))));
        throw new Error(stale);
      }
      return (await run<{ issue: number }>(splitCommand(ids, title))).issue;
    }, (created) => onSplit(created, ids));
  const toggle = (id: number) =>
    setPicked((p) => {
      const s = new Set(p);
      s.has(id) ? s.delete(id) : s.add(id);
      return s;
    });
  return (
    <IssueDialog title={`Split issue #${issue.id}`} busy={busy} onClose={onClose} className="split-dialog">
      <p>The findings you tick move out of “{issue.title}” into a new issue: two bugs that share a rule and host. The new issue starts with no write-up or rating.</p>
      <div className="issue-pick" role="group" aria-label="Findings that move">
        {!findings && !loadError && <div className="muted">Reading the issue…</div>}
        {(findings ?? []).map((f) => (
          <label key={f.id} className="check">
            <input type="checkbox" checked={picked.has(f.id)} onChange={() => toggle(f.id)} />
            <span className="muted">#{f.id}</span>
            <span className="ellipsis mono">
              {f.method} {f.url}
              {f.param && <span className="muted"> [{f.param}]</span>}
            </span>
            {f.state !== "open" && <span className="tag">{STATES.find((s) => s.id === f.state)?.label ?? f.state}</span>}
          </label>
        ))}
      </div>
      <label className="split-title">
        <span className="label">New issue's title</span>
        <input className="input" value={title} placeholder="Left empty: the alert's name" onChange={(e) => setTitle(e.target.value)} />
      </label>
      {findings && problem && <p className="muted">{problem}</p>}
      <Actions error={loadError || error}>
        <button type="button" className="btn" disabled={busy} onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="btn primary" disabled={busy || !findings || !!problem} onClick={split}>
          {busy ? "Splitting…" : ids.length ? `Move ${ids.length} to a new issue` : "Move to a new issue"}
        </button>
      </Actions>
    </IssueDialog>
  );
}
