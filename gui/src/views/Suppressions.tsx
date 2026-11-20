// Findings › Suppress… and Suppression rules: a rule that an alert on a host (under a path, of a
// parameter) is a false positive wherever scans find it. The arguments and wording are in
// suppression.ts; the CLI does the matching and marking.

import { useEffect, useRef, useState } from "react";
import { run, type Finding } from "../api";
import { useDialogFocus } from "../ui/dialogFocus";
import { addedNote, draftFor, draftProblem, removedNote, ruleWhere, rulesSummary, SUPPRESS_LIST_ARGS, suppressAddArgs, suppressRemoveArgs, type SuppressDraft, type SuppressionList, type SuppressionRule } from "./suppression.ts";

/** A new rule, started from `finding`. `added` gets what to say once it is added. */
export function SuppressDialog({ finding, close, added }: { finding: Finding; close: () => void; added: (note: string) => void }) {
  const [draft, setDraft] = useState<SuppressDraft>(() => draftFor(finding));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const box = useRef<HTMLFormElement>(null);
  useDialogFocus(box);
  const problem = draftProblem(draft);
  const set = (k: keyof SuppressDraft) => (e: { target: { value: string } }) => {
    setDraft({ ...draft, [k]: e.target.value });
    setError("");
  };

  const add = async () => {
    if (problem || busy) return;
    setBusy(true);
    setError("");
    try {
      const r = await run<{ id: number; marked: number }>(suppressAddArgs(draft));
      // Whether the rule took the finding it was made from: one someone triaged stays theirs.
      const now = await run<Finding>(["findings", "show", String(finding.id)]).catch(() => null);
      added(addedNote(r.id, r.marked, now));
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };

  return (
    // Not closed while the rule is being added: it would be added unseen, and its answer would
    // land on whatever dialog was opened next.
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && close()}>
      <form
        ref={box}
        className="confirm-dialog suppress-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="suppress-title"
        aria-describedby="suppress-help"
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
      >
        <h2 id="suppress-title">Suppress “{finding.name}”</h2>
        <p id="suppress-help">
          Findings of this alert on this host, under the path and of the parameter given, become false positives: the open ones nobody triaged now,
          and each one a scan finds later. They are still kept, with the reason as their note. Findings someone triaged and findings added by hand are
          left alone.
        </p>
        <div className="form">
          <label>
            <span>Alert</span>
            <input className="input mono" value={draft.alert} spellCheck={false} onChange={set("alert")} title="An alert ref or rule id, e.g. 10020 or 10020-1" />
          </label>
          <label>
            <span>Host</span>
            <input className="input mono" value={draft.host} spellCheck={false} onChange={set("host")} title="A host name such as app.test, or with a port (127.0.0.1:3000) for that port only" />
          </label>
          <label className="wide">
            <span>Path prefix</span>
            <input className="input mono" value={draft.pathPrefix} spellCheck={false} placeholder="every path" onChange={set("pathPrefix")} />
            <span className="muted small">Findings whose URL path starts with this. Cut it back to a directory, such as /static/, to cover the files under it; leave it empty for every path.</span>
          </label>
          <label className="wide">
            <span>Parameter</span>
            <input className="input mono" value={draft.param} spellCheck={false} placeholder="any parameter" onChange={set("param")} />
          </label>
          <label className="wide">
            <span>Reason</span>
            <input className="input" value={draft.reason} autoFocus placeholder="Why these are false positives, e.g. static files are served by the CDN" onChange={set("reason")} />
          </label>
        </div>
        {draft.reason.trim() !== "" && problem && <p className="suppress-error">{problem}</p>}
        {error && (
          <p className="suppress-error" role="alert">
            {error}
          </p>
        )}
        <div className="row gap">
          <span className="grow" />
          <button type="button" className="btn" disabled={busy} onClick={close}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={busy || !!problem} title={problem ?? undefined}>
            {busy ? "Adding…" : "Add rule"}
          </button>
        </div>
      </form>
    </div>
  );
}

/**
 * The rules, each with what it holds and Remove (which can open its findings again), read when
 * it opens and after each removal, so it never shows a rule already gone or hides a failed read.
 * `names`: alert refs to their names, as the findings list has them. `changed` gets what to say
 * after a removal, so the findings and the toolbar's count are read again.
 */
export function SuppressionRules(p: { names: ReadonlyMap<string, string>; close: () => void; changed: (note: string) => void }) {
  // The rule asked about, and whether its findings open again.
  const [removing, setRemoving] = useState<{ id: number; reopen: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // null until the first read lands (or fails).
  const [list, setList] = useState<SuppressionRule[] | null>(null);
  const box = useRef<HTMLDivElement>(null);
  useDialogFocus(box);
  const rules = list ?? [];
  const live = useRef(true);
  const load = () =>
    run<SuppressionList>(SUPPRESS_LIST_ARGS).then(
      (l) => live.current && setList(l.suppressions),
      (e: any) => live.current && setError(`Couldn't read the rules: ${e.message}`),
    );
  useEffect(() => {
    live.current = true;
    load();
    return () => {
      live.current = false;
    };
  }, []);
  // The buttons of a removal go when it ends; focus stays in the dialog, so Esc and Tab still work.
  const stopRemoving = () => {
    setRemoving(null);
    box.current?.focus({ preventScroll: true });
  };

  const remove = async () => {
    if (!removing || busy) return;
    const { id, reopen } = removing;
    setBusy(true);
    setError("");
    try {
      const held = rules.find((x) => x.id === id)?.findings ?? 0;
      const r = await run<{ id: number; reopened: number }>(suppressRemoveArgs(id, reopen));
      // The rule leaves the list before Remove can be pressed for it again.
      setList((l) => l?.filter((x) => x.id !== id) ?? l);
      stopRemoving();
      p.changed(removedNote(id, r.reopened, reopen, held));
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="confirm-backdrop"
      onKeyDown={(e) => {
        if (e.key !== "Escape") return;
        // Esc steps back out of a removal before it closes the dialog.
        if (removing) stopRemoving();
        else p.close();
      }}
    >
      <div ref={box} className="confirm-dialog suppress-rules" role="dialog" aria-modal="true" aria-labelledby="suppress-rules-title" aria-describedby="suppress-rules-help">
        <h2 id="suppress-rules-title">Suppression rules</h2>
        <p id="suppress-rules-help">{list == null ? (error ? "" : "Reading the rules…") : rulesSummary(rules)}</p>
        {rules.length > 0 && (
          <ul className="suppress-list" aria-label="Suppression rules">
            {rules.map((r) => (
              <li key={r.id}>
                <div className="row gap">
                  <b className="grow ellipsis" title={`Rule ${r.id}: ${r.alert_ref}`}>
                    {p.names.get(r.alert_ref) ?? r.alert_ref} <span className="muted mono small">{r.alert_ref}</span>
                  </b>
                  <span className="muted small">
                    {r.findings} finding{r.findings === 1 ? "" : "s"}
                  </span>
                  {removing?.id !== r.id && (
                    <button className="btn small" disabled={busy} onClick={() => setRemoving({ id: r.id, reopen: false })} aria-label={`Remove rule ${r.id}`}>
                      Remove…
                    </button>
                  )}
                </div>
                <div className="mono small">{ruleWhere(r)}</div>
                <div className="small">{r.reason}</div>
                <div className="muted small">
                  Rule {r.id}, added {r.by} · {new Date(r.time).toLocaleString()}
                </div>
                {removing?.id === r.id && (
                  <div className="suppress-remove" role="group" aria-label={`Remove rule ${r.id}`}>
                    <span>Scans stop marking new findings by it.</span>
                    <label className="check">
                      <input type="checkbox" checked={removing.reopen} disabled={busy || r.findings === 0} onChange={(e) => setRemoving({ id: r.id, reopen: e.target.checked })} /> Also open its{" "}
                      {r.findings} finding{r.findings === 1 ? "" : "s"} again
                    </label>
                    <span className="grow" />
                    <button className="btn small" disabled={busy} onClick={stopRemoving} autoFocus>
                      Keep
                    </button>
                    <button className="btn small danger" disabled={busy} onClick={remove}>
                      Remove rule
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
        {error && (
          <p className="suppress-error" role="alert">
            {error}
          </p>
        )}
        <div className="row gap">
          <span className="grow" />
          <button className="btn" onClick={p.close}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
