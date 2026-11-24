// Findings › Re-rate future findings… and Alert filters: a filter that gives an alert (on a host
// or any, under a path, of a parameter, by URL or parameter regex) a risk and/or confidence
// wherever scans find it. The arguments and wording are in alertFilter.ts; the CLI does the
// matching and rating.

import { useEffect, useRef, useState } from "react";
import { run, type Finding } from "../api";
import { useDialogFocus } from "../ui/dialogFocus";
import {
  FILTER_LIST_ARGS,
  filterAddArgs,
  filterAddedNote,
  filterDraftFor,
  filterDraftProblem,
  filterRating,
  filterRemoveArgs,
  filterRemovedNote,
  filtersSummary,
  filterWhere,
  type AlertFilterList,
  type AlertFilterRow,
  type FilterDraft,
} from "./alertFilter.ts";
import { RATE_CONFIDENCES, RATE_RISKS } from "./findingRating.ts";

/** A new filter, started from `finding`. `added` gets what to say once it is added. */
export function FilterDialog({ finding, close, added }: { finding: Finding; close: () => void; added: (note: string) => void }) {
  const [draft, setDraft] = useState<FilterDraft>(() => filterDraftFor(finding));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const box = useRef<HTMLFormElement>(null);
  useDialogFocus(box);
  const problem = filterDraftProblem(draft);
  const set = (k: keyof FilterDraft) => (e: { target: { value: string } }) => {
    setDraft({ ...draft, [k]: e.target.value });
    setError("");
  };

  const add = async () => {
    if (problem || busy) return;
    setBusy(true);
    setError("");
    try {
      const r = await run<{ id: number; rated: number }>(filterAddArgs(draft));
      // Whether the filter rated the finding it was made from: one someone rated stays theirs.
      const now = await run<Finding>(["findings", "show", String(finding.id)]).catch(() => null);
      added(filterAddedNote(r.id, r.rated, now));
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };

  return (
    // Not closed while the filter is being added: it would be added unseen.
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && close()}>
      <form
        ref={box}
        className="confirm-dialog suppress-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="filter-title"
        aria-describedby="filter-help"
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
      >
        <h2 id="filter-title">Re-rate “{finding.name}”</h2>
        <p id="filter-help">
          Findings of this alert that match get the risk and/or confidence you pick, in place of the scanner's: the open ones nobody rated now, and each
          one a scan finds later. The scanner's rating is kept beside it. Findings someone rated and findings added by hand are left alone. To make them
          false positives, use Suppress… instead.
        </p>
        <div className="form">
          <label>
            <span>Alert</span>
            <input className="input mono" value={draft.alert} spellCheck={false} onChange={set("alert")} title="An alert ref or rule id, e.g. 10020 or 10020-1" />
          </label>
          <label>
            <span>Host</span>
            <input className="input mono" value={draft.host} spellCheck={false} placeholder="any host" onChange={set("host")} title="A host name such as app.test, with a port (127.0.0.1:3000) for that port only, or empty for any host" />
          </label>
          <label className="wide">
            <span>Path prefix</span>
            <input className="input mono" value={draft.pathPrefix} spellCheck={false} placeholder="every path" onChange={set("pathPrefix")} />
            <span className="muted small">Findings whose URL path starts with this. Cut it back to a directory, such as /static/, to cover the files under it.</span>
          </label>
          <label className="wide">
            <span>URL regex</span>
            <input className="input mono" value={draft.urlRegex} spellCheck={false} placeholder="any URL" onChange={set("urlRegex")} />
            <span className="muted small">Findings whose URL, query included, this regex finds a match in, such as \.js$ or [?&amp;]debug=.</span>
          </label>
          <label>
            <span>Parameter</span>
            <input className="input mono" value={draft.param} spellCheck={false} placeholder="any parameter" onChange={set("param")} />
          </label>
          <label>
            <span>Parameter regex</span>
            <input className="input mono" value={draft.paramRegex} spellCheck={false} placeholder="any parameter" onChange={set("paramRegex")} />
          </label>
          <label>
            <span>Risk</span>
            <select className="input" value={draft.risk} onChange={set("risk")}>
              <option value="">as the scanner says</option>
              {RATE_RISKS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Confidence</span>
            <select className="input" value={draft.confidence} onChange={set("confidence")}>
              <option value="">as the scanner says</option>
              {RATE_CONFIDENCES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </label>
          <label className="wide">
            <span>Reason</span>
            <input className="input" value={draft.reason} autoFocus placeholder="Why, e.g. only reachable from the internal network" onChange={set("reason")} />
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
            {busy ? "Adding…" : "Add filter"}
          </button>
        </div>
      </form>
    </div>
  );
}

/**
 * The filters, each with what it matches, what it gives, the findings it holds and Remove
 * (which can give them the scanner's rating back), read when it opens and after each removal.
 * `names`: alert refs to their names, as the findings list has them. `changed` gets what to say
 * after a removal, so the findings are read again.
 */
export function AlertFilters(p: { names: ReadonlyMap<string, string>; close: () => void; changed: (note: string) => void }) {
  const [removing, setRemoving] = useState<{ id: number; unrate: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // null until the first read lands (or fails).
  const [list, setList] = useState<AlertFilterRow[] | null>(null);
  const box = useRef<HTMLDivElement>(null);
  useDialogFocus(box);
  const filters = list ?? [];
  const live = useRef(true);
  const load = () =>
    run<AlertFilterList>(FILTER_LIST_ARGS).then(
      (l) => live.current && setList(l.filters),
      (e: any) => live.current && setError(`Couldn't read the filters: ${e.message}`),
    );
  useEffect(() => {
    live.current = true;
    load();
    return () => {
      live.current = false;
    };
  }, []);
  const stopRemoving = () => {
    setRemoving(null);
    box.current?.focus({ preventScroll: true });
  };

  const remove = async () => {
    if (!removing || busy) return;
    const { id, unrate } = removing;
    setBusy(true);
    setError("");
    try {
      const held = filters.find((x) => x.id === id)?.holds ?? 0;
      const r = await run<{ id: number; unrated: number }>(filterRemoveArgs(id, unrate));
      setList((l) => l?.filter((x) => x.id !== id) ?? l);
      stopRemoving();
      p.changed(filterRemovedNote(id, r.unrated, unrate, held));
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
      <div ref={box} className="confirm-dialog suppress-rules" role="dialog" aria-modal="true" aria-labelledby="filters-title" aria-describedby="filters-help">
        <h2 id="filters-title">Alert filters</h2>
        <p id="filters-help">{list == null ? (error ? "" : "Reading the filters…") : filtersSummary(filters)}</p>
        {filters.length > 0 && (
          <ul className="suppress-list" aria-label="Alert filters">
            {filters.map((f) => (
              <li key={f.id}>
                <div className="row gap">
                  <b className="grow ellipsis" title={`Filter ${f.id}: ${f.alert_ref}`}>
                    {p.names.get(f.alert_ref) ?? f.alert_ref} <span className="muted mono small">{f.alert_ref}</span>
                  </b>
                  <span className="small">{filterRating(f)}</span>
                  <span className="muted small">
                    {f.holds} finding{f.holds === 1 ? "" : "s"}
                  </span>
                  {removing?.id !== f.id && (
                    <button className="btn small" disabled={busy} onClick={() => setRemoving({ id: f.id, unrate: false })} aria-label={`Remove filter ${f.id}`}>
                      Remove…
                    </button>
                  )}
                </div>
                <div className="mono small">{filterWhere(f)}</div>
                <div className="small">{f.reason}</div>
                <div className="muted small">
                  Filter {f.id}, added {f.by ?? ""} · {new Date(f.time).toLocaleString()}
                </div>
                {removing?.id === f.id && (
                  <div className="suppress-remove" role="group" aria-label={`Remove filter ${f.id}`}>
                    <span>Scans stop re-rating new findings by it.</span>
                    <label className="check">
                      <input type="checkbox" checked={removing.unrate} disabled={busy || f.holds === 0} onChange={(e) => setRemoving({ id: f.id, unrate: e.target.checked })} /> Give its{" "}
                      {f.holds} finding{f.holds === 1 ? "" : "s"} the scanner's rating back
                    </label>
                    <span className="grow" />
                    <button className="btn small" disabled={busy} onClick={stopRemoving} autoFocus>
                      Keep
                    </button>
                    <button className="btn small danger" disabled={busy} onClick={remove}>
                      Remove filter
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
