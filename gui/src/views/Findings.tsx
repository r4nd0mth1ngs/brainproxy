import { useEffect, useMemo, useRef, useState } from "react";
import { bodyText, historyRequest, isBinary, MAX_BODY, rawResponse, run, type Finding, type FindingItem, type HistoryEntry, type Risk } from "../api";
import { originOf, useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { compareArgs, seenById, type ScanCompare, type ScanJob, type Seen } from "./compare";
import { type FindingFilter, hostsOf, markCommands, matchesFinding, NO_FILTER, noteBy, noteCommand, SOURCES, type Source } from "./findingsFilter";
import { addedBy } from "./manualFinding";
import { NewFinding } from "./NewFinding";

const RISKS: Risk[] = ["high", "medium", "low", "info"];
const RANK: Record<Risk, number> = { high: 0, medium: 1, low: 2, info: 3 };

type Compare = "all" | Seen;
const COMPARE: { id: Compare; label: string; title: string }[] = [
  { id: "all", label: "All findings", title: "Every finding in the project" },
  { id: "new", label: "New in", title: "First found by this scan" },
  { id: "still", label: "Still found by", title: "Found before and found again by this scan" },
  {
    id: "gone",
    label: "Not found again by",
    title: "Found before, but this scan covered the site and rule and didn't find it again: likely fixed. Passive findings count only when the scan crawled.",
  },
];

export function RiskBadge({ risk }: { risk: Risk }) {
  return <span className={`risk risk-${risk}`}>{risk}</span>;
}

interface Group {
  ref: string;
  name: string;
  risk: Risk;
  items: FindingItem[];
}

export function FindingsView({ active }: { active: boolean }) {
  const app = useApp();
  // Every triage state but removed: removed findings added by hand stay in the project for
  // comparisons, not in the list (nor in the limit).
  const [data, refresh] = usePoll<{ items: FindingItem[] }>(() => run(["findings", "list", "--all", "--state", "open,confirmed,false_positive", "--limit", "10000"]), 5000, active);
  const [risks, setRisks] = useState(new Set<Risk>(RISKS));
  const [hideFp, setHideFp] = useState(true);
  const [filter, setFilter] = useState<FindingFilter>(NO_FILTER);
  // Findings ticked for bulk triage; only the ones still shown are acted on.
  const [checked, setChecked] = useState(new Set<number>());
  const [busy, setBusy] = useState(false);
  const [noteDraft, setNoteDraft] = useState("");
  const [open, setOpen] = useState(new Set<string>());
  const [selected, setSelected] = useState<number | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  // The finding open now, for a triage that finishes after another one was picked.
  const openId = useRef(selected);
  openId.current = selected;
  const [entry, setEntry] = useState<HistoryEntry | null>(null);
  // Compare with a scan: what's new, still there, or no longer found (likely fixed).
  const [compare, setCompare] = useState<Compare>("all");
  const [scanId, setScanId] = useState<number | null>(null);
  const [jobs] = usePoll<{ jobs: (ScanJob & { kind: string; state: string })[] }>(() => run(["job", "list", "--limit", "100"]), 10000, active);
  const scans = useMemo(() => (jobs?.jobs ?? []).filter((j) => j.kind === "active-scan" && (j.state === "completed" || j.state === "stopped")), [jobs]);
  const scan = scans.find((j) => j.id === scanId) ?? scans[0];
  const [compared, refreshSeen] = usePoll<ScanCompare | null>(
    () => (scan && compare !== "all" ? run<ScanCompare>(compareArgs(scan.id)) : Promise.resolve(null)),
    5000,
    active && compare !== "all",
  );
  useEffect(refreshSeen, [scan?.id, compare, refreshSeen]);
  const seen = useMemo(() => seenById(compared), [compared]);
  const comparing = compare !== "all" && scan != null;

  const groups = useMemo(() => {
    const by = new Map<string, Group>();
    for (const f of data?.items ?? []) {
      if (!risks.has(f.risk) || (hideFp && f.state === "false_positive")) continue;
      if (comparing && seen.get(f.id) !== compare) continue;
      if (!matchesFinding(f, filter)) continue;
      const g = by.get(f.alert_ref) ?? { ref: f.alert_ref, name: f.name, risk: f.risk, items: [] };
      g.items.push(f);
      by.set(f.alert_ref, g);
    }
    return [...by.values()].sort((a, b) => RANK[a.risk] - RANK[b.risk] || a.name.localeCompare(b.name));
  }, [data, risks, hideFp, comparing, seen, compare, filter]);

  const hosts = useMemo(() => hostsOf(data?.items ?? []), [data]);
  const shown = useMemo(() => groups.flatMap((g) => g.items.map((f) => f.id)), [groups]);
  const picked = useMemo(() => shown.filter((id) => checked.has(id)), [shown, checked]);
  const filtering = filter.text !== "" || filter.source !== "all" || filter.host !== "";

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of data?.items ?? []) if (f.state !== "false_positive") c[f.risk] = (c[f.risk] ?? 0) + 1;
    return c;
  }, [data]);

  useEffect(() => {
    if (selected == null) return;
    let live = true;
    setEntry(null);
    run<Finding>(["findings", "show", String(selected)])
      .then((f) => {
        if (!live) return;
        setFinding(f);
        setNoteDraft(f.note ?? "");
        if (f.history_id != null) run<HistoryEntry>(["history", "show", String(f.history_id), MAX_BODY]).then((e) => live && setEntry(e), () => {});
      })
      .catch((e) => app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [selected, app.toast]);

  const added = (id: number, ref: string, warnings: string[]) => {
    app.newFinding(null);
    app.toast([`Finding #${id} added.`, ...warnings].join("\n"));
    setRisks(new Set(RISKS));
    setCompare("all");
    setOpen((o) => new Set(o).add(ref));
    setSelected(id);
    refresh();
  };

  // Only findings added by hand can be removed; scanner findings are marked instead.
  const remove = async () => {
    if (!finding) return;
    const message = `"${finding.name}" at ${finding.url} leaves the findings and reports. The project keeps a record that it was removed, so comparing with an earlier report shows it as removed, not fixed.`;
    if (!(await confirm("Remove this finding?", message, "Remove", "Keep"))) return;
    try {
      await run(["findings", "remove", String(finding.id)]);
      setSelected(null);
      setFinding(null);
      setEntry(null);
      refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const mark = async (state: string) => {
    if (!finding) return;
    try {
      await run(["findings", "mark", String(finding.id), "--state", state]);
      setFinding((cur) => (cur?.id === finding.id ? { ...cur, state } : cur));
      refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // Several findings at once, in batches; a failed batch stops there and says so.
  const markPicked = async (state: string) => {
    setBusy(true);
    let done = 0;
    try {
      for (const cmd of markCommands(picked, state)) {
        await run(cmd);
        done += cmd.length - 4;
      }
      app.toast(`Marked ${done} finding${done === 1 ? "" : "s"} ${state.replace("_", " ")}.`);
      setChecked(new Set());
      setFinding((cur) => (cur && picked.includes(cur.id) ? { ...cur, state } : cur));
    } catch (e: any) {
      app.toast(`${done ? `Marked ${done}, then: ` : ""}${e.message}`, "error");
    }
    setBusy(false);
    refresh();
  };

  const saveNote = async () => {
    if (!finding) return;
    const id = finding.id;
    try {
      await run(noteCommand(id, noteDraft));
      const f = await run<Finding>(["findings", "show", String(id)]);
      // Another finding was opened meanwhile: the note is saved, and that one is shown.
      if (openId.current !== id) return;
      setFinding(f);
      setNoteDraft(f.note ?? "");
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // A readable HTML report (summary, how to fix, evidence folded away) saved where the user picks.
  const [reporting, setReporting] = useState(false);
  const saveReport = async () => {
    const name = app.temp ? "engagement" : app.project.split(/[\\/]/).pop()!.replace(/\.bpdb$/, "");
    const dialog = await import("@tauri-apps/plugin-dialog");
    const path = await dialog.save({ defaultPath: `${name}-report.html`, filters: [{ name: "HTML report", extensions: ["html"] }] });
    if (typeof path !== "string") return;
    setReporting(true);
    try {
      const file = /\.html?$/i.test(path) ? path : `${path}.html`;
      const r = await run<{ total: number; redacted: number | null }>(["report", "html", "--output", file, "--force", `--title=${name} security report`]);
      const masked = r.redacted ? ` Session secrets are masked in ${r.redacted} place${r.redacted === 1 ? "" : "s"}.` : "";
      app.toast(`Report saved with ${r.total} finding${r.total === 1 ? "" : "s"}.${masked} Open it in a browser; print it to make a PDF.`);
      const { revealItemInDir } = await import("@tauri-apps/plugin-opener");
      await revealItemInDir(file).catch(() => {});
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    setReporting(false);
  };

  const toggle = <T,>(set: Set<T>, v: T) => {
    const s = new Set(set);
    s.has(v) ? s.delete(v) : s.add(v);
    return s;
  };

  return (
    <div className="col fill">
      <div className="toolbar">
        <div className="seg">
          {RISKS.map((r) => (
            <button key={r} className={risks.has(r) ? "on" : ""} onClick={() => setRisks(toggle(risks, r))}>
              <span className={`dot-risk risk-${r}`} /> {r} <span className="muted">{counts[r] ?? 0}</span>
            </button>
          ))}
        </div>
        <input
          className="input"
          style={{ width: 200 }}
          placeholder="Search: name, URL, evidence, #id"
          value={filter.text}
          onChange={(e) => setFilter({ ...filter, text: e.target.value })}
          onKeyDown={(e) => e.key === "Escape" && setFilter({ ...filter, text: "" })}
        />
        <select className="input" value={filter.source} onChange={(e) => setFilter({ ...filter, source: e.target.value as Source })} title="Which scanner raised it">
          {SOURCES.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
            </option>
          ))}
        </select>
        {hosts.length > 1 && (
          <select className="input" value={filter.host} onChange={(e) => setFilter({ ...filter, host: e.target.value })} title="The host it was found on">
            <option value="">Any host</option>
            {hosts.map((h) => (
              <option key={h} value={h}>
                {h}
              </option>
            ))}
          </select>
        )}
        <label className="check">
          <input type="checkbox" checked={hideFp} onChange={(e) => setHideFp(e.target.checked)} /> Hide false positives
        </label>
        <select className="input" value={compare} onChange={(e) => setCompare(e.target.value as Compare)} title={COMPARE.find((c) => c.id === compare)!.title}>
          {COMPARE.map((c) => (
            <option key={c.id} value={c.id} disabled={c.id !== "all" && !scans.length} title={c.title}>
              {c.label}
              {c.id === "all" ? "" : " scan…"}
            </option>
          ))}
        </select>
        {compare !== "all" && (
          <select className="input" value={scan?.id ?? ""} onChange={(e) => setScanId(Number(e.target.value))} title="The scan to compare with">
            {scans.map((j) => (
              <option key={j.id} value={j.id}>
                #{j.id} {new Date(j.time).toLocaleString()} · {j.args.filter((a) => /^https?:\/\//i.test(a)).join(" ") || "recorded traffic"}
              </option>
            ))}
          </select>
        )}
        <span className="grow" />
        <span className="muted">{groups.length} issue types</span>
        <button className="btn small" onClick={() => app.newFinding({})} title="Write up an issue you found by hand (nothing is sent)">
          New finding…
        </button>
        <button className="btn small" disabled={reporting} onClick={saveReport} title="Save a readable HTML report of all findings except false positives">
          {reporting ? "Saving…" : "Report…"}
        </button>
      </div>
      {picked.length > 0 && (
        <div className="toolbar bulk-bar">
          <strong>{picked.length} selected</strong>
          <span className="muted">Mark as</span>
          <div className="seg">
            {["open", "confirmed", "false_positive"].map((s) => (
              <button key={s} disabled={busy} onClick={() => markPicked(s)}>
                {s.replace("_", " ")}
              </button>
            ))}
          </div>
          {picked.length < shown.length && (
            <button className="btn small" disabled={busy} onClick={() => setChecked(new Set(shown))}>
              Select all {shown.length} shown
            </button>
          )}
          <button className="btn small" disabled={busy} onClick={() => setChecked(new Set())}>
            Clear selection
          </button>
        </div>
      )}
      <Split id="findings" dir="row" initial={0.34}>
        <div className="tree">
          {groups.length === 0 && (
            <div className="empty">
              {comparing
                ? compare === "gone"
                  ? "Nothing that this scan covered is missing: no fixes to show yet."
                  : "No findings match this comparison."
                : filtering
                  ? "No findings match the search and filters."
                  : "No findings. Passive rules run on recorded traffic; active scans add more."}
            </div>
          )}
          {groups.map((g) => {
            const ids = g.items.map((f) => f.id);
            const n = ids.filter((id) => checked.has(id)).length;
            return (
              <div key={g.ref}>
                <div className="tree-row">
                  <input
                    type="checkbox"
                    className="tree-check"
                    aria-label={`Select every ${g.name} finding`}
                    checked={n === ids.length}
                    ref={(el) => {
                      if (el) el.indeterminate = n > 0 && n < ids.length;
                    }}
                    onChange={(e) => {
                      const next = new Set(checked);
                      for (const id of ids) e.target.checked ? next.add(id) : next.delete(id);
                      setChecked(next);
                    }}
                  />
                  <button className="tree-group" onClick={() => setOpen(toggle(open, g.ref))}>
                    <span className="caret">{open.has(g.ref) ? "▾" : "▸"}</span>
                    <span className={`dot-risk risk-${g.risk}`} />
                    <span className="grow ellipsis">{g.name}</span>
                    {g.ref.startsWith("manual:") &&
                      [...new Set(g.items.map((f) => addedBy(f.origin).tag))].map((t) => (
                        <span key={t} className="tag">
                          {t}
                        </span>
                      ))}
                    <span className="muted">{g.items.length}</span>
                  </button>
                </div>
                {/* A search opens every group it matches, so the matches are in view. */}
                {(open.has(g.ref) || filter.text !== "") &&
                  g.items.map((f) => (
                    <div key={f.id} className="tree-row">
                      <input
                        type="checkbox"
                        className="tree-check item"
                        aria-label={`Select finding ${f.id}`}
                        checked={checked.has(f.id)}
                        onChange={() => setChecked(toggle(checked, f.id))}
                      />
                      <button className={`tree-item ${selected === f.id ? "on" : ""} ${f.state === "false_positive" ? "struck" : ""}`} onClick={() => setSelected(f.id)}>
                        <span className="ellipsis">
                          {/* One rule can raise differently named alerts (e.g. 40018 for each database). */}
                          {f.name !== g.name && <span className="tree-subname">{f.name} · </span>}
                          {f.url}
                          {f.param && <span className="muted"> [{f.param}]</span>}
                        </span>
                        {f.state === "confirmed" && <span className="tag">confirmed</span>}
                      </button>
                    </div>
                  ))}
              </div>
            );
          })}
        </div>
        {finding ? (
          <Split id="finding-detail" dir="col" initial={0.5}>
            <div className="detail">
              <div className="detail-head">
                <RiskBadge risk={finding.risk} />
                <h2>{finding.name}</h2>
              </div>
              <div className="toolbar flat">
                <div className="seg">
                  {["open", "confirmed", "false_positive"].map((s) => (
                    <button key={s} className={finding.state === s ? "on" : ""} onClick={() => mark(s)}>
                      {s.replace("_", " ")}
                    </button>
                  ))}
                </div>
                {entry && (
                  <button
                    className="btn small"
                    onClick={() =>
                      historyRequest(entry.id).then(
                        ({ raw, binary }) => app.sendToRepeater({ raw, binary, target: originOf(entry.url), title: finding.name.slice(0, 24) }),
                        (e) => app.toast(e.message, "error"),
                      )
                    }
                  >
                    Send to Replay
                  </button>
                )}
                {finding.source === "manual" && (
                  <button className="btn small" onClick={remove} title="Take this finding out of the findings and reports">
                    Remove
                  </button>
                )}
              </div>
              <dl className="facts">
                <dt>URL</dt>
                <dd className="mono">
                  {finding.method} {finding.url}
                </dd>
                {finding.param && (
                  <>
                    <dt>Parameter</dt>
                    <dd className="mono">{finding.param}</dd>
                  </>
                )}
                {finding.attack && (
                  <>
                    <dt>Attack</dt>
                    <dd className="mono">{finding.attack}</dd>
                  </>
                )}
                {finding.evidence && (
                  <>
                    <dt>Evidence</dt>
                    <dd className="mono">{finding.evidence}</dd>
                  </>
                )}
                <dt>Confidence</dt>
                <dd>{finding.confidence}</dd>
                {finding.source === "manual" ? (
                  <>
                    <dt>Source</dt>
                    <dd>
                      {addedBy(finding.origin).text}
                      {finding.cwe ? ` · CWE-${finding.cwe}` : ""}
                      {finding.history_ids?.length ? ` · history ${finding.history_ids.map((h) => `#${h}`).join(", ")}` : ""}
                    </dd>
                  </>
                ) : (
                  <>
                    <dt>Rule</dt>
                    <dd>
                      {finding.alert_ref} ({finding.source}){finding.cwe ? ` · CWE-${finding.cwe}` : ""}
                      {finding.wasc ? ` · WASC-${finding.wasc}` : ""} · {finding.hits} hit{finding.hits === 1 ? "" : "s"}
                    </dd>
                  </>
                )}
              </dl>
              <h3>Note</h3>
              <textarea
                className="input note-input"
                rows={3}
                placeholder="Your triage notes: why it's confirmed or a false positive, what to retest. Reports show it."
                value={noteDraft}
                onChange={(e) => setNoteDraft(e.target.value)}
              />
              <div className="toolbar flat">
                <button className="btn small" disabled={noteDraft.trim() === (finding.note ?? "")} onClick={saveNote}>
                  {noteDraft.trim() === "" && finding.note ? "Clear note" : "Save note"}
                </button>
                {finding.note && <span className="muted">Written {noteBy(finding.note_origin, finding.note_changed_at)}</span>}
              </div>
              {finding.description && (
                <>
                  <h3>Description</h3>
                  <p className="prose">{finding.description}</p>
                </>
              )}
              {finding.other_info && (
                <>
                  <h3>Details</h3>
                  <p className="prose">{finding.other_info}</p>
                </>
              )}
              {finding.solution && (
                <>
                  <h3>Solution</h3>
                  <p className="prose">{finding.solution}</p>
                </>
              )}
              {!!finding.refs?.length && (
                <>
                  <h3>References</h3>
                  <ul className="refs">
                    {finding.refs.map((r) => (
                        <li key={r} className="mono">
                          {r}
                        </li>
                      ))}
                  </ul>
                </>
              )}
            </div>
            <Split id="finding-msg" dir="row">
              <HttpView title="Request" value={entry ? bodyText(entry.request) : ""} binary={isBinary(entry?.request)} placeholder="No recorded request" />
              <HttpView title="Response" value={entry ? rawResponse(entry) : ""} binary={isBinary(entry?.response?.body)} placeholder="" highlight={finding.evidence} />
            </Split>
          </Split>
        ) : (
          <div className="blank">Select a finding to see its details and evidence.</div>
        )}
      </Split>
      {app.findingDraft && <NewFinding draft={app.findingDraft} onClose={() => app.newFinding(null)} onAdded={added} />}
    </div>
  );
}
