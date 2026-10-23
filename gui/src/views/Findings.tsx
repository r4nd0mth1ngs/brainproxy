import { useEffect, useMemo, useState } from "react";
import { bodyText, historyRequest, isBinary, MAX_BODY, rawResponse, run, type Finding, type FindingItem, type HistoryEntry, type Risk } from "../api";
import { originOf, useApp } from "../store";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { compareSql, scanScope, type ScanJob, type Seen } from "./compare";

const RISKS: Risk[] = ["high", "medium", "low", "info"];
const RANK: Record<Risk, number> = { high: 0, medium: 1, low: 2, info: 3 };

type Compare = "all" | Exclude<Seen, "other">;
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
  const [data, refresh] = usePoll<{ items: FindingItem[] }>(() => run(["findings", "list", "--all", "--state", "all", "--limit", "10000"]), 5000, active);
  const [risks, setRisks] = useState(new Set<Risk>(RISKS));
  const [hideFp, setHideFp] = useState(true);
  const [open, setOpen] = useState(new Set<string>());
  const [selected, setSelected] = useState<number | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [entry, setEntry] = useState<HistoryEntry | null>(null);
  // Compare with a scan: what's new, still there, or no longer found (likely fixed).
  const [compare, setCompare] = useState<Compare>("all");
  const [scanId, setScanId] = useState<number | null>(null);
  const [jobs] = usePoll<{ jobs: (ScanJob & { kind: string; state: string })[] }>(() => run(["job", "list", "--limit", "100"]), 10000, active);
  const scans = useMemo(() => (jobs?.jobs ?? []).filter((j) => j.kind === "active-scan" && (j.state === "completed" || j.state === "stopped")), [jobs]);
  const scan = scans.find((j) => j.id === scanId) ?? scans[0];
  const [seenRows, refreshSeen] = usePoll<{ rows: [number, Seen][] }>(
    () => (scan && compare !== "all" ? run(["query", compareSql(scanScope(scan))]) : Promise.resolve({ rows: [] })),
    5000,
    active && compare !== "all",
  );
  useEffect(refreshSeen, [scan?.id, compare, refreshSeen]);
  const seen = useMemo(() => new Map(seenRows?.rows ?? []), [seenRows]);
  const comparing = compare !== "all" && scan != null;

  const groups = useMemo(() => {
    const by = new Map<string, Group>();
    for (const f of data?.items ?? []) {
      if (!risks.has(f.risk) || (hideFp && f.state === "false_positive")) continue;
      if (comparing && seen.get(f.id) !== compare) continue;
      const g = by.get(f.alert_ref) ?? { ref: f.alert_ref, name: f.name, risk: f.risk, items: [] };
      g.items.push(f);
      by.set(f.alert_ref, g);
    }
    return [...by.values()].sort((a, b) => RANK[a.risk] - RANK[b.risk] || a.name.localeCompare(b.name));
  }, [data, risks, hideFp, comparing, seen, compare]);

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
        if (f.history_id != null) run<HistoryEntry>(["history", "show", String(f.history_id), MAX_BODY]).then((e) => live && setEntry(e), () => {});
      })
      .catch((e) => app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [selected, app.toast]);

  const mark = async (state: string) => {
    if (!finding) return;
    try {
      await run(["findings", "mark", String(finding.id), "--state", state]);
      setFinding({ ...finding, state });
      refresh();
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
      const r = await run<{ total: number }>(["report", "html", "--output", file, "--force", `--title=${name} security report`]);
      app.toast(`Report saved with ${r.total} finding${r.total === 1 ? "" : "s"}. Open it in a browser; print it to make a PDF.`);
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
        <button className="btn small" disabled={reporting} onClick={saveReport} title="Save a readable HTML report of all findings except false positives">
          {reporting ? "Saving…" : "Report…"}
        </button>
      </div>
      <Split id="findings" dir="row" initial={0.34}>
        <div className="tree">
          {groups.length === 0 && (
            <div className="empty">
              {comparing
                ? compare === "gone"
                  ? "Nothing that this scan covered is missing: no fixes to show yet."
                  : "No findings match this comparison."
                : "No findings. Passive rules run on recorded traffic; active scans add more."}
            </div>
          )}
          {groups.map((g) => (
            <div key={g.ref}>
              <button className="tree-group" onClick={() => setOpen(toggle(open, g.ref))}>
                <span className="caret">{open.has(g.ref) ? "▾" : "▸"}</span>
                <span className={`dot-risk risk-${g.risk}`} />
                <span className="grow ellipsis">{g.name}</span>
                <span className="muted">{g.items.length}</span>
              </button>
              {open.has(g.ref) &&
                g.items.map((f) => (
                  <button key={f.id} className={`tree-item ${selected === f.id ? "on" : ""} ${f.state === "false_positive" ? "struck" : ""}`} onClick={() => setSelected(f.id)}>
                    <span className="ellipsis">
                      {/* One rule can raise differently named alerts (e.g. 40018 for each database). */}
                      {f.name !== g.name && <span className="tree-subname">{f.name} · </span>}
                      {f.url}
                      {f.param && <span className="muted"> [{f.param}]</span>}
                    </span>
                    {f.state === "confirmed" && <span className="tag">confirmed</span>}
                  </button>
                ))}
            </div>
          ))}
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
                <dt>Rule</dt>
                <dd>
                  {finding.alert_ref} ({finding.source}){finding.cwe ? ` · CWE-${finding.cwe}` : ""}
                  {finding.wasc ? ` · WASC-${finding.wasc}` : ""} · {finding.hits} hit{finding.hits === 1 ? "" : "s"}
                </dd>
              </dl>
              <h3>Description</h3>
              <p className="prose">{finding.description}</p>
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
    </div>
  );
}
