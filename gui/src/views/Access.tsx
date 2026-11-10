// Access: access control across users (`authz`). Start a run (or live testing through the proxy),
// see a run as a grid of requests by identities, and open a cell to compare the owner's response
// with that identity's.

import { useEffect, useMemo, useState } from "react";
import { bodyText, rawResponse, run, type HistoryEntry } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { afterStart, grid, KIND_LABEL, KINDS, liveArgs, notTested, parseSkipPaths, runArgs, runLabel, skipSetArgs, type AuthzRun, type CellKind, type Matrix, type RunForm } from "./accessMatrix";
import { startLive, withPortHint } from "./proxyPort";
import { stateClass, type Job } from "./Scanner";
import { accessConfirm, changeKinds, isLogout } from "./trafficActions";

const FORM: RunForm = { identities: [], anonymous: true, owner: "", select: "all", host: "", tag: "", where: "", history: [], keepCookies: "", rate: "", includeStatic: false };

/** The cell being compared: the run's baseline and the identity's replay. */
interface Picked {
  method: string;
  url: string;
  owner: string;
  identity: string;
  kind: CellKind;
  baselineId: number;
  historyId: number;
}

interface ResultRow {
  history_id: number | null;
  reason: string;
  evidence: string;
  similarity: number | null;
  private_total: number | null;
  private_hits: number | null;
}

export function AccessView({ active }: { active: boolean }) {
  const app = useApp();
  const [runs, refreshRuns] = usePoll<{ runs: AuthzRun[] }>(() => run(["authz", "list", "--limit", "50"]), 3000, active);
  const [runId, setRunId] = useState<number | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [only, setOnly] = useState<CellKind | null>(null);
  const [worstFirst, setWorstFirst] = useState(true);
  const [issuesOnly, setIssuesOnly] = useState(true);
  const [showHidden, setShowHidden] = useState(false);
  const [showSkips, setShowSkips] = useState(false);
  const [picked, setPicked] = useState<Picked | null>(null);

  // The newest run until one is picked; the form when there are none yet.
  useEffect(() => {
    if (!runs) return;
    if (runId == null && runs.runs.length) setRunId(runs.runs[0].run_id);
    if (!runs.runs.length) setShowNew(true);
  }, [runs, runId]);

  const current = runs?.runs.find((r) => r.run_id === runId) ?? null;
  const live = !!current && ["queued", "running", "stopping"].includes(current.state);
  const [job, refreshJob] = usePoll<Job>(() => run(["job", "status", String(runId)]), 2000, active && runId != null && live);
  const [matrix, refreshMatrix] = usePoll<Matrix | null>(
    // With the noise, each marked: the view hides it unless asked.
    () => (runId == null ? Promise.resolve(null) : run<Matrix>(["authz", "matrix", String(runId), "--limit", "2000", "--all"])),
    live ? 2000 : 30000,
    active,
  );
  useEffect(() => {
    refreshMatrix();
    setPicked(null);
  }, [runId, refreshMatrix]);
  // A run that just finished: its last rows.
  useEffect(() => {
    if (current && !live) refreshMatrix();
  }, [current?.state, live, refreshMatrix]);

  // What a finished run left out, from its summary.
  const [summary, setSummary] = useState<{ run: number; skipped: Record<string, unknown> | null } | null>(null);
  useEffect(() => {
    if (runId == null || live || !current) return;
    let cancelled = false;
    run<Job>(["job", "status", String(runId)]).then(
      // A batch run's summary has them under `skipped`, live testing's at the top.
      (j) => !cancelled && setSummary({ run: runId, skipped: j.result?.skipped ?? j.result ?? null }),
      () => {},
    );
    return () => {
      cancelled = true;
    };
  }, [runId, live, current?.state]);
  const leftOut = live ? notTested(job?.progress as Record<string, unknown> | null) : summary?.run === runId ? notTested(summary.skipped) : "";

  // Requests handed over from Traffic open the new-run form.
  useEffect(() => {
    if (app.accessInput) setShowNew(true);
  }, [app.accessInput]);

  const g = useMemo(
    () => (matrix && matrix.run_id === runId ? grid(matrix, { only, worstFirst, issuesOnly, showHidden }) : null),
    [matrix, runId, only, worstFirst, issuesOnly, showHidden],
  );

  const started = (id: number) => {
    setShowNew(false);
    setRunId(id);
    refreshRuns();
  };

  const stop = async () => {
    if (runId == null) return;
    try {
      await run(["job", "stop", String(runId)]);
      refreshJob();
      refreshRuns();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const top = (
    <div className="col fill">
      <div className="toolbar">
        <span className="label">Run</span>
        <select className="input az-run" value={runId ?? ""} onChange={(e) => setRunId(e.target.value ? Number(e.target.value) : null)} disabled={!runs?.runs.length}>
          {!runs?.runs.length && <option value="">No runs yet</option>}
          {runs?.runs.map((r) => (
            <option key={r.run_id} value={r.run_id}>
              {runLabel(r)}
            </option>
          ))}
        </select>
        {current && <span className={stateClass(current.state)}>{current.state}</span>}
        {live && job && <span className="muted small">{progressText(job)}</span>}
        {live && current?.args[0] !== "proxy" && (
          <button className="btn small" onClick={stop} disabled={current?.state === "stopping"}>
            Stop
          </button>
        )}
        <div className="toolbar-end">
          <label className="check" title="Only rows with a bypass, or a response anyone gets without a session. A verdict below picks its rows instead">
            <input type="checkbox" checked={issuesOnly} onChange={(e) => setIssuesOnly(e.target.checked)} /> Issues only
          </label>
          <label className="check" title="Rows with a bypass first">
            <input type="checkbox" checked={worstFirst} onChange={(e) => setWorstFirst(e.target.checked)} /> Worst first
          </label>
          <button className="btn small" onClick={() => setShowSkips((s) => !s)} title="Paths runs and live testing leave out, and this view hides">
            Skip paths
          </button>
          <button className={`btn small ${showNew ? "" : "primary"}`} onClick={() => setShowNew((s) => !s)}>
            {showNew ? "Hide new run" : "New run"}
          </button>
        </div>
      </div>
      {/* Kept mounted, so what was picked survives hiding it. */}
      <div className="az-new" hidden={!showNew}>
        <NewRun onStarted={started} />
      </div>
      {showSkips && <SkipPaths onSaved={refreshMatrix} onClose={() => setShowSkips(false)} />}
      {g && (
        <div className="toolbar flat az-legend">
          {KINDS.filter((k) => k !== "none" && (g.counts[k] || only === k)).map((k) => (
            <button key={k} className={`chip az-${k} ${only === k ? "on" : ""}`} onClick={() => setOnly(only === k ? null : k)} title={only === k ? "Show every row" : `Only rows with ${KIND_LABEL[k]}`}>
              {KIND_LABEL[k]} · {g.counts[k]}
            </button>
          ))}
          {g.skipped > 0 && <span className="muted small">{g.skipped} skipped</span>}
          {g.hidden > 0 && (
            <label className="check small" title="Static assets and requests matching a skip path, tested before they were left out">
              <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} /> {g.hidden} static or skipped
            </label>
          )}
          {g.quiet > 0 && (
            <button className="link small" onClick={() => setIssuesOnly(false)} title="Rows that are all enforced, different or inconclusive">
              {g.quiet} {g.quiet === 1 ? "row" : "rows"} with no issue
            </button>
          )}
          {leftOut && <span className="muted small" title="Left out before sending: the run's summary (brainproxy job status RUN) lists some with why">{leftOut}</span>}
          {matrix?.truncated && <span className="muted small">first 2000 requests</span>}
        </div>
      )}
      {!g ? (
        <div className="blank">
          <p>{!runs || runs.runs.length ? "Loading…" : "No access-control runs yet. Pick identities above and start one, or test live while you browse."}</p>
        </div>
      ) : !g.rows.length ? (
        <div className="blank">
          <p>
            {only
              ? "No rows with that verdict."
              : g.quiet > 0
                ? `No issues: ${g.quiet} ${g.quiet === 1 ? "row shows" : "rows show"} only refusals, differences or nothing to compare.`
                : live
                  ? "Waiting for results…"
                  : g.hidden > 0
                    ? "Only static assets or skipped paths: tick the box above to see them."
                    : "This run tested no requests."}
          </p>
        </div>
      ) : (
        <div className="az-grid-wrap">
          <table className="az-grid">
            <thead>
              <tr>
                <th>Request</th>
                <th>Owner</th>
                {g.columns.map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {g.rows.map((r) => (
                <tr key={r.key}>
                  <td className="mono ellipsis az-req" title={`${r.method} ${r.url}`}>
                    <span className="method">{r.method}</span> {r.url}
                  </td>
                  <td className="muted">{r.owner}</td>
                  {r.skipped ? (
                    <td className="muted small az-skipped" colSpan={g.columns.length}>
                      {r.skipped}
                    </td>
                  ) : (
                    r.cells.map((c) => {
                      const can = c.historyId != null && r.baselineId != null;
                      const on = picked?.historyId === c.historyId && can;
                      return (
                        <td key={c.identity}>
                          <button
                            className={`az-cell az-${c.kind} ${on ? "on" : ""}`}
                            disabled={!can}
                            title={can ? `${KIND_LABEL[c.kind]}: compare with the owner's response` : undefined}
                            onClick={() => setPicked({ method: r.method, url: r.url, owner: r.owner, identity: c.identity, kind: c.kind, baselineId: r.baselineId!, historyId: c.historyId! })}
                          >
                            {c.text}
                          </button>
                        </td>
                      );
                    })
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );

  // Always a Split, so opening a comparison doesn't remount the grid and the form.
  return (
    <Split id="access" dir="col" initial={0.5} solo={!picked || runId == null}>
      {top}
      {picked && runId != null ? <Compare runId={runId} picked={picked} onClose={() => setPicked(null)} /> : null}
    </Split>
  );
}

function progressText(j: Job): string {
  const p = j.progress as Record<string, number> | null;
  if (!p) return "";
  if (p.requests != null) return `${p.requests_done ?? 0}/${p.requests} requests · ${p.sent ?? 0} sent`;
  // Live testing through the proxy (what it left out is next to the legend).
  return `${p.tested ?? 0} tested · ${p.waiting ?? 0} waiting · ${p.duplicates ?? 0} duplicates${p.dropped_queue_full ? ` · ${p.dropped_queue_full} dropped (queue full)` : ""}`;
}

// ---------------- skip paths ----------------

function SkipPaths({ onSaved, onClose }: { onSaved: () => void; onClose: () => void }) {
  const app = useApp();
  const [text, setText] = useState<string | null>(null);
  const [info, setInfo] = useState<{ defaults: boolean; syntax: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const show = (d: { paths: string[]; defaults: boolean; syntax: string }) => {
    setText(d.paths.join("\n"));
    setInfo({ defaults: d.defaults, syntax: d.syntax });
  };
  useEffect(() => {
    run<{ paths: string[]; defaults: boolean; syntax: string }>(["authz", "skip", "list"]).then(show, (e) => app.toast(e.message, "error"));
  }, [app.toast]);

  const save = async (args: string[]) => {
    setBusy(true);
    try {
      show(await run(args));
      onSaved();
      app.toast("Skip paths saved: they apply to new runs, live testing and this view");
    } catch (e: any) {
      app.toast(e.message, "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="detail sc-form az-form az-skips">
      <div className="row gap">
        <span className="label">Skip paths</span>
        <span className="muted small">
          Requests runs and live testing leave out, and this view hides, for every run. One per line: {info?.syntax ?? "…"}.
          {info?.defaults && " These are the defaults: files that are public by design."}
        </span>
        <button className="icon-btn" onClick={onClose} title="Close">
          ×
        </button>
      </div>
      <textarea className="input mono" rows={8} value={text ?? ""} disabled={text == null} spellCheck={false} onChange={(e) => setText(e.target.value)} placeholder="/static/&#10;*/health$&#10;https://cdn.example.com/" />
      <div className="row gap">
        <button className="btn primary" disabled={busy || text == null} onClick={() => save(skipSetArgs(parseSkipPaths(text ?? "")))}>
          Save
        </button>
        <button className="btn" disabled={busy} onClick={() => save(["authz", "skip", "set", "--defaults"])} title="robots.txt, /.well-known/, favicon.ico, health checks and the like">
          Back to defaults
        </button>
      </div>
    </div>
  );
}

// ---------------- compare ----------------

function Compare({ runId, picked, onClose }: { runId: number; picked: Picked; onClose: () => void }) {
  const app = useApp();
  const [part, setPart] = useState<"response" | "request">("response");
  const [pair, setPair] = useState<{ base: HistoryEntry; other: HistoryEntry } | null>(null);
  const [row, setRow] = useState<ResultRow | null>(null);

  useEffect(() => {
    let cancelled = false;
    setPair(null);
    setRow(null);
    Promise.all([
      run<HistoryEntry>(["history", "show", String(picked.baselineId), "--max-body", "2000000"]),
      run<HistoryEntry>(["history", "show", String(picked.historyId), "--max-body", "2000000"]),
    ]).then(
      ([base, other]) => !cancelled && setPair({ base, other }),
      (e) => app.toast(e.message, "error"),
    );
    run<{ results: ResultRow[] }>(["authz", "results", String(runId), "--identity", picked.identity, "--limit", "100000"]).then(
      (d) => !cancelled && setRow(d.results.find((r) => r.history_id === picked.historyId) ?? null),
      () => {},
    );
    return () => {
      cancelled = true;
    };
  }, [runId, picked.baselineId, picked.historyId, picked.identity, app.toast]);

  const text = (e: HistoryEntry) => (part === "request" ? bodyText(e.request) : rawResponse(e));
  const toDiff = () => {
    if (!pair) return;
    app.setComparer([...app.comparer, text(pair.base), text(pair.other)].slice(-12));
    app.setTab("comparer");
  };

  return (
    <div className="col fill">
      <div className="toolbar">
        <span className={`chip az-${picked.kind}`}>{KIND_LABEL[picked.kind]}</span>
        <span className="mono ellipsis" title={picked.url}>
          <span className="method">{picked.method}</span> {picked.url}
        </span>
        {row && <span className="muted small ellipsis" title={row.evidence || row.reason}>{row.evidence || row.reason}{row.similarity != null ? ` · similarity ${row.similarity.toFixed(2)}` : ""}</span>}
        <div className="toolbar-end">
          <div className="seg">
            <button className={part === "response" ? "on" : ""} onClick={() => setPart("response")}>
              Responses
            </button>
            <button className={part === "request" ? "on" : ""} onClick={() => setPart("request")}>
              Requests
            </button>
          </div>
          <button className="btn small" disabled={!pair} onClick={toDiff} title="Open both in Diff">
            Diff
          </button>
          <button className="icon-btn" onClick={onClose} title="Close">
            ×
          </button>
        </div>
      </div>
      {!pair ? (
        <div className="blank">
          <p>Loading…</p>
        </div>
      ) : (
        <Split id="access-compare" dir="row" initial={0.5}>
          <HttpView value={text(pair.base)} title={`${picked.owner} (baseline) · #${picked.baselineId}`} />
          <HttpView value={text(pair.other)} title={`${picked.identity} · #${picked.historyId}`} />
        </Split>
      )}
    </div>
  );
}

// ---------------- new run ----------------

function NewRun({ onStarted }: { onStarted: (id: number) => void }) {
  const app = useApp();
  const [f, setF] = useState(FORM);
  const set = (patch: Partial<RunForm>) => setF((x) => ({ ...x, ...patch }));
  const [auth] = usePoll<{ profiles: { name: string; username?: string | null }[] }>(() => run(["auth", "list"]), 15000);
  const [hosts, setHosts] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const profiles = auth?.profiles ?? [];

  useEffect(() => {
    run<{ rows: [string][] }>(["query", "SELECT DISTINCT host FROM history WHERE source IN ('proxy','send','crawl','import') ORDER BY host LIMIT 200"]).then(
      (d) => setHosts(d.rows.map((r) => r[0])),
      () => {},
    );
  }, []);

  // Requests handed over from Traffic: test exactly those.
  useEffect(() => {
    if (app.accessInput) set({ select: "history", history: app.accessInput });
  }, [app.accessInput]);
  const unsafe = changeKinds(f.history);
  const logouts = f.history.filter(isLogout);

  const toggle = (name: string) => set({ identities: f.identities.includes(name) ? f.identities.filter((n) => n !== name) : [...f.identities, name] });

  const start = async () => {
    try {
      runArgs(f); // the form is checked before anything is asked
      // Requests from Traffic are replayed whatever their method or path once the user says so: a
      // POST, a GraphQL mutation or a logout is asked about first, and only a yes opts them in.
      const q = f.select === "history" ? accessConfirm(f.history, f.identities, f.anonymous) : null;
      if (q && !(await confirm(q.title, q.message, q.ok, q.cancel))) return;
      const args = runArgs(f, !!q);
      setBusy(true);
      const d = await run<{ job: number }>([...args, "--background"]);
      setF(afterStart);
      app.toast(`Access-control run #${d.job} started`);
      onStarted(d.job);
    } catch (e: any) {
      app.toast(e.message, "error");
    } finally {
      setBusy(false);
    }
  };

  // Restarts the proxy on the same address and with the same options, plus live testing, in one
  // `proxy restart` (proxyPort.ts). If it doesn't come up, the CLI starts the previous proxy again.
  const onLive = async () => {
    if (app.proxy.moving) return app.toast("The proxy is restarting on another port. Try again in a moment.");
    try {
      const live = liveArgs(f);
      setBusy(true);
      const d = await startLive(run, app.proxy, live);
      const who = [...(f.anonymous ? ["anonymous"] : []), ...f.identities].join(", ");
      app.toast(`Proxy restarted on ${d.listen}: requests you browse are now also tried as ${who}`);
      if (d.authz_run != null) onStarted(d.authz_run);
    } catch (e: any) {
      app.toast(withPortHint(e.message), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="detail sc-form az-form">
      <p className="muted small">
        Requests from history are sent again as each identity (with the owner's credentials removed) and with no session, and
        compared with the owner's response. Only GET requests that carry credentials are picked; logout paths, static
        assets and the skip paths are left alone. Requests sent from Traffic are the exception: they are tested as they
        are. Every request stays inside the engagement scope.
      </p>
      <div className="sc-field">
        <span className="label">Send as</span>
        <div className="row gap sc-checks">
          <label className="check" title="Send with no credentials at all">
            <input type="checkbox" checked={f.anonymous} onChange={(e) => set({ anonymous: e.target.checked })} /> anonymous
          </label>
          {profiles.map((p) => (
            <label key={p.name} className="check" title={p.username ? `logs in as ${p.username}` : undefined}>
              <input type="checkbox" checked={f.identities.includes(p.name)} onChange={() => toggle(p.name)} /> {p.name}
            </label>
          ))}
          {auth && !profiles.length && (
            <span className="muted small">
              No auth profiles yet: add one per user in{" "}
              <button className="link" onClick={() => app.setTab("settings")}>
                Settings › Auth profiles
              </button>
              .
            </span>
          )}
        </div>
      </div>
      <div className="sc-grid">
        <label className="sc-field" title="Whose responses are the baseline. Default: worked out per request from its session">
          <span className="label">Owner</span>
          <select className="input" value={f.owner} onChange={(e) => set({ owner: e.target.value })}>
            <option value="">worked out per request</option>
            {profiles.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="sc-field" title="Cookies that aren't credentials and stay on the request, comma-separated">
          <span className="label">Keep cookies</span>
          <input className="input" value={f.keepCookies} placeholder="lang, theme" onChange={(e) => set({ keepCookies: e.target.value })} />
        </label>
        <label className="sc-field" title="Requests per second at most">
          <span className="label">Rate</span>
          <input className="input" value={f.rate} placeholder="no limit (live: 5)" onChange={(e) => set({ rate: e.target.value })} />
        </label>
      </div>
      <div className="sc-field">
        <span className="label">Requests to test</span>
        <div className="row gap">
          <div className="seg">
            {(
              [
                ["all", "All with credentials"],
                ["host", "One site"],
                ["tag", "Tag"],
                ["where", "SQL condition"],
                ...(f.history.length ? ([["history", `From Traffic (${f.history.length})`]] as const) : []),
              ] as const
            ).map(([k, label]) => (
              <button key={k} className={f.select === k ? "on" : ""} onClick={() => set({ select: k })}>
                {label}
              </button>
            ))}
          </div>
          {f.select === "host" && (
            <>
              <input className="input mono" list="az-hosts" value={f.host} placeholder="app.example.com" onChange={(e) => set({ host: e.target.value })} />
              <datalist id="az-hosts">
                {hosts.map((h) => (
                  <option key={h} value={h} />
                ))}
              </datalist>
            </>
          )}
          {f.select === "tag" && <input className="input mono" value={f.tag} placeholder="api" onChange={(e) => set({ tag: e.target.value })} />}
          {f.select === "where" && <input className="input mono az-where" value={f.where} placeholder="host = 'app.example.com' AND path LIKE '/api/%'" onChange={(e) => set({ where: e.target.value })} />}
        </div>
        {f.select !== "history" && (
          <label className="check" title="Stylesheets, scripts, images, fonts, media and source maps, by the response's Content-Type, the browser's Sec-Fetch-Dest or the extension. Usually served to everyone">
            <input type="checkbox" checked={f.includeStatic} onChange={(e) => set({ includeStatic: e.target.checked })} /> Also test static assets
          </label>
        )}
        {f.select === "history" && (
          <div className="az-picked">
            {f.history.map((h) => (
              <div key={h.id} className="mono ellipsis small" title={h.url}>
                #{h.id} <span className="method">{h.method}</span> {h.url}
              </div>
            ))}
            <p className="muted small">
              Tested whatever its method or path, even a logout, and even if it carries no credentials.
              {unsafe.length > 0 && <b> {unsafe.join(", ")} requests are sent again as each identity: they may change data, now as another user.</b>}
              {logouts.length > 0 && <b> {logouts.map((h) => `#${h.id}`).join(", ")} {logouts.length === 1 ? "looks" : "look"} like a logout: sending {logouts.length === 1 ? "it" : "them"} can end the owner's session and each identity's.</b>}
            </p>
          </div>
        )}
      </div>
      <div className="row gap">
        <button className="btn primary" disabled={busy} onClick={start}>
          Start run
        </button>
        <button className="btn" disabled={busy || f.owner !== "" || f.select !== "all"} onClick={onLive} title="Restart the proxy so each request you browse is also tried as these identities">
          Test live while browsing
        </button>
        <span className="muted small">Live testing restarts the proxy (same address and options) and tests in-scope GET requests as they are recorded, leaving out static assets (unless ticked above), skip paths and responses other than 2xx.</span>
      </div>
    </div>
  );
}
