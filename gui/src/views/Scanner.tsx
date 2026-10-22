import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { run, withScheme, type Risk } from "../api";
import type { ChecksStatus } from "./Updates";
import { quickCheckArgs } from "./feed";
import { useApp } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";

export interface Job {
  id: number;
  time: string;
  kind: string; // crawl, active-scan, import
  state: string; // queued, running, stopping, completed, stopped, failed
  pid: number | null;
  args: string[];
  progress: Record<string, number> | null;
  error: string | null;
  finished_time: string | null;
  result?: Record<string, any>;
}

export const isLive = (j: Job) => j.state === "queued" || j.state === "running" || j.state === "stopping";

export function duration(j: Job): string {
  const ms = (j.finished_time ? Date.parse(j.finished_time) : Date.now()) - Date.parse(j.time);
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s} s` : s < 3600 ? `${Math.floor(s / 60)} m ${s % 60} s` : `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} m`;
}

/** A one-line progress summary and, when known, a done fraction. */
export function progress(j: Job): { text: string; frac: number | null } {
  const p = j.progress;
  if (!p) return { text: "", frac: null };
  // A crawl-and-audit scan reports crawl progress until the attack phase starts.
  if (j.kind === "active-scan" && p.units == null && p.depth != null)
    return { text: `crawling · depth ${p.depth} · ${p.requests ?? 0} req · ${p.endpoints ?? 0} endpoints`, frac: null };
  if (j.kind === "active-scan")
    return { text: `${p.units_done ?? 0}/${p.units ?? 0} units · ${p.requests ?? 0} req · ${p.raised ?? 0} raised`, frac: p.units ? (p.units_done ?? 0) / p.units : null };
  if (j.kind === "crawl") return { text: `depth ${p.depth ?? 0} · ${p.requests ?? 0} req · ${p.endpoints ?? 0} endpoints · ${p.queued ?? 0} queued`, frac: null };
  return { text: Object.entries(p).map(([k, v]) => `${k} ${v}`).join(" · "), frac: null };
}

export function stateClass(state: string): string {
  return state === "completed" ? "s2" : state === "failed" ? "s5" : state === "stopped" ? "s4" : "s3";
}

export function ScannerView({ active }: { active: boolean }) {
  const app = useApp();
  const [sub, setSub] = useState<"tasks" | "new" | "rules">("tasks");
  const [selected, setSelected] = useState<number | null>(null);
  const [picked, setPicked] = useState(new Set<number>()); // active rules chosen in Rules, used by New scan
  const [finished, setFinished] = useState<Job | null>(null);
  // Polled even when the tab is hidden, so finished scans are noticed anywhere.
  const [jobs, refreshJobs] = usePoll<{ jobs: Job[] }>(() => run(["job", "list", "--limit", "100"]), 2000);
  const seen = useRef<Map<number, string> | null>(null);

  // Toast when a job leaves the running states; jobs first seen after the first poll count as new.
  useEffect(() => {
    if (!jobs) return;
    const primed = seen.current != null;
    seen.current ??= new Map();
    for (const j of jobs.jobs) {
      const before = seen.current.get(j.id) ?? (primed ? "queued" : undefined);
      seen.current.set(j.id, j.state);
      if (before && before !== j.state && !isLive(j)) {
        app.toast(`${j.kind === "crawl" ? "Crawl" : "Scan"} #${j.id} ${j.state}`, j.state === "failed" ? "error" : "info");
        if (j.kind === "active-scan") setFinished(j);
      }
    }
  }, [jobs, app.toast]);

  const launched = (id: number) => {
    refreshJobs();
    setSelected(id);
    setSub("tasks");
  };

  return (
    <div className="col fill">
      <div className="subtabs">
        <button className={sub === "tasks" ? "on" : ""} onClick={() => setSub("tasks")}>
          Tasks
          {!!jobs?.jobs.filter(isLive).length && <span className="count">{jobs.jobs.filter(isLive).length}</span>}
        </button>
        <button className={sub === "new" ? "on" : ""} onClick={() => setSub("new")}>
          New scan
        </button>
        <button className={sub === "rules" ? "on" : ""} onClick={() => setSub("rules")}>
          Rules
        </button>
      </div>
      {finished && (
        <div className="toolbar sc-banner">
          <span>
            Active scan #{finished.id} {finished.state}.
          </span>
          <button
            className="btn small primary"
            onClick={() => {
              setFinished(null);
              app.setTab("findings");
            }}
          >
            View findings
          </button>
          <span className="grow" />
          <button className="icon-btn" onClick={() => setFinished(null)} title="Dismiss">
            ×
          </button>
        </div>
      )}
      <div className="fill" hidden={sub !== "tasks"}>
        <Tasks jobs={jobs?.jobs ?? []} selected={selected} setSelected={setSelected} refresh={refreshJobs} />
      </div>
      <div className="fill" hidden={sub !== "new"}>
        <NewScan picked={picked} onLaunched={launched} />
      </div>
      <div className="fill" hidden={sub !== "rules"}>
        <Rules active={active && sub === "rules"} picked={picked} setPicked={setPicked} />
      </div>
    </div>
  );
}

// ---------------- Tasks ----------------

const JOB_COLUMNS: Column<Job>[] = [
  { key: "id", label: "#", width: 50, value: (j) => j.id, align: "right" },
  { key: "kind", label: "Kind", width: 90, value: (j) => j.kind },
  { key: "state", label: "State", width: 86, value: (j) => j.state, render: (j) => <span className={stateClass(j.state)}>{j.state}</span> },
  {
    key: "progress",
    label: "Progress",
    width: 320,
    value: (j) => progress(j).text,
    render: (j) => {
      const p = progress(j);
      return (
        <span className="row gap">
          {p.frac != null && (
            <span className="sc-bar">
              <span style={{ width: `${Math.round(p.frac * 100)}%` }} />
            </span>
          )}
          <span className="ellipsis">{p.text}</span>
        </span>
      );
    },
  },
  { key: "target", label: "Target", width: 260, value: (j) => j.args.slice(j.kind === "crawl" ? 1 : 2).join(" ") },
  { key: "started", label: "Started", width: 150, value: (j) => j.time, render: (j) => new Date(j.time).toLocaleString() },
  { key: "duration", label: "Duration", width: 80, value: (j) => duration(j), align: "right" },
];

function Tasks(p: { jobs: Job[]; selected: number | null; setSelected: (id: number) => void; refresh: () => void }) {
  const app = useApp();
  const listed = p.jobs.find((j) => j.id === p.selected);
  // The list has no result; fetch it once the job is done (and while it runs, for its progress).
  const [detail, setDetail] = useState<Job | null>(null);
  const key = listed ? `${listed.id}:${listed.state}:${JSON.stringify(listed.progress)}` : "";
  useEffect(() => {
    if (!listed) return setDetail(null);
    let live = true;
    run<Job>(["job", "status", String(listed.id)]).then((d) => live && setDetail(d), () => {});
    return () => {
      live = false;
    };
  }, [key]);

  const stop = async (id: number) => {
    try {
      await run(["job", "stop", String(id)]);
      p.refresh();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const j = detail?.id === p.selected ? detail : listed;
  const prog = j ? progress(j) : null;
  return (
    <Split id="scanner-tasks" dir="col" initial={0.45}>
      <DataTable
        rows={p.jobs}
        columns={JOB_COLUMNS}
        rowKey={(r) => r.id}
        selected={p.selected}
        onSelect={(r) => p.setSelected(r.id)}
        initialSort={{ key: "id", desc: true }}
        empty="No tasks yet. Start a crawl or an active scan from New scan, or right-click a node in the site map."
      />
      {j ? (
        <div className="detail">
          <div className="detail-head">
            <h2>
              {j.kind} #{j.id}
            </h2>
            <span className={stateClass(j.state)}>{j.state}</span>
            <span className="grow" />
            {isLive(j) && (
              <button className="btn small" onClick={() => stop(j.id)} disabled={j.state === "stopping"}>
                Stop
              </button>
            )}
            {j.kind === "active-scan" && !isLive(j) && (
              <button className="btn small primary" onClick={() => app.setTab("findings")}>
                View findings
              </button>
            )}
          </div>
          {prog?.frac != null && (
            <div className="sc-bar wide">
              <span style={{ width: `${Math.round(prog.frac * 100)}%` }} />
            </div>
          )}
          <dl className="facts">
            <dt>Command</dt>
            <dd className="mono">brainproxy {j.args.join(" ")}</dd>
            <dt>Started</dt>
            <dd>
              {new Date(j.time).toLocaleString()} · {duration(j)}
            </dd>
            {prog?.text && (
              <>
                <dt>Progress</dt>
                <dd>{prog.text}</dd>
              </>
            )}
            {j.error && (
              <>
                <dt>Error</dt>
                <dd className="s5">{j.error}</dd>
              </>
            )}
            {j.result && <ResultFacts kind={j.kind} r={j.result} />}
          </dl>
          {j.result && (
            <>
              <h3>Result</h3>
              <pre className="code sc-json">{JSON.stringify(j.result, null, 2)}</pre>
            </>
          )}
        </div>
      ) : (
        <div className="blank">Select a task to see its progress and result.</div>
      )}
    </Split>
  );
}

function ResultFacts({ kind, r }: { kind: string; r: Record<string, any> }) {
  const facts: [string, string][] =
    kind === "active-scan"
      ? [
          ["Targets", `${r.targets} (${r.insertion_points} insertion points, ${r.skipped_out_of_scope} skipped out of scope)`],
          ["Requests", `${r.requests} · ${r.rules} rules`],
          ["New findings", String(r.new_findings)],
        ]
      : kind === "crawl"
        ? [
            ["Requests", `${r.requests} · depth ${r.depth_reached} · ${r.forms_submitted} forms`],
            ["Endpoints", String(r.endpoint_count)],
            ["New findings", String(r.new_findings)],
            ...(r.out_of_scope_hosts?.length ? [["Out of scope", r.out_of_scope_hosts.join(", ")] as [string, string]] : []),
          ]
        : [];
  return (
    <>
      {facts.map(([k, v]) => (
        <Fragment key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </Fragment>
      ))}
      {r.stopped && (
        <>
          <dt>Stopped</dt>
          <dd>{r.timed_out ? "time limit reached" : "yes"}</dd>
        </>
      )}
    </>
  );
}

// ---------------- New scan ----------------

const list = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
/** Seed/target URLs; ones typed without a scheme get one (shown in the command preview). */
const urls = (s: string) => list(s).map(withScheme);
// --flag=value, so a value starting with "-" isn't read as a flag.
const opt = (flag: string, v: string) => (v.trim() ? [`${flag}=${v.trim()}`] : []);
const flag = (f: string, on: boolean) => (on ? [f] : []);

const SCAN_DEFAULTS = {
  urls: "",
  where: "",
  strength: "medium",
  rules: "",
  excludeRules: "",
  checks: "",
  checkTags: "",
  checkSeverity: "",
  auth: "",
  concurrency: "",
  rate: "",
  timeout: "",
  checkTimeout: "",
  maxMinutes: "",
  maxTargets: "",
  injectHeaders: "",
  cookies: false,
  noQuery: false,
  noForm: false,
  noJson: false,
  noRules: false,
  noOob: false,
  http2: false,
  verifyTls: false,
  // crawl
  depth: "",
  maxPages: "",
  pathPrefix: "",
  headers: "",
  subdomains: false,
  noForms: false,
};

/** Sites recorded in history (scheme://host[:port]/, busiest first), excluding scan/fuzz traffic. */
const ORIGINS_SQL = `SELECT scheme || '://' || host ||
    CASE WHEN (scheme = 'http' AND port = 80) OR (scheme = 'https' AND port = 443) THEN '' ELSE ':' || port END || '/',
    count(*)
  FROM history WHERE status IS NOT NULL AND source NOT IN ('scan', 'fuzz')
  GROUP BY 1 ORDER BY 2 DESC LIMIT 20`;

export interface Suggestions {
  scope: string[];
  origins: string[];
  recorded: number;
}

/** What the engagement allows and what was recorded, to prefill targets. */
export async function loadSuggestions(): Promise<Suggestions> {
  const [eng, rows] = await Promise.all([
    run<{ engagement: { include: string[] } | null }>(["engagement", "show"]),
    run<{ rows: [string, number][] }>(["query", ORIGINS_SQL]),
  ]);
  const scope = eng.engagement?.include ?? [];
  let origins = rows.rows.map((r) => r[0]);
  if (!origins.length) {
    // Nothing recorded yet: exact hosts from the scope (wildcards and ranges aren't URLs).
    origins = scope.filter((t) => !t.includes("*") && !t.includes("/")).map((t) => withScheme(t).replace(/\/?$/, "/"));
  }
  return { scope, origins, recorded: rows.rows.reduce((n, r) => n + Number(r[1]), 0) };
}

function NewScan({ picked, onLaunched }: { picked: Set<number>; onLaunched: (id: number) => void }) {
  const app = useApp();
  // `quick:<id>`: a quick check from brainproxy's feed (tagged quick-check).
  const [kind, setKind] = useState<"scan" | "crawl" | "php2shell" | `quick:${string}`>("scan");
  const [f, setF] = useState(SCAN_DEFAULTS);
  const [hints, setHints] = useState<Suggestions | null>(null);
  // Downloaded Nuclei templates join active scans by default (high severity and up).
  const [checksStatus] = usePoll<ChecksStatus>(() => run(["checks", "status"]), 30000);
  const nucleiInstalled = checksStatus?.nuclei ?? null;
  const [useNuclei, setUseNuclei] = useState(true);
  const [nucleiSeverity, setNucleiSeverity] = useState("high");
  const nucleiOn = kind === "scan" && !!nucleiInstalled && useNuclei && !/\b(nuclei|all)\b/.test(f.checks);
  const quickChecks = checksStatus?.brainproxy?.installed?.quick_checks ?? [];
  const quick = kind.startsWith("quick:") ? quickChecks.find((q) => `quick:${q.id}` === kind) ?? null : null;
  // One-click checks: a few requests per site, no crawl.
  const oneClick = kind === "php2shell" || quick != null;
  // A quick check that left the feed falls back to the active scan form.
  useEffect(() => {
    if (kind.startsWith("quick:") && checksStatus && !quick) setKind("scan");
  }, [kind, checksStatus, quick]);
  // Active scan: crawl the listed sites then attack what's found, attack everything already
  // recorded, or attack only the listed URLs.
  const [mode, setMode] = useState<"crawl" | "recorded" | "urls">("crawl");

  useEffect(() => {
    loadSuggestions()
      .then((h) => {
        setHints(h);
        setF((x) => (x.urls ? x : { ...x, urls: h.origins.join("\n") }));
      })
      .catch(() => {});
  }, []);
  const [auth] = usePoll<{ profiles: { name: string }[] }>(() => run(["auth", "list"]), 30000);
  const set = (patch: Partial<typeof SCAN_DEFAULTS>) => setF((x) => ({ ...x, ...patch }));

  // Rules picked in the Rules tab fill the rules field.
  useEffect(() => {
    set({ rules: [...picked].join(",") });
  }, [picked]);

  const args = (): string[] =>
    oneClick
      ? [
          "scan",
          "active",
          ...urls(f.urls),
          ...(quick ? quickCheckArgs(quick.id) : ["--rules=100002"]),
          ...opt("--auth", f.auth),
          ...opt("--concurrency", f.concurrency),
          ...opt("--rate", f.rate),
          ...opt("--timeout", f.timeout),
          ...flag("--http2", f.http2),
          ...flag("--verify-tls", f.verifyTls),
        ]
      : kind === "crawl"
      ? [
          "crawl",
          ...urls(f.urls),
          ...opt("--depth", f.depth),
          ...opt("--max-pages", f.maxPages),
          ...opt("--concurrency", f.concurrency),
          ...opt("--rate", f.rate),
          ...opt("--timeout", f.timeout),
          ...opt("--auth", f.auth),
          ...opt("--path-prefix", f.pathPrefix),
          ...opt("--header", f.headers),
          ...flag("--subdomains", f.subdomains),
          ...flag("--no-forms", f.noForms),
          ...flag("--http2", f.http2),
          ...flag("--verify-tls", f.verifyTls),
        ]
      : [
          "scan",
          "active",
          ...(mode === "recorded" ? [] : urls(f.urls)),
          ...(mode === "crawl" ? ["--crawl"] : []),
          ...opt("--where", f.where),
          `--strength=${f.strength}`,
          ...opt("--rules", f.rules),
          ...opt("--exclude-rules", f.excludeRules),
          ...flag("--no-rules", f.noRules),
          ...opt("--checks", f.checks),
          // End-of-life checks (outdated PHP, nginx, WordPress, ...) whatever the severity chosen.
          ...(nucleiOn ? ["--checks", "nuclei", "--check-include-tags", "eol"] : []),
          ...opt("--check-tags", f.checkTags),
          ...opt("--check-severity", f.checkSeverity || (nucleiOn ? nucleiSeverity : "")),
          ...opt("--auth", f.auth),
          ...opt("--concurrency", f.concurrency),
          ...opt("--rate", f.rate),
          ...opt("--timeout", f.timeout),
          ...opt("--check-timeout", f.checkTimeout),
          ...opt("--max-minutes", f.maxMinutes),
          ...opt("--max-targets", f.maxTargets),
          ...list(f.injectHeaders).map((h) => `--inject-header=${h}`),
          ...flag("--cookies", f.cookies),
          ...flag("--no-query", f.noQuery),
          ...flag("--no-form", f.noForm),
          ...flag("--no-json", f.noJson),
          ...flag("--no-oob", f.noOob),
          ...flag("--http2", f.http2),
          ...flag("--verify-tls", f.verifyTls),
        ];

  const launch = async () => {
    if (kind !== "scan" && !list(f.urls).length)
      return app.toast(kind === "crawl" ? "Give at least one seed URL" : "Give at least one site", "error");
    if (kind === "scan" && mode !== "recorded" && !list(f.urls).length) return app.toast("Give at least one URL, or audit everything recorded", "error");
    try {
      const d = await run<{ job: number }>([...args(), "--background"]);
      app.toast(`${kind === "crawl" ? "Crawl" : quick ? quick.name : kind === "php2shell" ? "PHP2Shell check" : "Active scan"} started (job ${d.job})`);
      onLaunched(d.job);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const text = (label: string, key: keyof typeof SCAN_DEFAULTS, placeholder = "", title?: string) => (
    <label className="sc-field" title={title}>
      <span className="label">{label}</span>
      <input className="input" value={f[key] as string} placeholder={placeholder} onChange={(e) => set({ [key]: e.target.value })} />
    </label>
  );
  const check = (label: string, key: keyof typeof SCAN_DEFAULTS, title?: string) => (
    <label className="check" title={title}>
      <input type="checkbox" checked={f[key] as boolean} onChange={(e) => set({ [key]: e.target.checked })} /> {label}
    </label>
  );

  return (
    <div className="detail sc-form">
      <div className="row gap">
        <div className="seg">
          <button className={kind === "scan" ? "on" : ""} onClick={() => setKind("scan")}>
            Active scan
          </button>
          <button className={kind === "crawl" ? "on" : ""} onClick={() => setKind("crawl")}>
            Crawl
          </button>
          <button className={kind === "php2shell" ? "on" : ""} onClick={() => setKind("php2shell")} title="CVE-2026-109618, CVE-2026-109619">
            PHP2Shell check
          </button>
          {quickChecks.map((q) => (
            <button key={q.id} className={kind === `quick:${q.id}` ? "on" : ""} onClick={() => setKind(`quick:${q.id}`)} title={`${q.id} (brainproxy checks feed)`}>
              {q.name}
            </button>
          ))}
        </div>
        <span className="muted small grow">Runs in the background; every request stays inside the engagement scope.</span>
        <button className="btn small" onClick={() => app.openWizard(true)} title="Opens the step-by-step scan on the Overview">
          Guided scan
        </button>
      </div>
      {hints && hints.scope.length > 0 && (
        <div className="row gap sc-scope">
          <span className="label">Engagement scope</span>
          {hints.scope.map((t) => (
            <span key={t} className="chip">
              {t}
            </span>
          ))}
        </div>
      )}
      {kind === "scan" && (
        <div className="seg sc-mode">
          <button className={mode === "crawl" ? "on" : ""} onClick={() => setMode("crawl")} title="Crawl from the site URLs, then attack every request recorded on those sites">
            Crawl and audit
          </button>
          <button className={mode === "recorded" ? "on" : ""} onClick={() => setMode("recorded")} disabled={!hints?.recorded}>
            Audit everything recorded{hints?.recorded ? ` (${hints.recorded} requests)` : ""}
          </button>
          <button className={mode === "urls" ? "on" : ""} onClick={() => setMode("urls")}>
            Audit specific URLs
          </button>
        </div>
      )}
      {kind === "scan" &&
        (nucleiInstalled ? (
          <div className="row gap sc-nuclei">
            <label className="check">
              <input type="checkbox" checked={useNuclei} onChange={(e) => setUseNuclei(e.target.checked)} /> Include Nuclei templates (
              {nucleiInstalled.stored.toLocaleString()} installed)
            </label>
            {useNuclei && (
              <>
                <span className="muted">severity</span>
                <select className="input" value={nucleiSeverity} onChange={(e) => setNucleiSeverity(e.target.value)}>
                  <option value="high">high and above</option>
                  <option value="medium">medium and above</option>
                  <option value="low">low and above</option>
                  <option value="info">all</option>
                </select>
                <span className="muted small">Lower severities add thousands of requests. End-of-life checks always run.</span>
              </>
            )}
          </div>
        ) : (
          checksStatus && (
            <p className="muted small sc-nuclei">
              Nuclei templates aren't installed, so scans use the built-in rules only.{" "}
              <button className="link" onClick={() => app.setTab("dashboard")}>
                Download them on the Overview
              </button>{" "}
              for about 10,000 extra checks.
            </p>
          )
        ))}
      {kind === "php2shell" && (
        <p className="muted small sc-all">
          Looks for PHP2Shell (CVE-2026-109618, CVE-2026-109619) on each site: a reported PHP version without the fix, or
          PHP that hides its version. A few requests per site; nothing is sent that triggers the bug. Findings are
          suspected, so confirm the PHP version on the server.
        </p>
      )}
      {quick && (
        <p className="muted small sc-all">
          {quick.description || quick.name} From brainproxy's checks feed ({quick.id}); only this check runs on each site.
        </p>
      )}
      {kind !== "scan" || mode !== "recorded" ? (
        <label className="sc-field">
          <span className="label">
            {oneClick
              ? "Sites to check"
              : kind === "crawl" || mode === "crawl"
                ? "Sites to crawl (start URLs)"
                : "URLs to attack (only these requests)"}
            , one per line
          </span>
          <textarea
            className="input code sc-urls"
            value={f.urls}
            onChange={(e) => set({ urls: e.target.value })}
            placeholder={kind === "scan" ? "https://app.example.com/search?q=x" : "https://app.example.com/"}
          />
          {hints && hints.origins.some((o) => !list(f.urls).includes(o)) && (
            <div className="chips">
              <span className="muted small">Add:</span>
              {hints.origins
                .filter((o) => !list(f.urls).includes(o))
                .map((o) => (
                  <button key={o} className="chip in" onClick={() => set({ urls: [...list(f.urls), o].join("\n") })}>
                    + {o}
                  </button>
                ))}
            </div>
          )}
        </label>
      ) : (
        <p className="muted small sc-all">
          Attacks every request recorded for this engagement (proxy, Replay, crawl, imports). Narrow it with the history
          filter below.
        </p>
      )}
      <div className="sc-grid">
        {kind === "scan" ? (
          <>
            {text("History filter (SQL)", "where", "host = 'app.test' AND path LIKE '/api/%'", "Selects history rows to attack")}
            <label className="sc-field">
              <span className="label">Strength</span>
              <select className="input" value={f.strength} onChange={(e) => set({ strength: e.target.value })}>
                {["low", "medium", "high", "insane"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            {text("Only rules", "rules", "40018,40012 (or pick in Rules)")}
            {text("Skip rules", "excludeRules", "comma-separated ids")}
            {text("Checks", "checks", "nuclei, local, all, or a path", "Declarative checks to run as well")}
            {text("Check tags", "checkTags", "cve,exposure")}
            <label className="sc-field">
              <span className="label">Check min severity</span>
              <select className="input" value={f.checkSeverity} onChange={(e) => set({ checkSeverity: e.target.value })}>
                <option value="">any</option>
                {["info", "low", "medium", "high"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            {text("Inject into headers", "injectHeaders", "User-Agent, Referer")}
            {text("Max minutes", "maxMinutes", "no limit")}
            {text("Max targets", "maxTargets", "200")}
          </>
        ) : kind === "crawl" ? (
          <>
            {text("Depth", "depth", "5")}
            {text("Max pages", "maxPages", "500")}
            {text("Path prefix", "pathPrefix", "/app/")}
            {text("Header", "headers", "Cookie: session=…", "Sent with every request; for several, use the CLI")}
          </>
        ) : null}
        <label className="sc-field">
          <span className="label">Auth profile</span>
          <select className="input" value={f.auth} onChange={(e) => set({ auth: e.target.value })}>
            <option value="">none</option>
            {auth?.profiles.map((p) => (
              <option key={p.name}>{p.name}</option>
            ))}
          </select>
        </label>
        {text("Concurrency", "concurrency", "10")}
        {text("Rate (req/s)", "rate", "no limit")}
        {text("Timeout (s)", "timeout", kind === "crawl" ? "15" : "30")}
        {kind === "scan" && text("Template timeout (s)", "checkTimeout", "10")}
      </div>
      <div className="row gap sc-checks">
        {kind === "scan" ? (
          <>
            {check("Inject into cookies", "cookies")}
            {check("Skip query", "noQuery")}
            {check("Skip form bodies", "noForm")}
            {check("Skip JSON bodies", "noJson")}
            {check("Checks only (no rules)", "noRules")}
            {check("No out-of-band", "noOob")}
          </>
        ) : kind === "crawl" ? (
          <>
            {check("Include subdomains", "subdomains")}
            {check("Don't submit forms", "noForms")}
          </>
        ) : null}
        {check("HTTP/2", "http2")}
        {check("Verify TLS", "verifyTls")}
      </div>
      <div className="row gap">
        <button className="btn primary" onClick={launch}>
          Start {kind === "crawl" ? "crawl" : oneClick ? "check" : "scan"}
        </button>
        <button className="btn" onClick={() => setF({ ...SCAN_DEFAULTS, urls: hints?.origins.join("\n") ?? "" })}>
          Reset
        </button>
      </div>
      <pre className="code sc-json muted">brainproxy {args().join(" ")} --background</pre>
    </div>
  );
}

// ---------------- Rules ----------------

interface Rule {
  id: number;
  name: string;
  enabled?: boolean;
  scope?: string;
  max_risk: Risk;
  alerts: { alert_ref: string; name: string; risk: Risk }[];
}

const SOURCES = ["proxy", "send", "crawl", "fuzz", "scan", "import", "auth", "race"];
const RISK_RANK: Record<Risk, number> = { info: 0, low: 1, medium: 2, high: 3 };

function Rules(p: { active: boolean; picked: Set<number>; setPicked: (s: Set<number>) => void }) {
  const app = useApp();
  const [kind, setKind] = useState<"passive" | "active">("passive");
  const [filter, setFilter] = useState("");
  const [passive, refreshPassive] = usePoll<{ rules: Rule[]; sources: string[] }>(() => run(["scan", "rules"]), 15000, p.active);
  const [activeRules] = usePoll<{ rules: Rule[] }>(() => run(["scan", "rules", "--active"]), 60000, p.active);
  const [busy, setBusy] = useState(false);

  const call = async (args: string[]) => {
    try {
      await run(args);
      refreshPassive();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const toggleSource = (s: string) => {
    const cur = new Set(passive?.sources ?? []);
    cur.has(s) ? cur.delete(s) : cur.add(s);
    call(["scan", "sources", ...SOURCES.filter((x) => cur.has(x))]);
  };

  const runPassive = async (rescan: boolean) => {
    setBusy(true);
    try {
      const d = await run<{ scanned: number; new_findings: number }>(["scan", "passive", ...(rescan ? ["--rescan"] : [])]);
      app.toast(`Passive scan: ${d.scanned} captures, ${d.new_findings} new findings`);
    } catch (e: any) {
      app.toast(e.message, "error");
    } finally {
      setBusy(false);
    }
  };

  const rows = useMemo(() => {
    const t = filter.toLowerCase();
    return ((kind === "passive" ? passive?.rules : activeRules?.rules) ?? []).filter((r) => !t || r.name.toLowerCase().includes(t) || String(r.id).includes(t));
  }, [kind, passive, activeRules, filter]);

  const pick = (id: number, on: boolean) => {
    const s = new Set(p.picked);
    on ? s.add(id) : s.delete(id);
    p.setPicked(s);
  };

  const columns: Column<Rule>[] = [
    kind === "passive"
      ? {
          key: "on",
          label: "On",
          width: 40,
          value: (r) => (r.enabled ? 1 : 0),
          render: (r) => <input type="checkbox" checked={!!r.enabled} onChange={(e) => call(["scan", e.target.checked ? "enable" : "disable", String(r.id)])} />,
        }
      : {
          key: "on",
          label: "Use",
          width: 40,
          value: (r) => (p.picked.has(r.id) ? 1 : 0),
          render: (r) => <input type="checkbox" checked={p.picked.has(r.id)} onChange={(e) => pick(r.id, e.target.checked)} />,
        },
    { key: "id", label: "ID", width: 64, value: (r) => r.id, align: "right" },
    { key: "name", label: "Name", width: 340, value: (r) => r.name },
    {
      key: "risk",
      label: "Max risk",
      width: 90,
      value: (r) => RISK_RANK[r.max_risk],
      render: (r) => (
        <span className="row gap">
          <span className={`dot-risk risk-${r.max_risk}`} />
          {r.max_risk}
        </span>
      ),
    },
    ...(kind === "active" ? [{ key: "scope", label: "Scope", width: 70, value: (r: Rule) => r.scope ?? "" }] : []),
    { key: "alerts", label: "Alerts", width: 300, value: (r) => r.alerts.map((a) => a.alert_ref).join(", ") },
  ];

  return (
    <div className="col fill">
      <div className="toolbar">
        <div className="seg">
          <button className={kind === "passive" ? "on" : ""} onClick={() => setKind("passive")}>
            Passive
          </button>
          <button className={kind === "active" ? "on" : ""} onClick={() => setKind("active")}>
            Active
          </button>
        </div>
        <input className="input" style={{ width: 200 }} placeholder="Filter: name or id" value={filter} onChange={(e) => setFilter(e.target.value)} />
        {kind === "passive" ? (
          <>
            <span className="sep" />
            <span className="muted">Scan traffic from</span>
            <div className="seg">
              {SOURCES.map((s) => (
                <button key={s} className={passive?.sources.includes(s) ? "on" : ""} onClick={() => toggleSource(s)}>
                  {s}
                </button>
              ))}
            </div>
            <span className="grow" />
            <button className="btn" disabled={busy} onClick={() => runPassive(false)}>
              Run passive scan now
            </button>
            <button className="btn" disabled={busy} onClick={() => window.confirm("Delete passive findings and rescan all history?") && runPassive(true)}>
              Rescan all
            </button>
          </>
        ) : (
          <>
            <span className="grow" />
            <span className="muted">{p.picked.size ? `${p.picked.size} picked for the next scan` : "Tick rules to limit the next scan to them"}</span>
            {p.picked.size > 0 && (
              <button className="btn small" onClick={() => p.setPicked(new Set())}>
                Clear
              </button>
            )}
          </>
        )}
      </div>
      <DataTable rows={rows} columns={columns} rowKey={(r) => r.id} initialSort={{ key: "id", desc: false }} empty="No rules match." />
    </div>
  );
}
