import { run, type Risk } from "../api";
import { useApp } from "../store";
import { usePoll } from "../ui/usePoll";
import { useState } from "react";
import { duration, isLive, progress, stateClass, type Job } from "./Scanner";
import { ApiWizard } from "./ApiWizard";
import { ScanWizard } from "./Wizard";
import { UpdatesCard } from "./Updates";
import { AppUpdateCard } from "./AppUpdate";

const RISKS: Risk[] = ["high", "medium", "low", "info"];

const STATS_SQL = `SELECT count(*) AS requests, count(DISTINCT host) AS hosts, count(DISTINCT host || ':' || port || path) AS paths,
  min(time) AS first, max(time) AS last FROM history`;

const RISK_SQL = `SELECT risk, count(*) AS n FROM findings WHERE state <> 'false_positive' GROUP BY risk`;

const RECENT_SQL = `SELECT id, name, risk, url, param, time FROM findings WHERE state <> 'false_positive' ORDER BY id DESC LIMIT 8`;

export function DashboardView({ active }: { active: boolean }) {
  const app = useApp();
  const [jobs] = usePoll<{ jobs: Job[] }>(() => run(["job", "list", "--limit", "8"]), 3000, active);
  const [byRisk] = usePoll<{ rows: [Risk, number][] }>(() => run(["query", RISK_SQL]), 5000, active);
  const [recent] = usePoll<{ rows: { id: number; name: string; risk: Risk; url: string; param: string; time: string }[] }>(
    () => run(["query", RECENT_SQL, "--shape", "objects"]),
    5000,
    active,
  );
  const [stats] = usePoll<{ rows: { requests: number; hosts: number; paths: number; first: string | null; last: string | null }[] }>(
    () => run(["query", STATS_SQL, "--shape", "objects"]),
    5000,
    active,
  );
  // The guided scan shows by itself until the project has a scan, and again whenever it is opened
  // (Overview > Guided scan, Scans > New scan). It remembers its own scan and a "do it myself"
  // choice per project.
  const key = (k: string) => `wizard-${k}:${app.project}`;
  const stored = (k: string) => {
    try {
      return localStorage.getItem(key(k));
    } catch {
      return null;
    }
  };
  const store = (k: string, v: string) => {
    try {
      localStorage.setItem(key(k), v);
    } catch {
      /* storage unavailable */
    }
  };
  const [wizardJob, setWizardJob] = useState<number | null>(() => Number(stored("job")) || null);
  const [wizardOff, setWizardOff] = useState(() => stored("off") === "1");
  // The guided scan's API flow, in the same slot with the same job id.
  const [apiWizard, setApiWizard] = useState(false);
  // Scans run from the CLI in the foreground leave findings but no job.
  const [activeFindings] = usePoll<{ rows: [number][] }>(() => run(["query", "SELECT count(*) FROM findings WHERE source = 'active'"]), 10000, active);
  const hasScan = jobs?.jobs.some((j) => j.kind === "active-scan" && j.state !== "failed") || (activeFindings?.rows[0]?.[0] ?? 0) > 0;
  const showWizard = wizardJob != null || app.wizardOpen || (jobs != null && activeFindings != null && !hasScan && !wizardOff);

  const s = stats?.rows[0];
  const live = jobs?.jobs.filter(isLive).length ?? 0;
  const hosted = {
    jobId: wizardJob,
    onStarted: (id: number) => {
      setWizardJob(id);
      store("job", String(id));
      app.openWizard(false);
    },
    onDismiss: () => {
      setWizardOff(true);
      setWizardJob(null);
      setApiWizard(false);
      app.openWizard(false);
      store("off", "1");
      store("job", "");
    },
  };
  return (
    <div className="dash">
      {showWizard &&
        (apiWizard ? <ApiWizard {...hosted} onBack={() => setApiWizard(false)} /> : <ScanWizard {...hosted} onApi={() => setApiWizard(true)} />)}
      <AppUpdateCard />
      <UpdatesCard />
      <section className="dash-card">
        <header>
          <span className="label">Issues</span>
          <button className="btn small" onClick={() => app.setTab("findings")}>
            Open Findings
          </button>
        </header>
        <div className="dash-risks">
          {RISKS.map((r) => (
            <button key={r} className="dash-risk" onClick={() => app.setTab("findings")}>
              <span className={`dash-num risk-text-${r}`}>{byRisk?.rows.find((x) => x[0] === r)?.[1] ?? 0}</span>
              <span className="row gap">
                <span className={`dot-risk risk-${r}`} /> {r}
              </span>
            </button>
          ))}
        </div>
        <div className="label dash-sub">Recent</div>
        {recent?.rows.length ? (
          recent.rows.map((f) => (
            <button key={f.id} className="tree-item dash-row" onClick={() => app.setTab("findings")} title={f.url}>
              <span className={`dot-risk risk-${f.risk}`} />
              <span className="ellipsis grow">{f.name}</span>
              <span className="ellipsis muted dash-url">
                {f.url}
                {f.param && ` [${f.param}]`}
              </span>
            </button>
          ))
        ) : (
          <p className="muted">No findings yet.</p>
        )}
      </section>

      <section className="dash-card">
        <header>
          <span className="label">Tasks</span>
          {live > 0 && <span className="count">{live} running</span>}
          {!showWizard && (
            <button className="btn small" onClick={() => app.openWizard(true)} title="Check a website step by step">
              Guided scan
            </button>
          )}
          <button className="btn small" onClick={() => app.setTab("scanner")}>
            Open Scans
          </button>
        </header>
        {jobs?.jobs.length ? (
          jobs.jobs.map((j) => {
            const p = progress(j);
            return (
              <button key={j.id} className="tree-item dash-row" onClick={() => app.setTab("scanner")} title={j.args.join(" ")}>
                <span className="muted">#{j.id}</span>
                <span>{j.kind}</span>
                <span className={stateClass(j.state)}>{j.state}</span>
                <span className="ellipsis grow muted">{p.text}</span>
                <span className="muted">{duration(j)}</span>
              </button>
            );
          })
        ) : (
          <p className="muted">No crawls or scans yet. Start one from Scans.</p>
        )}
      </section>

      <section className="dash-card dash-wide">
        <header>
          <span className="label">History</span>
          <button className="btn small" onClick={() => app.setTab("target")}>
            Open site map
          </button>
        </header>
        <div className="dash-risks">
          <div className="dash-risk">
            <span className="dash-num">{s?.requests ?? 0}</span>
            <span className="muted">requests</span>
          </div>
          <div className="dash-risk">
            <span className="dash-num">{s?.hosts ?? 0}</span>
            <span className="muted">hosts</span>
          </div>
          <div className="dash-risk">
            <span className="dash-num">{s?.paths ?? 0}</span>
            <span className="muted">paths</span>
          </div>
        </div>
        {s?.last && (
          <p className="muted small">
            {new Date(s.first!).toLocaleString()} → {new Date(s.last).toLocaleString()}
          </p>
        )}
      </section>
    </div>
  );
}
