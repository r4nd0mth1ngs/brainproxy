// Guided scan for people who don't live in HTTP: what to test, login, how thorough, then a
// crawl-and-audit scan with progress and results explained in plain words. Shown on the
// Overview until the project has a scan, and whenever Guided scan opens it.

import { useEffect, useState } from "react";
import { run, withScheme, type Risk } from "../api";
import { useApp } from "../store";
import { usePoll } from "../ui/usePoll";
import { loadSuggestions, type Job, type Suggestions } from "./Scanner";
import { hasChromium, wizardBrowserArgs, type BrowserList } from "./browserCrawl";
import type { ChecksStatus } from "./Updates";

type Depth = "quick" | "standard" | "thorough";

/** Nuclei templates per depth when installed (none for Quick: thousands of extra requests). */
const NUCLEI: Record<Depth, string[]> = {
  quick: [],
  // Plus the end-of-life checks (outdated PHP, nginx, WordPress, ...), which are rated info.
  standard: ["--checks", "nuclei,brainproxy", "--check-severity", "high", "--check-include-tags", "eol"],
  thorough: ["--checks", "nuclei,brainproxy", "--check-severity", "medium", "--check-include-tags", "eol"],
};

const DEPTHS: { id: Depth; title: string; time: string; text: string; args: string[] }[] = [
  {
    id: "quick",
    title: "Quick check",
    time: "a few minutes",
    text: "Explores the main pages and tries the most common attacks with few requests.",
    // Medium, not low: low strength skips the SQL injection payloads that matter most.
    args: ["--strength", "medium", "--crawl-depth", "3", "--crawl-max-pages", "150"],
  },
  {
    id: "standard",
    title: "Standard",
    time: "about 5 to 20 minutes",
    text: "A balanced scan of the whole site. Good for a first assessment.",
    args: ["--strength", "high", "--crawl-depth", "5", "--crawl-max-pages", "500", "--cookies"],
  },
  {
    id: "thorough",
    title: "Thorough",
    time: "30 minutes or more",
    text: "Goes deeper and tries many more attack variations. Sends a lot of requests.",
    args: ["--strength", "insane", "--crawl-depth", "8", "--crawl-max-pages", "1500", "--cookies"],
  },
];

type Speed = "gentle" | "normal" | "fast";

/** Requests in flight at once. More only helps when the site keeps up, and it is louder. */
const SPEEDS: { id: Speed; title: string; text: string; args: string[]; danger?: boolean }[] = [
  { id: "gentle", title: "Gentle", text: "For fragile or shared sites. Slower.", args: ["-c", "3"] },
  { id: "normal", title: "Normal", text: "Suits most sites.", args: [] },
  {
    id: "fast",
    title: "Fast",
    text: "Not recommended. Can overload the site and disrupt it for real users. Only for test servers you can afford to take down.",
    args: ["-c", "30"],
    danger: true,
  },
];

const RISK_TEXT: Record<Risk, string> = {
  high: "Serious: could let an attacker steal data or take over accounts. Fix these first.",
  medium: "Important weaknesses that make attacks easier. Plan fixes soon.",
  low: "Minor issues and missing hardening. Fix when convenient.",
  info: "Observations, not problems on their own.",
};

const RISK_SQL = `SELECT risk, count(*) FROM findings WHERE state <> 'false_positive' GROUP BY risk`;

export function ScanWizard(p: { jobId: number | null; onStarted: (id: number) => void; onDismiss: () => void }) {
  const app = useApp();
  const [step, setStep] = useState(0);
  const [hints, setHints] = useState<Suggestions | null>(null);
  const [site, setSite] = useState("");
  const [login, setLogin] = useState<string>(""); // "" = no login, else an auth profile
  const [depth, setDepth] = useState<Depth>("standard");
  const [speed, setSpeed] = useState<Speed>("normal");
  const [busy, setBusy] = useState(false);
  const [checks] = usePoll<ChecksStatus>(() => run(["checks", "status"]), 30000);
  // brainproxy's feed checks join Standard and Thorough even without the Nuclei templates.
  const nuclei = checks?.nuclei ? NUCLEI[depth] : depth === "quick" ? [] : ["--checks", "brainproxy", "--check-severity", depth === "standard" ? "high" : "medium"];
  // Thorough also crawls in a browser that runs the site's JavaScript, when one is installed.
  const [browsers] = usePoll<BrowserList>(() => run(["browser", "list"]), 60000);
  const canBrowse = hasChromium(browsers);
  const [profiles] = usePoll<{ profiles: { name: string; session?: { logged_in?: boolean } }[] }>(() => run(["auth", "list"]), 10000);

  useEffect(() => {
    loadSuggestions()
      .then((h) => {
        setHints(h);
        // Only prefill a site that was actually seen; a scope host alone doesn't say http/https or the port.
        if (h.recorded > 0) setSite((s) => s || h.origins[0] || "");
      })
      .catch(() => {});
  }, []);

  const url = withScheme(site.trim());
  const [checking, setChecking] = useState(false);
  const [problem, setProblem] = useState("");

  // Step 1 -> 2: make sure the address answers before anything else is set up.
  const checkSite = async () => {
    setChecking(true);
    setProblem("");
    try {
      const r = await run<{ response: { status: number } | null }>(["send", `--url=${url}`, "--timeout=10"]);
      if (r.response) setStep(1);
      else setProblem("The site didn't send a response.");
    } catch (e: any) {
      setProblem(
        e.kind === "out_of_scope"
          ? `${url} is outside this project's approved scope (${hints?.scope.join(", ")}). Use an address inside it.`
          : `Couldn't reach ${url}: ${e.message.replace(/^[a-z ]+: /, "")}. Check the address: does it start with http:// or https://, and does it need a port such as :8080?`,
      );
    }
    setChecking(false);
  };

  const start = async () => {
    setBusy(true);
    try {
      const depthArgs = DEPTHS.find((d) => d.id === depth)!.args;
      const d = await run<{ job: number }>(["scan", "active", url, "--crawl", ...depthArgs, ...wizardBrowserArgs(depth, canBrowse), ...SPEEDS.find((s) => s.id === speed)!.args, ...nuclei, ...(login ? [`--auth=${login}`] : []), "--background"]);
      p.onStarted(d.job);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    setBusy(false);
  };

  // After every hook above: the hook count must not change between renders.
  if (p.jobId != null) return <WizardProgress jobId={p.jobId} onClose={p.onDismiss} />;

  const steps = ["Website", "Login", "Depth", "Start"];
  return (
    <section className="dash-card wizard">
      <header>
        <div>
          <div className="wiz-kicker">Guided scan</div>
          <h2>Check a website for security problems</h2>
        </div>
        <button className="link" onClick={p.onDismiss}>
          I'll set it up myself
        </button>
      </header>
      <ol className="wiz-steps">
        {steps.map((s, i) => (
          <li key={s} className={i === step ? "on" : i < step ? "done" : ""}>
            <span>{i < step ? "✓" : i + 1}</span>
            {s}
          </li>
        ))}
      </ol>

      {step === 0 && (
        <div className="wiz-body">
          <label className="label">Which website should we test?</label>
          <input
            className="input full wiz-input"
            placeholder={hints?.scope[0] && !hints.scope[0].includes("*") ? `e.g. http://${hints.scope[0]}/  (the address you open in a browser)` : "https://www.example.com"}
            value={site}
            onChange={(e) => {
              setSite(e.target.value);
              setProblem("");
            }}
            onKeyDown={(e) => e.key === "Enter" && url && checkSite()}
            autoFocus
          />
          {problem && <div className="wiz-problem">{problem}</div>}
          {hints && hints.recorded > 0 && hints.origins.length > 1 && (
            <div className="chips">
              {hints.origins.map((o) => (
                <button key={o} className={`chip ${o === site ? "in" : ""}`} onClick={() => setSite(o)}>
                  {o}
                </button>
              ))}
            </div>
          )}
          <p className="muted">
            We start from this address and follow its links and forms. Only addresses in this project's approved scope
            {hints?.scope.length ? ` (${hints.scope.join(", ")})` : ""} are ever contacted.
          </p>
        </div>
      )}

      {step === 1 && (
        <div className="wiz-body">
          <label className="label">Do you need to log in to use the parts you want tested?</label>
          <div className="wiz-choices">
            <button className={`wiz-choice ${login === "" ? "on" : ""}`} onClick={() => setLogin("")}>
              <b>No, test what anyone can see</b>
              <span>Public pages, forms, and search. A good start.</span>
            </button>
            {profiles?.profiles.map((pr) => (
              <button key={pr.name} className={`wiz-choice ${login === pr.name ? "on" : ""}`} onClick={() => setLogin(pr.name)}>
                <b>Yes, log in as "{pr.name}"</b>
                <span>{pr.session?.logged_in ? "Session is active." : "Logs in automatically during the scan."}</span>
              </button>
            ))}
          </div>
          <p className="muted">
            To test logged-in pages you need a login profile.{" "}
            <button className="link" onClick={() => app.setTab("settings")}>
              Create one in Settings → Auth profiles
            </button>
            , then come back.
          </p>
        </div>
      )}

      {step === 2 && (
        <div className="wiz-body">
          <label className="label">How thorough should it be?</label>
          <div className="wiz-choices three">
            {DEPTHS.map((d) => (
              <button key={d.id} className={`wiz-choice ${depth === d.id ? "on" : ""}`} onClick={() => setDepth(d.id)}>
                <b>{d.title}</b>
                <span className="wiz-time">{d.time}</span>
                <span>{d.text}</span>
                {d.id === "thorough" && canBrowse && <span>Also opens the site in a hidden browser to find pages built by JavaScript.</span>}
              </button>
            ))}
          </div>
          <label className="label">How hard may it push the site?</label>
          <div className="wiz-choices three">
            {SPEEDS.map((s) => (
              <button key={s.id} className={`wiz-choice ${speed === s.id ? "on" : ""} ${s.danger ? "danger" : ""}`} onClick={() => setSpeed(s.id)}>
                <b>{s.title}</b>
                <span>{s.text}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="wiz-body">
          <label className="label">Ready to start</label>
          <dl className="facts">
            <dt>Website</dt>
            <dd className="mono">{url}</dd>
            <dt>Login</dt>
            <dd>{login ? `as "${login}"` : "none (public pages only)"}</dd>
            <dt>Depth</dt>
            <dd>
              {DEPTHS.find((d) => d.id === depth)!.title} ({DEPTHS.find((d) => d.id === depth)!.time})
            </dd>
            <dt>Speed</dt>
            <dd className={speed === "fast" ? "s5" : ""}>{SPEEDS.find((s) => s.id === speed)!.title}</dd>
            {wizardBrowserArgs(depth, canBrowse).length > 0 && (
              <>
                <dt>JavaScript</dt>
                <dd>runs in a hidden browser that clicks through the site (logout and delete buttons are left alone)</dd>
              </>
            )}
            <dt>Extra checks</dt>
            <dd>
              {!checks?.nuclei
                ? "none (download the Nuclei templates on the Overview for thousands more)"
                : nuclei.length
                  ? `Nuclei templates, ${nuclei[3]} severity and above, plus end-of-life checks`
                  : "none (Quick skips the Nuclei templates)"}
            </dd>
          </dl>
          {speed === "fast" && (
            <div className="wiz-warn danger">
              <b>Fast can take the site down.</b> It sends up to 30 requests at once with no pause. Use it only on a test
              server you can afford to disrupt, never on a production or shared site.
            </div>
          )}
          <div className="wiz-warn replay">
            <b>Forms and other POST requests are replayed.</b> Whatever the scan finds is sent again with attack data,
            often many times, and that can change data or trigger side effects: one contact form can send a lot of
            emails.
          </div>
          <div className="wiz-warn">
            The scan sends real attack requests, as an attacker would. It can create test data or slow down a fragile
            site. Prefer a test environment, and only scan systems you have permission to
            test.
          </div>
        </div>
      )}

      <footer className="row gap">
        {step > 0 && (
          <button className="btn" onClick={() => setStep(step - 1)}>
            Back
          </button>
        )}
        <span className="grow" />
        {step < 3 ? (
          <button className="btn primary" disabled={(step === 0 && !url) || checking} onClick={() => (step === 0 ? checkSite() : setStep(step + 1))}>
            {checking ? "Checking the site…" : "Next"}
          </button>
        ) : (
          <button className="btn primary" disabled={busy || !url} onClick={start}>
            {busy ? "Starting…" : "Start scan"}
          </button>
        )}
      </footer>
    </section>
  );
}

/** The wizard's scan as it runs, then what it found, in plain words. */
function WizardProgress({ jobId, onClose }: { jobId: number; onClose: () => void }) {
  const app = useApp();
  const [job] = usePoll<Job>(() => run(["job", "status", String(jobId)]), 1500);
  const done = job != null && !["queued", "running", "stopping"].includes(job.state);
  const [risks] = usePoll<{ rows: [Risk, number][] }>(() => run(["query", RISK_SQL]), 3000, done);
  const pr = job?.progress ?? {};
  const testing = pr.units != null;
  const frac = testing && pr.units ? (pr.units_done ?? 0) / pr.units : null;
  const count = (r: Risk) => risks?.rows.find((x) => x[0] === r)?.[1] ?? 0;

  return (
    <section className="dash-card wizard">
      <header>
        <div>
          <div className="wiz-kicker">Guided scan</div>
          <h2>{!job ? "Starting…" : !done ? (testing ? "Testing for vulnerabilities…" : "Exploring the website…") : job.state === "completed" ? "Scan finished" : `Scan ${job.state}`}</h2>
        </div>
        {!done && job && (
          <button className="btn" onClick={() => run(["job", "stop", String(jobId)]).catch((e) => app.toast(e.message, "error"))}>
            Stop
          </button>
        )}
        {done && (
          <button className="link" onClick={onClose}>
            Close
          </button>
        )}
      </header>
      {!done ? (
        <div className="wiz-body">
          <div className="wiz-bar">
            <span style={{ width: frac == null ? "100%" : `${Math.round(frac * 100)}%` }} className={frac == null ? "indeterminate" : ""} />
          </div>
          <p className="muted">
            {testing
              ? `Trying attacks on what was found: ${pr.units_done ?? 0} of ${pr.units} checks done, ${pr.requests ?? 0} requests sent${pr.raised ? `, ${pr.raised} possible problem${pr.raised === 1 ? "" : "s"} so far` : ""}.`
              : `Following links and forms to map the site: ${pr.requests ?? 0} pages visited, ${pr.endpoints ?? 0} distinct pages and forms found.`}
          </p>
          <p className="muted small">You can use other tools meanwhile; the scan keeps running in the background.</p>
        </div>
      ) : job?.state === "failed" ? (
        <div className="wiz-body">
          <div className="error">{job.error}</div>
        </div>
      ) : (
        <div className="wiz-body wiz-done">
          <div className="wiz-results">
            {(["high", "medium", "low", "info"] as Risk[]).map((r) => (
              <div key={r} className="wiz-result">
                <span className={`dash-num risk-text-${r}`}>{count(r)}</span>
                <div>
                  <b className="wiz-risk">
                    <span className={`dot-risk risk-${r}`} /> {r}
                  </b>
                  <span className="muted small">{RISK_TEXT[r]}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="row gap wiz-next">
            <button className="btn primary" onClick={() => app.setTab("findings")}>
              Review the findings
            </button>
            <span className="muted small">
              Each finding explains the problem, shows the evidence, and suggests a fix. Mark the ones that aren't real as
              false positives.
            </span>
          </div>
        </div>
      )}
    </section>
  );
}
