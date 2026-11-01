// "Record a login": log in once in a browser and brainproxy works out the auth profile from
// the recorded traffic (login request, CSRF token, bearer token, logged-in check), then saves
// and tests it. Runs `auth record start` / `auth record finish` and `auth login`.

import { useEffect, useState } from "react";
import { run, withScheme } from "../api";
import { useApp } from "../store";
import { startProxy } from "./proxyPort";
import { loadSuggestions } from "./Scanner";

interface Proposal {
  mode: "replay" | "session";
  recorded: number;
  found: string[];
  warnings: string[];
  profile: {
    login_url?: string;
    username?: string;
    csrf_url?: string;
    token_header?: string;
    check_url?: string;
    logged_in?: string;
    logged_out?: string;
    headers: [string, string][];
  };
}

interface LoginResult {
  login: { success: boolean; reason: string };
}

type Step = "start" | "recording" | "review" | "done";

const nameFor = (url: string) => {
  try {
    return new URL(url).hostname.split(".").filter((p) => p !== "www")[0] || "site";
  } catch {
    return "site";
  }
};

export function RecordLogin(p: { onDone: (name: string) => void; onCancel: () => void }) {
  const app = useApp();
  const [step, setStep] = useState<Step>("start");
  const [site, setSite] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [envVar, setEnvVar] = useState("");
  const [result, setResult] = useState<LoginResult | null>(null);

  useEffect(() => {
    loadSuggestions()
      .then((h) => setSite((s) => s || h.origins[0] || ""))
      .catch(() => {});
  }, []);

  const url = withScheme(site.trim());
  const profileName = name.trim() || nameFor(url);

  const guard = async (f: () => Promise<void>) => {
    setBusy(true);
    try {
      await f();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    setBusy(false);
  };

  const start = () =>
    guard(async () => {
      const status = await run<{ running: boolean }>(["proxy", "status"]);
      if (!status.running) await startProxy(run);
      await run(["auth", "record", "start", url]);
      setStep("recording");
    });

  const analyze = () =>
    guard(async () => {
      setProposal(await run<Proposal>(["auth", "record", "finish", "--", profileName]));
      setStep("review");
    });

  const save = () =>
    guard(async () => {
      const env = envVar.trim() ? [`--password-env=${envVar.trim()}`] : [];
      await run(["auth", "record", "finish", "--save", ...env, "--", profileName]);
      setResult(
        proposal?.mode === "replay"
          ? await run<LoginResult>(["auth", "login", profileName])
          : { login: { success: true, reason: "the recorded session is used as is" } },
      );
      setStep("done");
    });

  const steps: [Step, string][] = [
    ["start", "Site"],
    ["recording", "Log in"],
    ["review", "Review"],
    ["done", "Test"],
  ];
  const at = steps.findIndex(([s]) => s === step);
  const pr = proposal?.profile;
  return (
    <div className="detail record-login">
      <div className="detail-head">
        <h2>Record a login</h2>
        <span className="grow" />
        <button className="link" onClick={p.onCancel}>
          Cancel
        </button>
      </div>
      <ol className="wiz-steps">
        {steps.map(([s, label], i) => (
          <li key={s} className={i === at ? "on" : i < at ? "done" : ""}>
            <span>{i + 1}</span> {label}
          </li>
        ))}
      </ol>

      {step === "start" && (
        <>
          <p className="muted">
            Log in once in a browser, as you normally would. brainproxy records it and works out the rest: the login
            request, any CSRF or bearer token, and how to tell a logged-in page from a logged-out one.
          </p>
          <label className="label">Login page or site</label>
          <input className="input full" value={site} placeholder="https://app.example.com/login" onChange={(e) => setSite(e.target.value)} />
          <label className="label">Profile name</label>
          <input className="input" value={name} placeholder={nameFor(url)} onChange={(e) => setName(e.target.value)} />
          <div className="row gap">
            <button className="btn primary" disabled={busy || !url} onClick={start}>
              {busy ? "Opening…" : "Open browser and record"}
            </button>
          </div>
          <p className="muted small">The browser starts with an empty profile, so an earlier session can't skip the login.</p>
        </>
      )}

      {step === "recording" && (
        <>
          <ol className="record-howto">
            <li>Log in in the browser that just opened.</li>
            <li>Then open one page that only a logged-in user can see (your account, a dashboard).</li>
            <li>Come back here.</li>
          </ol>
          <div className="row gap">
            <button className="btn primary" disabled={busy} onClick={analyze}>
              {busy ? "Looking at the recording…" : "I'm logged in"}
            </button>
            <button className="btn" disabled={busy} onClick={start}>
              Open the browser again
            </button>
          </div>
        </>
      )}

      {step === "review" && proposal && pr && (
        <>
          <p>
            {proposal.mode === "replay"
              ? "brainproxy can log in by itself, and again whenever the session ends."
              : "brainproxy can't replay this login, so the profile carries your current session. Record again when it expires."}
          </p>
          <dl className="facts">
            {pr.login_url && (
              <>
                <dt>Login</dt>
                <dd className="mono">{pr.login_url}</dd>
              </>
            )}
            {pr.username && (
              <>
                <dt>User</dt>
                <dd>{pr.username}</dd>
              </>
            )}
            {pr.csrf_url && (
              <>
                <dt>CSRF token</dt>
                <dd>fetched from <span className="mono">{pr.csrf_url}</span> before each login</dd>
              </>
            )}
            {pr.token_header && (
              <>
                <dt>Token</dt>
                <dd className="mono">{pr.token_header}</dd>
              </>
            )}
            {pr.check_url && (
              <>
                <dt>Logged-in check</dt>
                <dd>
                  <span className="mono">{pr.check_url}</span>
                  {pr.logged_in ? (
                    <>
                      {" "}
                      shows <span className="mono">{pr.logged_in}</span>
                    </>
                  ) : null}
                </dd>
              </>
            )}
            {pr.headers.length > 0 && (
              <>
                <dt>Headers</dt>
                <dd className="mono">{pr.headers.map(([k]) => k).join(", ")}</dd>
              </>
            )}
          </dl>
          {proposal.warnings.length > 0 && (
            <div className="wiz-warn">
              {proposal.warnings.map((w) => (
                <p key={w}>{w}</p>
              ))}
            </div>
          )}
          <details>
            <summary className="muted small">What was found in {proposal.recorded} recorded requests</summary>
            <ul className="small">
              {proposal.found.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </details>
          {proposal.mode === "replay" && (
            <>
              <label className="label">Password</label>
              <input
                className="input"
                value={envVar}
                placeholder="kept in the project file; or an environment variable name"
                onChange={(e) => setEnvVar(e.target.value)}
              />
            </>
          )}
          <div className="row gap">
            <button className="btn primary" disabled={busy} onClick={save}>
              {busy ? "Saving and testing…" : proposal.mode === "replay" ? "Save and test the login" : "Save"}
            </button>
            <button className="btn" disabled={busy} onClick={() => setStep("start")}>
              Record again
            </button>
          </div>
        </>
      )}

      {step === "done" && result && (
        <>
          <p className={result.login.success ? "s2" : "s5"}>
            {result.login.success ? `Profile ${profileName} works: ` : `Saved, but the test login failed: `}
            {result.login.reason}.
          </p>
          <p className="muted small">
            Use it with the Auth profile choice in the guided scan and Scans, or <span className="mono">--auth {profileName}</span>{" "}
            on the command line.
          </p>
          <div className="row gap">
            <button className="btn primary" onClick={() => p.onDone(profileName)}>
              Done
            </button>
            {!result.login.success && (
              <button className="btn" onClick={() => setStep("start")}>
                Record again
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
