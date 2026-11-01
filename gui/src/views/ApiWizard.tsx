// Guided scan of an API: import its definition, choose the server, optionally set up a key or a
// signer, tick the operations, then a `scan active --api` job. Hosted where the website wizard
// is. The logic is in apiScan.ts; this file holds the screens and the CLI calls.

import { useEffect, useRef, useState } from "react";
import { bodyText, inTauri, run, type HistoryEntry } from "../api";
import { useApp } from "../store";
import { loadSuggestions } from "./Scanner";
import { SignerBuilder } from "./SessionHandling";
import { PostWarning, SPEEDS, WizardProgress, type Speed } from "./Wizard";
import {
  EMPTY_AUTH,
  EMPTY_TARGET,
  apiDepthText,
  apiSpeedText,
  authProblems,
  authProfile,
  authSummary,
  baseUrlProblem,
  checkArgs,
  checkMeaning,
  credentialOnRequest,
  credentialText,
  defaultProfileName,
  defaultSelection,
  likelyInScope,
  defaultTarget,
  dropOptIn,
  excludedText,
  filterOperations,
  formatLabel,
  hostLabel,
  hostScopeText,
  includeMethods,
  keyAddArgs,
  keyDefaults,
  keyEnv,
  keyKindDefaults,
  keyProblems,
  listWords,
  methodSummary,
  newSignerForm,
  newSignerProblems,
  operationCount,
  operationOrigins,
  optInMethods,
  pickCheckOperation,
  previewArgs,
  previewTitle,
  scanArgs,
  scrubSecret,
  selectShown,
  selectionProblems,
  sendsPost,
  sendsStateChanging,
  serverProblems,
  serverSummary,
  signRuleArgs,
  signerCoverage,
  signerFormOrigins,
  signerHome,
  signerOnRequest,
  signingSummary,
  sourceKind,
  sourceProblem,
  targetArgs,
  tickable,
  variableInputs,
  type ApiOperation,
  type ApiPreview,
  type ApiTarget,
  type AuthState,
  type KeyKind,
} from "./apiScan";
import { signerAddArgs, signerLabel, signerProblems, type SessionRule, type Signer, type SignerForm } from "./sessionRules";
import { DEPTHS, attacksPaths, type Depth } from "./wizardDepths";

const FILTERS = [{ name: "API definition", extensions: ["json", "yaml", "yml"] }];

/** A definition file's path; null if cancelled. */
async function chooseFile(): Promise<string | null> {
  if (inTauri) {
    const dialog = await import("@tauri-apps/plugin-dialog");
    const p = await dialog.open({ filters: FILTERS, multiple: false });
    return typeof p === "string" ? p : null;
  }
  return window.prompt("Path of the API definition (full path):")?.trim() || null;
}

interface Props {
  jobId: number | null;
  onStarted: (id: number) => void;
  onDismiss: () => void;
  /** Back to the website guided scan. */
  onBack: () => void;
}

const STEPS = ["Definition", "Server", "Authentication", "Operations", "Depth and start"];

export function ApiWizard(p: Props) {
  const [step, setStep] = useState(0);
  const [typed, setTyped] = useState("");
  // What the preview below is of. `typed` can move on from it.
  const [source, setSource] = useState("");
  const [preview, setPreview] = useState<ApiPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [problem, setProblem] = useState("");
  const [docChanged, setDocChanged] = useState(false);
  const [target, setTarget] = useState<ApiTarget>(EMPTY_TARGET);
  const [customBase, setCustomBase] = useState(false);
  const [previewedKey, setPreviewedKey] = useState("");
  const [scope, setScope] = useState<string[]>([]);
  const [auth, setAuth] = useState<AuthState>(EMPTY_AUTH);
  const [signerDraft, setSignerDraft] = useState<SignerForm | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [optIn, setOptIn] = useState(false);
  const [depth, setDepth] = useState<Depth>("standard");
  const [speed, setSpeed] = useState<Speed>("normal");
  const [busy, setBusy] = useState(false);
  const [startProblem, setStartProblem] = useState("");
  const seq = useRef(0);

  useEffect(() => {
    loadSuggestions()
      .then((h) => setScope(h.scope))
      .catch(() => {});
  }, []);

  const keyOf = (src: string, t: ApiTarget) => JSON.stringify(previewArgs(src, t));

  /** Runs the preview. A new source starts the flow over; a new server keeps the choices made before it. */
  const load = async (src: string, t: ApiTarget | null) => {
    const n = ++seq.current;
    setPreviewing(true);
    setProblem("");
    try {
      const d = await run<ApiPreview>(previewArgs(src, t ?? EMPTY_TARGET));
      if (n !== seq.current) return;
      setSelected(defaultSelection(d.requests));
      setOptIn(false);
      if (t) {
        if (preview && d.document_sha256 !== preview.document_sha256) setDocChanged(true);
        // A saved query key may only go to the origins it was saved for: a new server needs it saved again.
        const inScopeOrigins = (x: ApiPreview) => operationOrigins(likelyInScope(x.requests)).join(" ");
        if (preview && inScopeOrigins(d) !== inScopeOrigins(preview)) setAuth((a) => (a.savedProfile && a.place === "query" ? { ...a, savedProfile: "", profileName: "" } : a));
        // A variable gave the definition its address, so no base URL is needed after all.
        if (preview?.base_url_required && !d.base_url_required && !t.baseUrl.trim()) setCustomBase(false);
        setPreviewedKey(keyOf(src, t));
      } else {
        const first = defaultTarget(d);
        setSource(src);
        setTarget(first);
        setCustomBase(d.base_url_required);
        setPreviewedKey(keyOf(src, first));
        setDocChanged(false);
        setAuth({ ...EMPTY_AUTH, ...keyDefaults(d.credentials) });
        setSignerDraft(null);
      }
      setPreview(d);
    } catch (e: any) {
      if (n !== seq.current) return;
      if (t) setPreviewedKey(keyOf(src, t));
      else setPreview(null);
      setProblem(e.kind === "out_of_scope" ? `That address is outside this project's approved scope${scope.length ? ` (${scope.join(", ")})` : ""}, so it wasn't fetched. ${e.message}` : e.message);
    }
    if (n === seq.current) setPreviewing(false);
  };

  // The Server step: previews again shortly after a change.
  const previewStale = !!preview && step === 1 && keyOf(source, target) !== previewedKey;
  // Until a base URL, or a variable that may give the address, is typed.
  const noBase = customBase && !target.baseUrl.trim() && !Object.values(target.vars).some(Boolean);
  const previewWaits = previewStale && !noBase && !baseUrlProblem(target.baseUrl);
  useEffect(() => {
    if (!previewWaits) return;
    const timer = setTimeout(() => load(source, target), 600);
    return () => clearTimeout(timer);
  }, [previewWaits, target]);

  const browse = async () => {
    try {
      const f = await chooseFile();
      if (!f) return;
      setTyped(f);
      const bad = sourceProblem(f);
      // A local file sends nothing, so it's previewed straight away.
      if (bad) setProblem(bad);
      else await load(f, null);
    } catch (e: any) {
      setProblem(String(e.message ?? e));
    }
  };

  const start = async () => {
    if (!preview) return;
    setBusy(true);
    setStartProblem("");
    try {
      const d = await run<{ job: number }>(
        scanArgs({
          source,
          sha256: preview.document_sha256,
          target,
          operations: preview.requests,
          selected,
          profile: authProfile(auth),
          depth,
          speedArgs: SPEEDS.find((s) => s.id === speed)!.args,
        }),
      );
      p.onStarted(d.job);
    } catch (e: any) {
      setStartProblem(e.message);
    }
    setBusy(false);
  };

  // After every hook above: the hook count must not change between renders.
  if (p.jobId != null) return <WizardProgress jobId={p.jobId} onClose={p.onDismiss} />;

  const previewed = !!preview && source === typed.trim();
  const blockers: string[] =
    !preview
      ? []
      : step === 1
        ? noBase
          ? ["Give the base URL."]
          : serverProblems(preview, target, scope)
        : step === 2
          ? authProblems(auth)
          : step === 3
            ? selectionProblems(selected)
            : [];
  const canGoOn = step === 0 ? previewed && !previewing : !previewing && !previewStale && !problem && blockers.length === 0;

  return (
    <section className="dash-card wizard">
      <header>
        <div>
          <div className="wiz-kicker">Guided scan</div>
          <h2>Check an API for security problems</h2>
        </div>
        <div className="wiz-row">
          <button className="link" onClick={p.onBack}>
            Test a website instead
          </button>
          <button className="link" onClick={p.onDismiss}>
            I'll set it up myself
          </button>
        </div>
      </header>
      <ol className="wiz-steps">
        {STEPS.map((s, i) => (
          <li key={s} className={i === step ? "on" : i < step ? "done" : ""}>
            <span>{i < step ? "✓" : i + 1}</span>
            {s}
          </li>
        ))}
      </ol>

      {step === 0 && (
        <DefinitionStep typed={typed} setTyped={setTyped} previewing={previewing} problem={problem} clearProblem={() => setProblem("")} preview={previewed ? preview : null} browse={browse} fetch={() => load(typed.trim(), null)} scope={scope} />
      )}
      {step === 1 && preview && (
        <ServerStep
          preview={preview}
          target={target}
          setTarget={setTarget}
          customBase={customBase}
          setCustomBase={setCustomBase}
          scope={scope}
          busy={previewing || previewWaits}
          problem={problem}
          docChanged={docChanged}
          blockers={blockers}
        />
      )}
      {step === 2 && preview && (
        <AuthStep preview={preview} source={source} target={target} selected={selected} auth={auth} setAuth={setAuth} draft={signerDraft} setDraft={setSignerDraft} />
      )}
      {step === 3 && preview && <OperationsStep operations={preview.requests} truncated={preview.requests_truncated} selected={selected} setSelected={setSelected} optIn={optIn} setOptIn={setOptIn} />}
      {step === 4 && preview && (
        <StartStep preview={preview} source={source} target={target} auth={auth} selected={selected} depth={depth} setDepth={setDepth} speed={speed} setSpeed={setSpeed} problem={startProblem} />
      )}

      {step > 1 && blockers.length > 0 && (
        <div className="wiz-body">
          {blockers.map((b) => (
            <div key={b} className="wiz-problem">
              {b}
            </div>
          ))}
        </div>
      )}

      <footer className="row gap">
        {step > 0 && (
          <button className="btn" onClick={() => setStep(step - 1)}>
            Back
          </button>
        )}
        <span className="grow" />
        {step < STEPS.length - 1 ? (
          <button className="btn primary" disabled={!canGoOn} onClick={() => setStep(step + 1)}>
            {step === 1 && (previewing || previewWaits) ? "Checking…" : "Next"}
          </button>
        ) : (
          <button className="btn primary" disabled={busy || !selected.length} onClick={start}>
            {busy ? "Starting…" : "Start scan"}
          </button>
        )}
      </footer>
    </section>
  );
}

function DefinitionStep(p: {
  typed: string;
  setTyped: (s: string) => void;
  previewing: boolean;
  problem: string;
  clearProblem: () => void;
  preview: ApiPreview | null;
  browse: () => void;
  fetch: () => void;
  scope: string[];
}) {
  const text = p.typed.trim();
  const isUrl = !!text && sourceKind(text) === "url";
  const bad = text ? sourceProblem(text) : "";
  const d = p.preview;
  return (
    <div className="wiz-body">
      <label className="label">Which API definition should we use?</label>
      <div className="wiz-row">
        <button className="btn" disabled={p.previewing} onClick={p.browse}>
          Choose a file…
        </button>
        <input
          className="input wiz-input"
          placeholder="or paste a URL, e.g. https://api.example.com/openapi.json"
          value={p.typed}
          spellCheck={false}
          onChange={(e) => {
            p.setTyped(e.target.value);
            p.clearProblem();
          }}
          onKeyDown={(e) => e.key === "Enter" && text && !bad && p.fetch()}
        />
        <button className="btn" disabled={!text || !!bad || p.previewing} onClick={p.fetch}>
          {p.previewing ? "Reading…" : isUrl ? "Fetch and preview" : "Preview"}
        </button>
      </div>
      {bad && <div className="wiz-problem">{bad}</div>}
      {p.problem && <div className="wiz-problem">{p.problem}</div>}
      <p className="muted">
        OpenAPI, Swagger and Postman files. Previewing a file sends nothing.{" "}
        {isUrl
          ? `Previewing this URL fetches it from here right away, and only if it's inside this project's approved scope${p.scope.length ? ` (${p.scope.join(", ")})` : ""}.`
          : "A URL is fetched as soon as you preview it, and only if it's inside this project's approved scope."}
      </p>
      {d && (
        <>
          <dl className="facts">
            <dt>Definition</dt>
            <dd>
              {previewTitle(d)} ({formatLabel(d.format)})
            </dd>
            <dt>Operations</dt>
            <dd>{d.built}</dd>
            {d.requests_truncated && (
              <>
                <dt>Listed</dt>
                <dd>Only the first {d.requests.length} can be chosen. The rest won't be sent.</dd>
              </>
            )}
          </dl>
          <SkippedList preview={d} />
        </>
      )}
    </div>
  );
}

function SkippedList({ preview: d }: { preview: ApiPreview }) {
  return (
    <>
      {d.skipped.length > 0 && (
        <div className="wiz-warn replay">
          <b>
            {d.skipped.length} operation{d.skipped.length === 1 ? "" : "s"} can't be sent.
          </b>
          <ul className="wiz-list">
            {d.skipped.map((s, i) => (
              <li key={i}>
                <span className="mono">{s.operation}</span>: {s.reason}
              </li>
            ))}
          </ul>
        </div>
      )}
      {d.warnings.length > 0 && (
        <div className="wiz-warn replay">
          <ul className="wiz-list">
            {d.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

function ServerStep(p: {
  preview: ApiPreview;
  target: ApiTarget;
  setTarget: (t: ApiTarget) => void;
  customBase: boolean;
  setCustomBase: (on: boolean) => void;
  scope: string[];
  busy: boolean;
  problem: string;
  docChanged: boolean;
  blockers: string[];
}) {
  const d = p.preview;
  const t = p.target;
  const vars = variableInputs(d, t.vars);
  const useServer = (server: number | null) => {
    p.setCustomBase(false);
    p.setTarget({ ...t, server, baseUrl: "" });
  };
  return (
    <div className="wiz-body">
      <label className="label">Where is the API?</label>
      <div className="wiz-choices">
        {d.servers.map((s) => (
          <button key={s.index} className={`wiz-choice ${!p.customBase && t.server === s.index ? "on" : ""}`} onClick={() => useServer(s.index)}>
            <b className="mono">{s.url}</b>
            {s.description && <span>{s.description}</span>}
          </button>
        ))}
        {!d.servers.length && !d.base_url_required && (
          <button className={`wiz-choice ${!p.customBase ? "on" : ""}`} onClick={() => useServer(null)}>
            <b>The addresses in the definition</b>
            <span>Each operation goes where the definition says.</span>
          </button>
        )}
        <button
          className={`wiz-choice ${p.customBase ? "on" : ""}`}
          onClick={() => {
            p.setCustomBase(true);
            p.setTarget({ ...t, server: null });
          }}
        >
          <b>Another base URL</b>
          <span>{d.base_url_required ? "This definition doesn't say where the API is, so it needs one." : "For example a test environment. It replaces the definition's servers."}</span>
        </button>
      </div>
      {p.customBase && (
        <input
          className="input full wiz-input"
          placeholder="https://api.example.com/v1"
          value={t.baseUrl}
          spellCheck={false}
          autoFocus
          onChange={(e) => p.setTarget({ ...t, server: null, baseUrl: e.target.value })}
        />
      )}

      {vars.length > 0 && (
        <>
          <label className="label">Variables</label>
          <div className="form">
            {vars.map((v) => (
              <label key={v.name}>
                <span className="label mono">
                  {v.name}
                  {v.unresolved && !t.vars[v.name] ? " (no value yet)" : ""}
                </span>
                {v.secret ? (
                  <span className="muted small">Holds a secret, so it gets no field here. Use the authentication step.</span>
                ) : (
                  <input className="input mono" value={t.vars[v.name] ?? v.value} spellCheck={false} onChange={(e) => p.setTarget({ ...t, vars: { ...t.vars, [v.name]: e.target.value } })} />
                )}
              </label>
            ))}
          </div>
          <p className="muted small">These values go on the command line and in the job's record, so don't put a key or password in one.</p>
        </>
      )}

      <label className="label">Hosts this would contact</label>
      {d.hosts.length ? (
        <ul className="wiz-list">
          {d.hosts.map((h) => (
            <li key={`${h.host}:${h.port}`}>
              <span className="mono">{hostLabel(h)}</span> <span className={h.in_scope ? "muted" : "s5"}>{hostScopeText(h)}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">None yet.</p>
      )}
      <p className="muted">
        This project's approved scope: {p.scope.length ? <span className="mono">{p.scope.join(", ")}</span> : "not known"}. The scope can't be widened here, so operations on hosts outside it are skipped and nothing is added to the engagement.
      </p>
      {p.docChanged && <div className="wiz-warn danger">The definition changed since you first read it. The ticked operations were reset, and the scan will use the latest version.</div>}
      {p.problem && <div className="wiz-problem">{p.problem}</div>}
      {!p.busy && !p.problem && p.blockers.map((b) => <div key={b} className="wiz-problem">{b}</div>)}
    </div>
  );
}

interface AuthData {
  /** Names can only be checked for collisions once this loaded. */
  profiles: { name: string; login_url?: string | null; session?: { logged_in?: boolean } }[];
  signers: { profile: string; signer: Signer }[];
  rules: Record<string, SessionRule[]>;
}

async function loadAuthData(): Promise<AuthData> {
  const { profiles } = await run<{ profiles: AuthData["profiles"] }>(["auth", "list"]);
  const each = await Promise.all(
    profiles.map(async (pr) => {
      const [s, r] = await Promise.all([
        run<{ signers: Signer[] }>(["auth", "sign", "list", "--", pr.name]).catch(() => ({ signers: [] as Signer[] })),
        run<{ rules: SessionRule[] }>(["auth", "rule", "list", "--", pr.name]).catch(() => ({ rules: [] as SessionRule[] })),
      ]);
      return { name: pr.name, signers: s.signers, rules: r.rules };
    }),
  );
  return {
    profiles,
    signers: each.flatMap((e) => e.signers.map((signer) => ({ profile: e.name, signer }))),
    rules: Object.fromEntries(each.map((e) => [e.name, e.rules])),
  };
}

function AuthStep(p: {
  preview: ApiPreview;
  source: string;
  target: ApiTarget;
  selected: number[];
  auth: AuthState;
  setAuth: (a: AuthState) => void;
  draft: SignerForm | null;
  setDraft: (f: SignerForm | null) => void;
}) {
  const app = useApp();
  const [data, setData] = useState<AuthData | null>(null);
  const [loadProblem, setLoadProblem] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const a = p.auth;
  const set = (patch: Partial<AuthState>) => p.setAuth({ ...a, ...patch });
  const ops = p.preview.requests;
  const inScope = ops.filter((o) => o.in_scope);
  const origins = operationOrigins(likelyInScope(ops));
  const taken = data?.profiles.map((x) => x.name) ?? [];

  const reload = () =>
    loadAuthData().then(
      (d) => {
        setData(d);
        setLoadProblem("");
        return d;
      },
      (e: any) => {
        setLoadProblem(e.message);
        return null;
      },
    );

  useEffect(() => {
    reload().then((d) => {
      if (d && !a.profileName) set({ profileName: defaultProfileName(p.preview.title, d.profiles.map((x) => x.name)) });
    });
  }, []);

  const signerRow = a.signer && data?.signers.find((s) => s.profile === a.signer!.profile && s.signer.name === a.signer!.name);
  const ticked = new Set(p.selected);
  const coverage = signerRow ? signerCoverage(data!.rules[signerRow.profile] ?? [], signerRow.signer, inScope.filter((o) => ticked.has(o.index)).map((o) => o.url)) : null;

  const pickSigner = (profile: string, name: string) => {
    // A scan uses one profile, and `auth add` can't add a key to one that exists: pick its profile.
    const moved = authProfile(a) !== profile;
    p.setAuth({ ...a, signing: true, signer: { profile, name }, ...(moved ? { mode: "profile" as const, existing: profile } : {}) });
    p.setDraft(null);
    setNote(moved ? `Selected the profile "${profile}", which holds this signer. The scan runs with that profile's credentials.` : "");
  };

  const saveSigner = async (f: SignerForm) => {
    const home = signerHome(a);
    setSaving(true);
    try {
      await run(signerAddArgs(home, f));
      const name = f.name.trim();
      // The session rule is what turns a signer on. If it fails, the coverage check below offers it again.
      for (const args of signRuleArgs(home, name, signerFormOrigins(f))) await run(args);
      p.setAuth({ ...a, signing: true, signer: { profile: home, name } });
      p.setDraft(null);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    await reload();
    setSaving(false);
  };

  const addRule = async () => {
    if (!signerRow) return;
    setSaving(true);
    try {
      for (const args of signRuleArgs(signerRow.profile, signerRow.signer.name, signerRow.signer.origins)) await run(args);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    await reload();
    setSaving(false);
  };

  const signerNames = data?.signers.filter((s) => s.profile === signerHome(a)).map((s) => s.signer.name) ?? [];
  const draftProblems = p.draft ? [...(data ? [] : ["Profiles are still loading."]), ...newSignerProblems(a, taken), ...signerProblems(p.draft, signerNames)] : [];

  return (
    <div className="wiz-body">
      <label className="label">Does the API need authentication?</label>
      {loadProblem && <div className="wiz-problem">Couldn't read the auth profiles: {loadProblem}</div>}
      <div className="wiz-choices three">
        <button className={`wiz-choice ${a.mode === "none" ? "on" : ""}`} onClick={() => set({ mode: "none" })}>
          <b>No authentication</b>
          <span>Test what anyone can reach. A good start.</span>
        </button>
        <button className={`wiz-choice ${a.mode === "key" ? "on" : ""}`} onClick={() => set({ mode: "key" })}>
          <b>API key or bearer token</b>
          <span>The usual way. Stored in a new auth profile.</span>
        </button>
        <button className={`wiz-choice ${a.mode === "profile" ? "on" : ""}`} onClick={() => set({ mode: "profile" })}>
          <b>Existing auth profile</b>
          <span>{taken.length ? "One you already set up." : "This project has none yet."}</span>
        </button>
      </div>

      {a.mode === "key" && <KeyFields auth={a} set={set} preview={p.preview} taken={taken} loaded={!!data} origins={origins} reload={reload} />}

      {a.mode === "profile" && (
        <label>
          <span className="label">Profile</span>
          <select className="input" value={a.existing} onChange={(e) => set({ existing: e.target.value })}>
            <option value="">Choose a profile…</option>
            {data?.profiles.map((x) => (
              <option key={x.name} value={x.name}>
                {x.name} {x.login_url ? (x.session?.logged_in ? "(session active)" : "(logs in during the scan)") : ""}
              </option>
            ))}
          </select>
        </label>
      )}

      {p.preview.credentials.length > 0 && (
        <>
          <label className="label">What the definition says about authentication</label>
          <ul className="wiz-list">
            {p.preview.credentials.map((c, i) => (
              <li key={i}>{credentialText(c)}</li>
            ))}
          </ul>
        </>
      )}

      <div className="wiz-sign">
        <label className="check wiz-wrap">
          <input type="checkbox" checked={a.signing} onChange={(e) => set({ signing: e.target.checked })} />
          Every request must be signed
        </label>
        {a.signing && (
          <>
            <p className="muted">For APIs that reject requests without an HMAC signature or a JWT. Most APIs don't need this.</p>
            {note && <p className="muted">{note}</p>}
            {data && data.signers.length > 0 && (
              <div className="wiz-choices">
                {data.signers.map((s) => (
                  <button
                    key={`${s.profile}/${s.signer.name}`}
                    className={`wiz-choice ${a.signer?.profile === s.profile && a.signer.name === s.signer.name ? "on" : ""}`}
                    onClick={() => pickSigner(s.profile, s.signer.name)}
                  >
                    <b>
                      {s.signer.name} <span className="muted">in {s.profile}</span>
                    </b>
                    <span>{signerLabel(s.signer)}</span>
                  </button>
                ))}
              </div>
            )}
            {coverage && coverage.state !== "covered" && (
              <div className="wiz-warn">
                {coverage.message}{" "}
                {coverage.state !== "origin_limited" && (
                  <button className="link" disabled={saving} onClick={addRule}>
                    Add a rule for every tool
                  </button>
                )}
              </div>
            )}
            {!p.draft ? (
              <div>
                <button className="btn" onClick={() => p.setDraft(newSignerForm(origins))}>
                  Set up a new signer
                </button>
              </div>
            ) : (
              <>
                {a.mode === "none" && (
                  <label>
                    <span className="label">New profile to hold the signer</span>
                    <input className="input mono" value={a.profileName} onChange={(e) => set({ profileName: e.target.value })} />
                  </label>
                )}
                <SignerBuilder form={p.draft} editing={false} setForm={p.setDraft} problems={draftProblems} onSave={() => saveSigner(p.draft!)} onCancel={() => p.setDraft(null)} />
                <p className="muted small">Saving also adds a session rule that signs requests to these origins, for every tool.</p>
              </>
            )}
          </>
        )}
      </div>

      <TryOne preview={p.preview} source={p.source} target={p.target} selected={p.selected} auth={a} ruleApplies={coverage?.checkCovered ?? true} />
    </div>
  );
}

/** The key's input stays out of React state: it lives in the DOM until saved, then it's cleared. */
function KeyFields(p: {
  auth: AuthState;
  set: (patch: Partial<AuthState>) => void;
  preview: ApiPreview;
  taken: string[];
  loaded: boolean;
  origins: string[];
  reload: () => Promise<unknown>;
}) {
  const a = p.auth;
  const input = useRef<HTMLInputElement>(null);
  const [hasValue, setHasValue] = useState(false);
  const [saving, setSaving] = useState(false);
  const [problem, setProblem] = useState("");

  if (a.savedProfile) {
    return (
      <div className="wiz-good">
        Saved in the profile "{a.savedProfile}". The value isn't shown again.{" "}
        <button className="link" onClick={() => p.set({ savedProfile: "", profileName: defaultProfileName(p.preview.title, p.taken) })}>
          Enter a different one
        </button>
      </div>
    );
  }

  const bearer = a.keyKind === "bearer";
  const problems = keyProblems(a, p.taken, hasValue, p.origins);
  const save = async () => {
    const value = input.current?.value ?? "";
    setSaving(true);
    setProblem("");
    try {
      await run(keyAddArgs(a, p.origins), { env: keyEnv(a.keyKind, value) });
      if (input.current) input.current.value = "";
      setHasValue(false);
      p.set({ savedProfile: a.profileName.trim() });
      await p.reload();
    } catch (e: any) {
      setProblem(scrubSecret(e.message, value));
    }
    setSaving(false);
  };

  return (
    <div className="form">
      <div>
        <span className="label">Type</span>
        <div className="seg">
          {(["api_key", "bearer"] as KeyKind[]).map((k) => (
            <button key={k} className={a.keyKind === k ? "on" : ""} onClick={() => p.set(keyKindDefaults(p.preview.credentials, k))}>
              {k === "bearer" ? "Bearer token" : "API key"}
            </button>
          ))}
        </div>
      </div>
      {!bearer && (
        <div>
          <span className="label">Goes in</span>
          <div className="seg">
            <button className={a.place === "header" ? "on" : ""} onClick={() => p.set({ place: "header" })}>
              Header
            </button>
            <button className={a.place === "query" ? "on" : ""} onClick={() => p.set({ place: "query" })}>
              Query
            </button>
          </div>
        </div>
      )}
      <label>
        <span className="label">{bearer ? "Header" : a.place === "query" ? "Query parameter" : "Header name"}</span>
        <input className="input mono" value={bearer ? "Authorization" : a.keyName} disabled={bearer} placeholder={a.place === "query" ? "api_key" : "X-Api-Key"} onChange={(e) => p.set({ keyName: e.target.value })} />
      </label>
      <label>
        <span className="label">{bearer ? "Token (without the word Bearer)" : "Key"}</span>
        <input ref={input} className="input mono" type="password" autoComplete="off" spellCheck={false} onChange={(e) => setHasValue(!!e.target.value.trim())} />
      </label>
      <label>
        <span className="label">New profile name</span>
        <input className="input mono" value={a.profileName} onChange={(e) => p.set({ profileName: e.target.value })} />
      </label>
      <div className="wide">
        {a.place === "query" && !bearer && <p className="muted small">The key is only sent to {p.origins.join(", ") || "in-scope addresses"}, and history keeps a placeholder.</p>}
        {problem && <div className="wiz-problem">{problem}</div>}
        {hasValue && problems.map((m) => <div key={m} className="set-err small">{m}</div>)}
        <button className="btn" disabled={saving || !p.loaded || problems.length > 0} onClick={save}>
          {saving ? "Saving…" : "Save to the profile"}
        </button>
      </div>
    </div>
  );
}

interface TryResult {
  profile: string;
  tone: "ok" | "warn" | "bad";
  text: string;
}

function TryOne(p: { preview: ApiPreview; source: string; target: ApiTarget; selected: number[]; auth: AuthState; ruleApplies: boolean }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<TryResult | null>(null);
  const [problem, setProblem] = useState("");
  const op = pickCheckOperation(p.preview.requests, p.selected);
  const profile = authProfile(p.auth);
  const signer = p.auth.signing && p.auth.signer ? p.auth.signer.name : "";
  const blocked = authProblems(p.auth).length > 0;

  const go = async () => {
    if (!op) return;
    setBusy(true);
    setProblem("");
    setResult(null);
    try {
      const d = await run<{ requests?: { status: number | null; history_id: number | null; error?: string }[] }>(checkArgs(p.source, p.preview.document_sha256, p.target, op.index, profile));
      const sent = d.requests?.[0];
      if (!sent) {
        setProblem("Nothing was sent. The operation may be outside the scope.");
      } else {
        let raw: string | null = null;
        if (profile && sent.history_id != null) {
          try {
            raw = bodyText((await run<HistoryEntry>(["history", "show", String(sent.history_id)])).request);
          } catch {
            /* said in the result */
          }
        }
        // Only yes or no comes out of the recorded request. It is not kept or displayed.
        setResult({
          profile,
          ...checkMeaning({
            status: sent.status,
            error: sent.error,
            profile,
            signer,
            credentialOn: raw == null ? null : credentialOnRequest(raw, profile),
            signerOn: signer ? (raw == null ? null : signerOnRequest(raw, profile, signer)) : null,
            signerRuleApplies: p.ruleApplies,
          }),
        });
      }
    } catch (e: any) {
      setProblem(e.message);
    }
    setBusy(false);
  };

  return (
    <div className="wiz-sign">
      <label className="label">Check it works (optional)</label>
      {op ? (
        <p className="muted">
          This sends one real request to the API now: <span className="mono">{op.method.toUpperCase()} {op.url}</span>
          {profile ? `, with the profile "${profile}".` : ", with no authentication."}
        </p>
      ) : (
        <p className="muted">No GET, HEAD or OPTIONS operation is in scope, so there's nothing safe to try. POST and state-changing operations are never used for this.</p>
      )}
      <div>
        <button className="btn" disabled={busy || !op || blocked} onClick={go}>
          {busy ? "Sending…" : "Try one request (sends it now)"}
        </button>
      </div>
      {problem && <div className="wiz-problem">{problem}</div>}
      {result && result.profile === profile && <div className={result.tone === "ok" ? "wiz-good" : result.tone === "bad" ? "wiz-problem" : "wiz-warn"}>{result.text}</div>}
    </div>
  );
}

function OperationsStep(p: {
  operations: ApiOperation[];
  truncated: boolean;
  selected: number[];
  setSelected: (s: number[]) => void;
  optIn: boolean;
  setOptIn: (on: boolean) => void;
}) {
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const ops = p.operations;
  const on = new Set(p.selected);
  const shown = filterOperations(ops, filter);
  const riskyMethods = optInMethods(ops);
  const toggle = (i: number) => p.setSelected(on.has(i) ? p.selected.filter((x) => x !== i) : [...p.selected, i].sort((a, b) => a - b));
  return (
    <div className="wiz-body">
      <label className="label">Which operations should be sent and tested?</label>
      <div className="wiz-row">
        <input className="input wiz-input" placeholder="Filter by method, name or URL" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <button className="btn small" onClick={() => p.setSelected(selectShown(p.selected, shown, p.optIn, true))}>
          Select all
        </button>
        <button className="btn small" onClick={() => p.setSelected(selectShown(p.selected, shown, p.optIn, false))}>
          Select none
        </button>
        <b>{operationCount(p.selected.length)}</b>
      </div>
      {riskyMethods.length > 0 && (
        <label className="check wiz-wrap">
          <input
            type="checkbox"
            checked={p.optIn}
            onChange={(e) => {
              p.setOptIn(e.target.checked);
              if (!e.target.checked) p.setSelected(dropOptIn(p.selected, ops));
            }}
          />
          <span>
            Let me tick {listWords(riskyMethods)} operations. These overwrite or delete data on the server. Each one you tick is sent as written, then again with attack data.
          </span>
        </label>
      )}
      <div className="wiz-ops-box">
        <table className="wiz-ops">
          <thead>
            <tr>
              <th className="tick" />
              <th className="method">Method</th>
              <th>Name</th>
              <th>URL</th>
              <th className="more" />
            </tr>
          </thead>
          <tbody>
            {shown.map((o) => {
              const why = excludedText(o, on.has(o.index));
              const can = tickable(o, p.optIn);
              return (
                <OperationRow key={o.index} op={o} ticked={on.has(o.index)} can={can} why={why} open={open === o.index} onToggle={() => toggle(o.index)} onOpen={() => setOpen(open === o.index ? null : o.index)} />
              );
            })}
          </tbody>
        </table>
        {shown.length === 0 && <div className="empty">No operation matches.</div>}
      </div>
      {p.truncated && <p className="muted small">The definition has more operations than this list. Only those listed can be sent.</p>}
      {sendsStateChanging(ops, p.selected) && (
        <div className="wiz-warn danger">
          <b>You ticked operations that change or delete data ({listWords(includeMethods(ops, p.selected))}).</b> They are sent as written and then many times with attack data. Real records can be overwritten or deleted, and that can't be undone. Use a test environment you can restore.
        </div>
      )}
      {sendsPost(ops, p.selected) && <PostWarning />}
    </div>
  );
}

function OperationRow(p: { op: ApiOperation; ticked: boolean; can: boolean; why: string; open: boolean; onToggle: () => void; onOpen: () => void }) {
  const o = p.op;
  return (
    <>
      <tr className={p.ticked ? "" : "off"}>
        <td className="tick">
          <input type="checkbox" aria-label={`Send ${o.name}`} checked={p.ticked} disabled={!p.can && !p.ticked} onChange={p.onToggle} />
        </td>
        <td className="method mono">{o.method.toUpperCase()}</td>
        <td>
          {o.name}
          {p.why && <div className="muted small">{p.why}</div>}
        </td>
        <td className="wide mono small">{o.url}</td>
        <td className="more">
          <button className="link" onClick={p.onOpen}>
            {p.open ? "Hide" : "Example"}
          </button>
        </td>
      </tr>
      {p.open && (
        <tr>
          <td className="wide" colSpan={5}>
            <pre className="mono small">
              {o.headers.join("\n")}
              {o.body ? `\n\n${o.body.encoding === "base64" ? `(binary body, ${o.body.length ?? "unknown"} bytes)` : bodyText(o.body)}${o.body.truncated ? "\n…" : ""}` : ""}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

function StartStep(p: {
  preview: ApiPreview;
  source: string;
  target: ApiTarget;
  auth: AuthState;
  selected: number[];
  depth: Depth;
  setDepth: (d: Depth) => void;
  speed: Speed;
  setSpeed: (s: Speed) => void;
  problem: string;
}) {
  const d = p.preview;
  const depth = DEPTHS.find((x) => x.id === p.depth)!;
  return (
    <div className="wiz-body">
      <label className="label">How thorough should it be?</label>
      <div className="wiz-choices three">
        {DEPTHS.map((x) => (
          <button key={x.id} className={`wiz-choice ${p.depth === x.id ? "on" : ""}`} onClick={() => p.setDepth(x.id)}>
            <b>{x.title}</b>
            <span className="wiz-time">{x.time}</span>
            <span>{apiDepthText(x.id)}</span>
          </button>
        ))}
      </div>
      <label className="label">How hard may it push the API?</label>
      <div className="wiz-choices three">
        {SPEEDS.map((s) => (
          <button key={s.id} className={`wiz-choice ${p.speed === s.id ? "on" : ""} ${s.danger ? "danger" : ""}`} onClick={() => p.setSpeed(s.id)}>
            <b>{s.title}</b>
            <span>{apiSpeedText(s.id)}</span>
          </button>
        ))}
      </div>

      <label className="label">Ready to start</label>
      <dl className="facts">
        <dt>Definition</dt>
        <dd>
          {previewTitle(d)} <span className="mono muted">{p.source}</span>
        </dd>
        <dt>Server</dt>
        <dd className="mono">{serverSummary(d, p.target)}</dd>
        {targetArgs(p.target).some((x) => x.startsWith("--var=")) && (
          <>
            <dt>Variables</dt>
            <dd className="mono">{Object.keys(p.target.vars).filter((k) => p.target.vars[k] !== "").join(", ")}</dd>
          </>
        )}
        <dt>Authentication</dt>
        <dd>{authSummary(p.auth)}</dd>
        <dt>Signing</dt>
        <dd>{signingSummary(p.auth)}</dd>
        <dt>Operations</dt>
        <dd>{methodSummary(d.requests, p.selected)}</dd>
        <dt>Depth</dt>
        <dd>
          {depth.title} ({depth.time})
        </dd>
        <dt>Speed</dt>
        <dd className={p.speed === "fast" ? "s5" : ""}>{SPEEDS.find((s) => s.id === p.speed)!.title}</dd>
      </dl>
      {p.problem && <div className="wiz-problem">{p.problem}</div>}
      {p.speed === "fast" && (
        <div className="wiz-warn danger">
          <b>Fast can take the API down.</b> It sends up to 30 requests at once with no pause. Use it only on a test server you can afford to disrupt, never on a production or shared API.
        </div>
      )}
      {sendsStateChanging(d.requests, p.selected) && (
        <div className="wiz-warn danger">
          <b>This scan sends operations that change or delete data ({listWords(includeMethods(d.requests, p.selected))}).</b> They are sent as written and then many times with attack data. Real records can be overwritten or deleted, and that can't be undone.
        </div>
      )}
      {sendsPost(d.requests, p.selected) && <PostWarning />}
      {attacksPaths(p.depth) && (
        <div className="wiz-warn replay">
          <b>Paths are attacked too.</b> Each part of a path, such as the 42 in /users/42, is changed and requested.
          {authProfile(p.auth) && " With authentication, a changed path can still change or delete data if the API does that on a plain GET."}
        </div>
      )}
      <div className="wiz-warn">
        The scan sends real attack requests, as an attacker would. It can create test data or slow down a fragile API. Prefer a test environment, and only scan systems you have permission to test.
      </div>
    </div>
  );
}
