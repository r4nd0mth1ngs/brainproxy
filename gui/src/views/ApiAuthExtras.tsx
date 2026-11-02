// The API guided scan's OAuth setup and Postman script choice. The logic is in apiScan.ts.

import { useRef, useState } from "react";
import { run } from "../api";
import {
  oauthAddArgs,
  oauthDefaults,
  oauthEnv,
  oauthProblems,
  scriptSignerForm,
  scriptTextArgs,
  scrubSecret,
  signRuleArgs,
  sourceKind,
  type ApiPreview,
  type ApiTarget,
  type AuthState,
  type OAuthFlow,
  type OAuthForm,
} from "./apiScan";
import { signerAddArgs } from "./sessionRules";

const FLOWS: { id: OAuthFlow; label: string; text: string }[] = [
  { id: "client_credentials", label: "Client credentials", text: "A client id and secret, no user." },
  { id: "authorization_code", label: "Browser sign-in", text: "You sign in once in your browser (authorization code with PKCE)." },
  { id: "password", label: "Username and password", text: "The older password grant." },
  { id: "refresh_token", label: "Refresh token", text: "One you already have." },
];

/** The secrets' inputs stay out of React state: they live in the DOM until saved, then they're cleared. */
export function OAuthFields(p: { auth: AuthState; set: (patch: Partial<AuthState>) => void; preview: ApiPreview; taken: string[]; loaded: boolean; reload: () => Promise<unknown> }) {
  const a = p.auth;
  const f = a.oauth;
  const setForm = (patch: Partial<OAuthForm>) => p.set({ oauth: { ...f, ...patch } });
  const secret = useRef<HTMLInputElement>(null);
  const refresh = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const [has, setHas] = useState({ secret: false, refresh: false, password: false });
  const [saving, setSaving] = useState(false);
  const [problem, setProblem] = useState("");

  if (a.savedProfile) {
    return (
      <div className="wiz-good">
        Token obtained, and saved in the profile "{a.savedProfile}". It's renewed during the scan as it runs out. The values aren't shown again.{" "}
        <button className="link" onClick={() => p.set({ savedProfile: "", profileName: "" })}>
          Enter different ones
        </button>
      </div>
    );
  }

  const problems = oauthProblems(f, a.profileName, p.taken, has);
  const hints = p.preview.oauth ?? [];
  const browser = f.flow === "authorization_code";

  const discover = async (url: string) => {
    setProblem("");
    try {
      const d = await run<{ token_url: string | null; authorize_url: string | null }>(["auth", "oauth", "discover", "--", url]);
      setForm({ tokenUrl: d.token_url ?? f.tokenUrl, authorizeUrl: d.authorize_url ?? f.authorizeUrl });
    } catch (e: any) {
      setProblem(e.message);
    }
  };

  const save = async () => {
    const values = { secret: secret.current?.value ?? "", refresh: refresh.current?.value ?? "", password: password.current?.value ?? "" };
    const clean = (m: string) => [values.secret, values.refresh, values.password].reduce(scrubSecret, m);
    const name = a.profileName.trim();
    setSaving(true);
    setProblem("");
    try {
      await run(oauthAddArgs(name, f, { secret: !!values.secret.trim(), refresh: !!values.refresh.trim() }), { env: oauthEnv(values) });
      // A profile that can't get a token isn't worth keeping: the check below would only fail later.
      try {
        const r = await run<{ login?: { success: boolean; reason: string } }>(browser ? ["auth", "oauth", "authorize", "--", name] : ["auth", "login", "--", name]);
        if (r.login && !r.login.success) throw new Error(r.login.reason);
      } catch (e) {
        await run(["auth", "remove", "--", name]).catch(() => {});
        throw e;
      }
      for (const input of [secret, refresh, password]) if (input.current) input.current.value = "";
      setHas({ secret: false, refresh: false, password: false });
      p.set({ savedProfile: name });
      await p.reload();
    } catch (e: any) {
      const scope = e.kind === "out_of_scope" ? " The token endpoint has to be in the engagement's scope, and the scope can't be widened here." : "";
      setProblem(clean(e.message) + scope);
    }
    setSaving(false);
  };

  return (
    <div className="form">
      {hints.length > 0 && (
        <div className="wide">
          <span className="label">What the definition declares</span>
          <div className="wiz-choices">
            {hints.map((h, i) =>
              h.openid_url ? (
                <button key={i} className="wiz-choice" onClick={() => discover(h.openid_url!)}>
                  <b>OpenID Connect</b>
                  <span>Reads {h.openid_url}, in scope only.</span>
                </button>
              ) : (
                <button key={i} className="wiz-choice" onClick={() => p.set({ oauth: { ...f, ...oauthDefaults([h]) } })}>
                  <b>{FLOWS.find((x) => x.id === h.flow)?.label ?? "OAuth 2"}</b>
                  <span>{h.token_url ?? h.authorize_url ?? h.source}</span>
                </button>
              ),
            )}
          </div>
        </div>
      )}
      <div className="wide">
        <span className="label">How does the API give out tokens?</span>
        <div className="seg">
          {FLOWS.map((x) => (
            <button key={x.id} className={f.flow === x.id ? "on" : ""} title={x.text} onClick={() => setForm({ flow: x.id })}>
              {x.label}
            </button>
          ))}
        </div>
        <p className="muted small">{FLOWS.find((x) => x.id === f.flow)?.text}</p>
      </div>
      <label className="wide">
        <span className="label">Token URL (its host must be in scope)</span>
        <input className="input mono" value={f.tokenUrl} spellCheck={false} placeholder="https://login.example.com/oauth/token" onChange={(e) => setForm({ tokenUrl: e.target.value })} />
      </label>
      {browser && (
        <>
          <label className="wide">
            <span className="label">Sign-in page</span>
            <input className="input mono" value={f.authorizeUrl} spellCheck={false} placeholder="https://login.example.com/authorize" onChange={(e) => setForm({ authorizeUrl: e.target.value })} />
          </label>
          <label>
            <span className="label">Redirect port, if the client registered one</span>
            <input className="input mono" value={f.redirectPort} placeholder="any free port" onChange={(e) => setForm({ redirectPort: e.target.value })} />
          </label>
          <p className="muted small wide">
            The provider redirects to <span className="mono">http://127.0.0.1:{f.redirectPort.trim() || "PORT"}/callback</span>, which it must allow.
          </p>
        </>
      )}
      <label>
        <span className="label">Client id</span>
        <input className="input mono" value={f.clientId} spellCheck={false} autoComplete="off" onChange={(e) => setForm({ clientId: e.target.value })} />
      </label>
      <label>
        <span className="label">Client secret{f.flow === "client_credentials" ? "" : " (if it has one)"}</span>
        <input ref={secret} className="input mono" type="password" autoComplete="off" spellCheck={false} onChange={(e) => setHas((h) => ({ ...h, secret: !!e.target.value.trim() }))} />
      </label>
      <div>
        <span className="label">Client secret goes</span>
        <div className="seg">
          <button className={f.clientAuth === "body" ? "on" : ""} onClick={() => setForm({ clientAuth: "body" })}>
            In the form
          </button>
          <button className={f.clientAuth === "basic" ? "on" : ""} onClick={() => setForm({ clientAuth: "basic" })}>
            HTTP Basic
          </button>
        </div>
      </div>
      {f.flow === "password" && (
        <>
          <label>
            <span className="label">Username</span>
            <input className="input mono" value={f.username} spellCheck={false} autoComplete="off" onChange={(e) => setForm({ username: e.target.value })} />
          </label>
          <label>
            <span className="label">Password</span>
            <input ref={password} className="input mono" type="password" autoComplete="off" spellCheck={false} onChange={(e) => setHas((h) => ({ ...h, password: !!e.target.value.trim() }))} />
          </label>
        </>
      )}
      {f.flow === "refresh_token" && (
        <label className="wide">
          <span className="label">Refresh token</span>
          <input ref={refresh} className="input mono" type="password" autoComplete="off" spellCheck={false} onChange={(e) => setHas((h) => ({ ...h, refresh: !!e.target.value.trim() }))} />
        </label>
      )}
      <label>
        <span className="label">Scopes (optional)</span>
        <input className="input mono" value={f.scope} spellCheck={false} placeholder="read write" onChange={(e) => setForm({ scope: e.target.value })} />
      </label>
      <label>
        <span className="label">Audience (optional)</span>
        <input className="input mono" value={f.audience} spellCheck={false} onChange={(e) => setForm({ audience: e.target.value })} />
      </label>
      <label>
        <span className="label">New profile name</span>
        <input className="input mono" value={a.profileName} onChange={(e) => p.set({ profileName: e.target.value })} />
      </label>
      <div className="wide">
        <p className="muted small">{browser ? "This opens your browser and waits for you to sign in, up to five minutes." : "This asks for a token now, from the token URL above, to prove the setup works."} The secrets are stored in the project file, like other keys. Token requests aren't recorded in history.</p>
        {problem && <div className="wiz-problem">{problem}</div>}
        {problems.map((m) => (
          <div key={m} className="set-err small">
            {m}
          </div>
        ))}
        <button className="btn" disabled={saving || !p.loaded || problems.length > 0} onClick={save}>
          {saving ? (browser ? "Waiting for the sign-in…" : "Asking for a token…") : browser ? "Save and sign in" : "Save and get a token"}
        </button>
      </div>
    </div>
  );
}

/** A collection's pre-request scripts, listed. One runs only after its text was shown and it was chosen. */
export function ScriptChoice(p: {
  preview: ApiPreview;
  source: string;
  target: ApiTarget;
  home: string;
  /** What keeps a signer from being saved in `home`. */
  blockers: string[];
  origins: string[];
  chosen: string | null;
  onSaved: (name: string, sha256: string) => Promise<void>;
}) {
  const [texts, setTexts] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState("");
  const scripts = p.preview.scripts ?? [];
  if (!scripts.length) return null;
  const remote = sourceKind(p.source) === "url";

  const read = async () => {
    setBusy(true);
    setProblem("");
    try {
      const d = await run<ApiPreview>(scriptTextArgs(p.source, p.target));
      setTexts(Object.fromEntries((d.scripts ?? []).map((s) => [s.sha256, s.text ?? ""])));
    } catch (e: any) {
      setProblem(e.message);
    }
    setBusy(false);
  };

  const use = async (s256: string) => {
    setBusy(true);
    setProblem("");
    try {
      const form = scriptSignerForm(p.source, s256, p.target.environment, p.origins);
      await run(signerAddArgs(p.home, form));
      for (const args of signRuleArgs(p.home, form.name, p.origins)) await run(args);
      await p.onSaved(form.name, s256);
    } catch (e: any) {
      setProblem(e.message);
    }
    setBusy(false);
  };

  return (
    <div className="wiz-warn replay">
      <b>This collection has {scripts.length === 1 ? "a pre-request script" : `${scripts.length} pre-request scripts`}.</b>
      <p className="muted small">Nothing has run. Choosing one runs that code for every request, cut off from your files and the network, with the variables and environment file in reach. It can only change headers and the query. Read it first. Scripts of other folders or requests don't run.</p>
      {remote && <p className="muted small">A script only runs from a local file. Save the collection and choose the file to use one.</p>}
      {!remote && !Object.keys(texts).length && (
        <button className="btn small" disabled={busy} onClick={read}>
          Read {scripts.length === 1 ? "the script" : "the scripts"}
        </button>
      )}
      {scripts.map((s) => (
        <div key={s.sha256}>
          <div className="small">
            <span className="mono">{s.scopes.join(", ")}</span>: {s.lines} line{s.lines === 1 ? "" : "s"}, for {s.requests} request{s.requests === 1 ? "" : "s"}
            {s.signs ? ", seems to sign" : ""}
          </div>
          {s.unsupported.length > 0 && <div className="set-err small">It uses {s.unsupported.join(", ")}, which can't run here, so requests would fail.</div>}
          {texts[s.sha256] !== undefined && (
            <>
              <pre className="mono small wiz-script">{texts[s.sha256]}</pre>
              {p.chosen === s.sha256 ? (
                <div className="wiz-good">Runs for every request.</div>
              ) : (
                <button className="btn small" disabled={busy || p.blockers.length > 0 || s.unsupported.length > 0 || !p.origins.length} onClick={() => use(s.sha256)}>
                  Run this one for every request
                </button>
              )}
            </>
          )}
        </div>
      ))}
      {p.blockers.map((m) => (
        <div key={m} className="set-err small">
          {m}
        </div>
      ))}
      {problem && <div className="wiz-problem">{problem}</div>}
    </div>
  );
}
