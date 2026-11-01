// Project and tool settings: auth profiles, match & replace, intercept options, proxy setup,
// connection options, the CA, rule data, project info, and open-source licenses. Each sub-tab loads its data when first shown.

import { Fragment, useEffect, useState, type ReactNode } from "react";
import { run, type CliInput } from "../api";
import { AUTO_PROXY, autoProxy, useApp } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { Split } from "../ui/Split";
import { interceptEnableArgs, type InterceptSettings } from "./Proxy";
import { usePoll } from "../ui/usePoll";
import { RecordLogin } from "./RecordLogin";
import { AppUpdateSettings } from "./AppUpdate";
import {
  EMPTY_CERT,
  EMPTY_UPSTREAM,
  certAddArgs,
  describePlatform,
  hostsAddArgs,
  passthroughAddArgs,
  platformArgs,
  platformForm,
  upstreamAddArgs,
  type CertForm,
  type ConnectionSettings,
  type PlatformAuth,
  type PlatformForm,
  type UpstreamForm,
} from "./connection";
import { MacroBuilder, SessionHandling } from "./SessionHandling";
import type { MacroSummary, SessionRule, Signer } from "./sessionRules";
import NOTICE from "../../../NOTICE?raw";

type Sub = "auth" | "rules" | "intercept" | "proxy" | "connections" | "ca" | "data" | "project" | "licenses";

const SUBS: { id: Sub; label: string }[] = [
  { id: "auth", label: "Auth profiles" },
  { id: "rules", label: "Match & replace" },
  { id: "intercept", label: "Intercept options" },
  { id: "proxy", label: "Proxy" },
  { id: "connections", label: "Connections" },
  { id: "ca", label: "TLS / CA" },
  { id: "data", label: "Rules & data" },
  { id: "project", label: "Project" },
  { id: "licenses", label: "Open source licenses" },
];

export function SettingsView() {
  const [sub, setSub] = useState<Sub>("auth");
  return (
    <div className="col fill">
      <div className="subtabs">
        {SUBS.map((s) => (
          <button key={s.id} className={sub === s.id ? "on" : ""} onClick={() => setSub(s.id)}>
            {s.label}
          </button>
        ))}
      </div>
      {/* Only the open sub-tab is mounted, so it reloads fresh data each time it is opened. */}
      {sub === "auth" && <Auth />}
      {sub === "rules" && <Rules />}
      {sub === "intercept" && <Intercept />}
      {sub === "proxy" && <ProxySetup />}
      {sub === "connections" && <Connections />}
      {sub === "ca" && <Ca />}
      {sub === "data" && <RuleData />}
      {sub === "project" && <Project />}
      {sub === "licenses" && <Licenses />}
    </div>
  );
}

/** A button that asks inline before running a destructive or networked action. */
function ConfirmButton(p: { label: string; question: string; onConfirm: () => void; disabled?: boolean; className?: string }) {
  const [asking, setAsking] = useState(false);
  if (!asking)
    return (
      <button className={p.className ?? "btn"} disabled={p.disabled} onClick={() => setAsking(true)}>
        {p.label}
      </button>
    );
  return (
    <span className="confirm">
      <span>{p.question}</span>
      <button
        className="btn small primary"
        onClick={() => {
          setAsking(false);
          p.onConfirm();
        }}
      >
        Confirm
      </button>
      <button className="btn small" onClick={() => setAsking(false)}>
        Cancel
      </button>
    </span>
  );
}

/** Runs a command, toasting its error; returns its data or undefined on failure. */
function useRunner() {
  const app = useApp();
  return async <T,>(args: string[], input?: CliInput): Promise<T | undefined> => {
    try {
      return await run<T>(args, input);
    } catch (e: any) {
      app.toast(e.message, "error");
      return undefined;
    }
  };
}

function Field(p: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <label className={p.wide ? "wide" : undefined}>
      <span className="label">{p.label}</span>
      {p.children}
    </label>
  );
}

// ---------------- Auth profiles ----------------

interface Session {
  logged_in: boolean;
  cookies: string[];
  token: boolean;
  last_login: string | null;
  last_error: string | null;
  /** Names of the values its macros extracted. */
  vars?: string[];
}

interface Profile {
  name: string;
  login_url?: string;
  login_method: string;
  login_body?: string;
  login_request?: string;
  login_headers: [string, string][];
  username?: string;
  password?: { env: string } | { literal: string };
  csrf_url?: string;
  csrf_regex?: string;
  token_regex?: string;
  token_header?: string;
  logged_in?: string;
  logged_out?: string;
  check_url?: string;
  headers: [string, string][];
  relogin_interval_secs: number;
  max_relogins: number;
  platform?: PlatformAuth;
}

interface ProfileItem {
  name: string;
  login_url: string | null;
  username: string | null;
  session: Session;
}

interface Form {
  name: string;
  loginUrl: string;
  loginMethod: string;
  loginBody: string;
  loginRequestFile: string;
  loginHeaders: string;
  username: string;
  passwordMode: "env" | "literal" | "none";
  passwordEnv: string;
  password: string;
  csrfUrl: string;
  csrfRegex: string;
  tokenRegex: string;
  tokenHeader: string;
  loggedIn: string;
  loggedOut: string;
  checkUrl: string;
  headers: string;
  reloginInterval: string;
  maxRelogins: string;
  platform: PlatformForm;
}

const EMPTY_FORM: Form = {
  name: "",
  loginUrl: "",
  loginMethod: "POST",
  loginBody: "",
  loginRequestFile: "",
  loginHeaders: "",
  username: "",
  passwordMode: "env",
  passwordEnv: "",
  password: "",
  csrfUrl: "",
  csrfRegex: "",
  tokenRegex: "",
  tokenHeader: "",
  loggedIn: "",
  loggedOut: "",
  checkUrl: "",
  headers: "",
  reloginInterval: "5",
  maxRelogins: "20",
  platform: platformForm(),
};

const headerLines = (h: [string, string][]) => h.map(([k, v]) => `${k}: ${v}`).join("\n");

function formOf(p: Profile): Form {
  const pw = p.password;
  return {
    ...EMPTY_FORM,
    name: p.name,
    loginUrl: p.login_url ?? "",
    loginMethod: p.login_method,
    loginBody: p.login_body ?? "",
    loginHeaders: headerLines(p.login_headers),
    username: p.username ?? "",
    // A stored password is redacted by `auth show`, so editing asks for it again.
    passwordMode: !pw ? "none" : "env" in pw ? "env" : "literal",
    passwordEnv: pw && "env" in pw ? pw.env : "",
    csrfUrl: p.csrf_url ?? "",
    csrfRegex: p.csrf_regex ?? "",
    tokenRegex: p.token_regex ?? "",
    tokenHeader: p.token_header ?? "",
    loggedIn: p.logged_in ?? "",
    loggedOut: p.logged_out ?? "",
    checkUrl: p.check_url ?? "",
    headers: headerLines(p.headers),
    reloginInterval: String(p.relogin_interval_secs),
    maxRelogins: String(p.max_relogins),
    platform: platformForm(p.platform),
  };
}

/** `auth add` arguments: --flag=value so values may start with "-", and the name last after "--". */
function addArgs(f: Form): string[] {
  const args = ["auth", "add"];
  const opt = (flag: string, v: string) => v.trim() && args.push(`${flag}=${v.trim()}`);
  const lines = (flag: string, v: string) =>
    v
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .forEach((l) => args.push(`${flag}=${l}`));
  opt("--login-url", f.loginUrl);
  opt("--login-method", f.loginMethod);
  // The login body is a template ({{password}} is filled at login), so it isn't a secret.
  if (f.loginBody) args.push(`--login-body=${f.loginBody}`);
  opt("--login-request", f.loginRequestFile);
  lines("--login-header", f.loginHeaders);
  opt("--username", f.username);
  if (f.passwordMode === "env") opt("--password-env", f.passwordEnv);
  opt("--csrf-url", f.csrfUrl);
  opt("--csrf-regex", f.csrfRegex);
  opt("--token-regex", f.tokenRegex);
  opt("--token-header", f.tokenHeader);
  opt("--logged-in", f.loggedIn);
  opt("--logged-out", f.loggedOut);
  opt("--check-url", f.checkUrl);
  lines("--header", f.headers);
  opt("--relogin-interval", f.reloginInterval);
  opt("--max-relogins", f.maxRelogins);
  args.push(...platformArgs(f.platform));
  // This form doesn't show query keys, so saving it mustn't drop them.
  args.push("--keep-query-keys");
  args.push("--", f.name.trim());
  return args;
}

function SessionState({ s }: { s: Session }) {
  return (
    <span className={`tag ${s.logged_in ? "set-ok" : ""}`} title={s.last_error ?? undefined}>
      {s.logged_in ? "logged in" : s.last_error ? "login failed" : "no session"}
    </span>
  );
}

interface Shown {
  profile: Profile;
  session: Session;
  macros: MacroSummary[];
  rules: SessionRule[];
  signers: Signer[];
}

function Auth() {
  const app = useApp();
  const exec = useRunner();
  const [list, setList] = useState<ProfileItem[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [shown, setShown] = useState<Shown | null>(null);
  const [check, setCheck] = useState<{ url: string; status: number | null; logged_in: boolean } | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [editing, setEditing] = useState(false);
  const [recording, setRecording] = useState(false);
  const [macroProfile, setMacroProfile] = useState<string | null>(null);
  const [busy, setBusy] = useState("");

  const load = async () => {
    const d = await exec<{ profiles: ProfileItem[] }>(["auth", "list"]);
    if (d) setList(d.profiles);
  };
  const show = async (name: string) => {
    const d = await exec<Shown>(["auth", "show", "--", name]);
    if (d) setShown(d);
  };
  useEffect(() => {
    load();
  }, []);
  useEffect(() => {
    setCheck(null);
    if (selected) show(selected);
    else setShown(null);
  }, [selected]);

  const act = async (label: string, args: string[]) => {
    setBusy(label);
    const d = await exec<any>(args);
    setBusy("");
    if (selected) await show(selected);
    load();
    return d;
  };

  const save = async () => {
    if (!form) return;
    if (!form.name.trim()) return app.toast("A profile needs a name", "error");
    // A literal password goes in the environment, never on the command line (`ps` shows that).
    const env = form.passwordMode === "literal" && form.password ? { BRAINPROXY_SECRET_PASSWORD: form.password } : undefined;
    const d = await exec(addArgs(form), { env });
    if (!d) return;
    app.toast(`Saved profile ${form.name.trim()}`);
    setForm(null);
    setSelected(form.name.trim());
    if (selected === form.name.trim()) show(form.name.trim());
    load();
  };

  const remove = async (name: string) => {
    if (!(await exec(["auth", "remove", "--", name]))) return;
    setSelected(null);
    load();
  };

  const set = (patch: Partial<Form>) => form && setForm({ ...form, ...patch });
  const text = (key: { [K in keyof Form]: Form[K] extends string ? K : never }[keyof Form], placeholder = "") => (
    <input className="input" value={form![key]} placeholder={placeholder} onChange={(e) => set({ [key]: e.target.value })} />
  );

  return (
    <Split id="settings-auth" dir="row" initial={0.26}>
      <div className="col fill">
        <div className="toolbar">
          <button
            className="btn primary"
            title="Log in once in a browser; brainproxy works out the profile"
            onClick={() => {
              setForm(null);
              setMacroProfile(null);
              setRecording(true);
            }}
          >
            Record a login
          </button>
          <button
            className="btn"
            onClick={() => {
              setRecording(false);
              setMacroProfile(null);
              setEditing(false);
              setForm({ ...EMPTY_FORM });
            }}
          >
            New profile
          </button>
          <button
            className="btn"
            title="A session with no login: its macros and rules make it"
            onClick={() => {
              setRecording(false);
              setForm(null);
              setMacroProfile("");
            }}
          >
            New macro profile
          </button>
          <span className="grow" />
          <span className="muted">{list.length} profiles</span>
        </div>
        <div className="tree">
          {list.length === 0 && (
            <div className="empty">No auth profiles. Record a login to scan as a logged-in user (--auth NAME).</div>
          )}
          {list.map((p) => (
            <button
              key={p.name}
              className={`tree-item ${selected === p.name && !form ? "on" : ""}`}
              onClick={() => {
                setForm(null);
                setRecording(false);
                setMacroProfile(null);
                setSelected(p.name);
              }}
            >
              <span className="grow ellipsis">
                {p.name}
                {p.username && <span className="muted"> · {p.username}</span>}
              </span>
              <SessionState s={p.session} />
            </button>
          ))}
        </div>
      </div>
      {recording ? (
        <RecordLogin
          onCancel={() => setRecording(false)}
          onDone={(name) => {
            setRecording(false);
            setSelected(name);
            show(name);
            load();
          }}
        />
      ) : macroProfile !== null ? (
        <div className="detail">
          <div className="detail-head">
            <h2>New macro profile</h2>
          </div>
          <p className="muted small">A profile with no login: its macros and session rules make the session. Edit it afterwards to add a check URL or username.</p>
          <div className="form">
            <Field label="Profile name">
              <input className="input" value={macroProfile} onChange={(e) => setMacroProfile(e.target.value)} />
            </Field>
          </div>
          <MacroBuilder
            profile={macroProfile.trim()}
            onCancel={() => setMacroProfile(null)}
            onSaved={() => {
              const name = macroProfile.trim();
              setMacroProfile(null);
              setSelected(name);
              show(name);
              load();
            }}
          />
        </div>
      ) : form ? (
        <div className="detail">
          <div className="detail-head">
            <h2>{editing ? `Edit ${form.name}` : "New auth profile"}</h2>
          </div>
          <p className="muted small">
            A profile logs in (form, JSON, or a raw request), keeps the session, and re-logs in when it sees a 401, a
            redirect to the login page, or the logged-out pattern. Without a login URL it only adds the headers below.
          </p>
          <h3>Profile</h3>
          <div className="form">
            <Field label="Name">
              <input className="input" value={form.name} disabled={editing} onChange={(e) => set({ name: e.target.value })} />
            </Field>
            <Field label="Headers on every request (one per line)" wide>
              <textarea className="input area mono" value={form.headers} placeholder="X-Api-Key: …" onChange={(e) => set({ headers: e.target.value })} />
            </Field>
          </div>
          <h3>Login request</h3>
          <div className="form">
            <Field label="Login URL">{text("loginUrl", "https://app/login")}</Field>
            <Field label="Method">{text("loginMethod", "POST")}</Field>
            <Field label="Body ({{username}}, {{password}}, {{csrf}})" wide>
              <textarea
                className="input area mono"
                value={form.loginBody}
                placeholder="user={{username}}&pass={{password}}  or JSON starting with {"
                onChange={(e) => set({ loginBody: e.target.value })}
              />
            </Field>
            <Field label="Raw request file (replaces method/body)" wide>
              {text("loginRequestFile", "/path/to/login.req")}
            </Field>
            {editing && shown?.profile.login_request && !form.loginRequestFile && (
              <p className="muted small wide">This profile has a stored raw login request; saving without a file drops it.</p>
            )}
            <Field label="Login-only headers (one per line)" wide>
              <textarea className="input area mono" value={form.loginHeaders} onChange={(e) => set({ loginHeaders: e.target.value })} />
            </Field>
            <Field label="CSRF page URL">{text("csrfUrl")}</Field>
            <Field label="CSRF regex (group 1)">{text("csrfRegex", 'name="csrf" value="([^"]+)"')}</Field>
          </div>
          <h3>Credentials</h3>
          <div className="form">
            <Field label="Username">{text("username")}</Field>
            <div>
              <span className="label">Password</span>
              <div className="seg">
                {(["env", "literal", "none"] as const).map((m) => (
                  <button key={m} className={form.passwordMode === m ? "on" : ""} onClick={(e) => (e.preventDefault(), set({ passwordMode: m }))}>
                    {m === "env" ? "Env variable" : m === "literal" ? "Stored" : "None"}
                  </button>
                ))}
              </div>
            </div>
            {form.passwordMode === "env" && <Field label="Environment variable (read at each login, never stored)">{text("passwordEnv", "APP_PASSWORD")}</Field>}
            {form.passwordMode === "literal" && (
              <Field label="Password (stored in the project file)">
                <input
                  className="input"
                  type="password"
                  value={form.password}
                  placeholder={editing ? "re-enter: the stored one is redacted" : ""}
                  onChange={(e) => set({ password: e.target.value })}
                />
              </Field>
            )}
          </div>
          <h3>Platform authentication</h3>
          <p className="muted small">
            HTTP Basic, Digest, or NTLM with the username and password above. brainproxy answers these hosts' 401
            challenges on every command and through the proxy, without --auth; the header is added on the wire only, so
            history never holds it. For NTLM give the domain here or as DOMAIN\user.
          </p>
          <div className="form">
            <div>
              <span className="label">Scheme</span>
              <div className="seg">
                {(["", "basic", "digest", "ntlm"] as const).map((m) => (
                  <button
                    key={m || "none"}
                    className={form.platform.scheme === m ? "on" : ""}
                    onClick={(e) => (e.preventDefault(), set({ platform: { ...form.platform, scheme: m } }))}
                  >
                    {m ? m.toUpperCase() : "None"}
                  </button>
                ))}
              </div>
            </div>
            {form.platform.scheme && (
              <>
                <Field label="Hosts (one pattern per line: app.test, *.corp.test, *)" wide>
                  <textarea
                    className="input area mono"
                    value={form.platform.hosts}
                    placeholder="*.corp.test"
                    onChange={(e) => set({ platform: { ...form.platform, hosts: e.target.value } })}
                  />
                </Field>
                {form.platform.scheme === "ntlm" && (
                  <Field label="Domain">
                    <input className="input" value={form.platform.domain} onChange={(e) => set({ platform: { ...form.platform, domain: e.target.value } })} />
                  </Field>
                )}
              </>
            )}
          </div>
          <h3>Session checks</h3>
          <div className="form">
            <Field label="Logged-in regex">{text("loggedIn", "Logout")}</Field>
            <Field label="Logged-out regex">{text("loggedOut", "session expired")}</Field>
            <Field label="Check URL">{text("checkUrl", "https://app/account")}</Field>
            <Field label="Token regex (group 1)">{text("tokenRegex", '"token":"([^"]+)"')}</Field>
            <Field label="Token header">{text("tokenHeader", "Authorization: Bearer {{token}}")}</Field>
            <Field label="Min seconds between re-logins">{text("reloginInterval")}</Field>
            <Field label="Max re-logins per run">{text("maxRelogins")}</Field>
          </div>
          <div className="row gap set-actions">
            <button className="btn primary" onClick={save}>
              Save profile
            </button>
            <button className="btn" onClick={() => setForm(null)}>
              Cancel
            </button>
          </div>
        </div>
      ) : shown ? (
        <div className="detail">
          <div className="detail-head">
            <h2>{shown.profile.name}</h2>
            <SessionState s={shown.session} />
          </div>
          <div className="toolbar flat">
            <button className="btn primary" disabled={!!busy || !shown.profile.login_url} onClick={() => act("login", ["auth", "login", shown.profile.name])}>
              {busy === "login" ? "Logging in…" : "Login now"}
            </button>
            <button
              className="btn"
              disabled={!!busy}
              onClick={async () => {
                const d = await act("status", ["auth", "status", shown.profile.name]);
                setCheck(d?.check ?? null);
              }}
            >
              {busy === "status" ? "Checking…" : "Status"}
            </button>
            <button
              className="btn"
              onClick={() => {
                setEditing(true);
                setForm(formOf(shown.profile));
              }}
            >
              Edit
            </button>
            <ConfirmButton label="Remove" question={`Remove ${shown.profile.name} and its session?`} onConfirm={() => remove(shown.profile.name)} />
          </div>
          <h3>Session</h3>
          <dl className="facts">
            <dt>State</dt>
            <dd>{shown.session.logged_in ? "logged in" : "not logged in"}</dd>
            <dt>Cookies</dt>
            <dd className="mono">{shown.session.cookies.join(", ") || "none"}</dd>
            <dt>Token</dt>
            <dd>{shown.session.token ? "captured" : "none"}</dd>
            {!!shown.session.vars?.length && (
              <>
                <dt>Macro values</dt>
                <dd className="mono">{shown.session.vars.join(", ")}</dd>
              </>
            )}
            <dt>Last login</dt>
            <dd>{shown.session.last_login ?? "never"}</dd>
            {shown.session.last_error && (
              <>
                <dt>Last error</dt>
                <dd className="set-err">{shown.session.last_error}</dd>
              </>
            )}
            {check && (
              <>
                <dt>Check URL</dt>
                <dd>
                  {check.logged_in ? "valid" : "logged out"} ({check.status ?? "no response"}) · <span className="mono">{check.url}</span>
                </dd>
              </>
            )}
          </dl>
          <h3>Profile</h3>
          <dl className="facts">
            {(
              [
                ["Login", shown.profile.login_url && `${shown.profile.login_method} ${shown.profile.login_url}`],
                ["Body", shown.profile.login_body],
                ["Raw request", shown.profile.login_request],
                ["Login headers", headerLines(shown.profile.login_headers)],
                ["Username", shown.profile.username],
                ["Password", shown.profile.password && ("env" in shown.profile.password ? `$${shown.profile.password.env}` : "stored (redacted)")],
                ["CSRF", shown.profile.csrf_url && `${shown.profile.csrf_url}  ${shown.profile.csrf_regex ?? ""}`],
                ["Token", shown.profile.token_regex && `${shown.profile.token_regex} → ${shown.profile.token_header ?? ""}`],
                ["Logged in", shown.profile.logged_in],
                ["Logged out", shown.profile.logged_out],
                ["Check URL", shown.profile.check_url],
                ["Headers", headerLines(shown.profile.headers)],
                ["Platform auth", shown.profile.platform && describePlatform(shown.profile.platform)],
                ["Re-login", `at most ${shown.profile.max_relogins} per run, ${shown.profile.relogin_interval_secs} s apart`],
              ] as [string, string | undefined][]
            )
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <Fragment key={k}>
                  <dt>{k}</dt>
                  <dd className="mono set-pre">{v}</dd>
                </Fragment>
              ))}
          </dl>
          {/* Keyed: an open form belongs to its profile and mustn't save to the next one. */}
          <SessionHandling
            key={shown.profile.name}
            profile={shown.profile.name}
            macros={shown.macros ?? []}
            rules={shown.rules ?? []}
            signers={shown.signers ?? []}
            hasCheckUrl={!!shown.profile.check_url}
            hasLogin={!!shown.profile.login_url}
            onChange={() => show(shown.profile.name)}
          />
          <p className="muted small">
            Use it with <span className="mono">--auth {shown.profile.name}</span> on send, fuzz, crawl, scan active, and proxy start.
          </p>
        </div>
      ) : (
        <div className="blank">Select a profile, or add one.</div>
      )}
    </Split>
  );
}

// ---------------- Connections ----------------

/** Upstream proxies, host overrides, client certificates, and TLS pass-through (`connection *`). */
function Connections() {
  const exec = useRunner();
  const [s, setS] = useState<ConnectionSettings | null>(null);
  const [up, setUp] = useState<UpstreamForm>({ ...EMPTY_UPSTREAM });
  const [host, setHost] = useState({ host: "", ip: "" });
  const [cert, setCert] = useState<CertForm>({ ...EMPTY_CERT });
  const [pass, setPass] = useState("");
  const [probe, setProbe] = useState("");
  const [route, setRoute] = useState<any>(null);

  // Every connection command answers with the full settings.
  const apply = async (args: string[]) => {
    const d = await exec<ConnectionSettings>(args);
    if (d) setS(d);
    return d;
  };
  useEffect(() => {
    apply(["connection", "show"]);
  }, []);
  if (!s) return <div className="blank">Loading…</div>;

  const remove = (what: string, h: string) => (
    <button className="btn small" onClick={() => apply(["connection", what, "remove", `--host=${h}`])}>
      Remove
    </button>
  );

  return (
    <div className="detail">
      <div className="detail-head">
        <h2>Connections</h2>
      </div>
      <p className="muted small">
        These apply to every request brainproxy sends (send, scans, crawl, fuzz, imports, logins, and the proxy's
        upstream side). A running proxy picks up changes within a second. None of them widens the engagement scope:
        every target is still resolved and checked, and passwords are read from environment variables, never stored.
      </p>
      {s.warnings.length > 0 && (
        <ul className="set-err small">
          {s.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}

      <h3>Upstream proxies</h3>
      <p className="muted small">
        First matching host pattern wins; no match connects directly. The proxy is asked for the address brainproxy
        checked, never the name. Proxies on this machine work as they are; others must be listed when the engagement
        starts (<span className="mono">engagement start --proxy HOST:PORT</span>).
      </p>
      <table className="set-table">
        <tbody>
          {s.upstream.map((r) => (
            <tr key={r.host}>
              <td className="mono">{r.host}</td>
              <td className="mono">{r.proxy ?? <span className="muted">direct</span>}</td>
              <td className="mono">{r.username ? `${r.username}${r.password_env ? ` · $${r.password_env}` : ""}` : ""}</td>
              <td>{remove("upstream", r.host)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="toolbar flat">
        <input className="input mono" placeholder="host pattern" value={up.host} onChange={(e) => setUp({ ...up, host: e.target.value })} />
        <label className="check">
          <input type="checkbox" checked={up.direct} onChange={(e) => setUp({ ...up, direct: e.target.checked })} /> direct
        </label>
        {!up.direct && (
          <>
            <input className="input grow mono" placeholder="socks5://127.0.0.1:1080 or http://proxy:3128" value={up.proxy} onChange={(e) => setUp({ ...up, proxy: e.target.value })} />
            <input className="input" placeholder="username" value={up.username} onChange={(e) => setUp({ ...up, username: e.target.value })} />
            <input className="input mono" placeholder="password env var" value={up.passwordEnv} onChange={(e) => setUp({ ...up, passwordEnv: e.target.value })} />
          </>
        )}
        <label className="check">
          <input type="checkbox" checked={up.first} onChange={(e) => setUp({ ...up, first: e.target.checked })} /> first
        </label>
        <button
          className="btn primary"
          disabled={!up.host.trim() || (!up.direct && !up.proxy.trim())}
          onClick={async () => (await apply(upstreamAddArgs(up))) && setUp({ ...EMPTY_UPSTREAM })}
        >
          Add
        </button>
      </div>

      <h3>Host overrides</h3>
      <p className="muted small">
        Like /etc/hosts: connect to this address for the name. The name must be in scope, and a private, loopback, or
        link-local address must also be listed in the scope by address. A public address needs no listing;
        TLS SNI and the Host header stay the name.
      </p>
      <table className="set-table">
        <tbody>
          {s.hosts.map((h) => (
            <tr key={h.host}>
              <td className="mono">{h.host}</td>
              <td className="mono">{h.ip}</td>
              <td>
                <button className="btn small" onClick={() => apply(["connection", "hosts", "remove", "--", h.host])}>
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="toolbar flat">
        <input className="input mono" placeholder="app.test" value={host.host} onChange={(e) => setHost({ ...host, host: e.target.value })} />
        <input className="input mono" placeholder="10.0.0.5" value={host.ip} onChange={(e) => setHost({ ...host, ip: e.target.value })} />
        <button
          className="btn primary"
          disabled={!host.host.trim() || !host.ip.trim()}
          onClick={async () => (await apply(hostsAddArgs(host.host, host.ip))) && setHost({ host: "", ip: "" })}
        >
          Add
        </button>
      </div>

      <h3>Client certificates (mutual TLS)</h3>
      <p className="muted small">Offered to matching hosts over HTTP/1.1 and HTTP/2. The files are read when settings load.</p>
      <table className="set-table">
        <tbody>
          {s.client_certs.map((c) => (
            <tr key={c.host}>
              <td className="mono">{c.host}</td>
              <td className="mono">{c.pkcs12 ? `${c.pkcs12}${c.password_env ? ` · $${c.password_env}` : ""}` : `${c.cert} + ${c.key}`}</td>
              <td>{remove("cert", c.host)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="toolbar flat">
        <input className="input mono" placeholder="host pattern" value={cert.host} onChange={(e) => setCert({ ...cert, host: e.target.value })} />
        <div className="seg">
          {(["pem", "pkcs12"] as const).map((k) => (
            <button key={k} className={cert.kind === k ? "on" : ""} onClick={() => setCert({ ...cert, kind: k })}>
              {k === "pem" ? "PEM" : "PKCS#12"}
            </button>
          ))}
        </div>
        {cert.kind === "pem" ? (
          <>
            <input className="input grow mono" placeholder="/path/client.pem" value={cert.cert} onChange={(e) => setCert({ ...cert, cert: e.target.value })} />
            <input className="input grow mono" placeholder="/path/client.key" value={cert.key} onChange={(e) => setCert({ ...cert, key: e.target.value })} />
          </>
        ) : (
          <>
            <input className="input grow mono" placeholder="/path/client.p12" value={cert.pkcs12} onChange={(e) => setCert({ ...cert, pkcs12: e.target.value })} />
            <input className="input mono" placeholder="password env var" value={cert.passwordEnv} onChange={(e) => setCert({ ...cert, passwordEnv: e.target.value })} />
          </>
        )}
        <button
          className="btn primary"
          disabled={!cert.host.trim() || (cert.kind === "pem" ? !cert.cert.trim() || !cert.key.trim() : !cert.pkcs12.trim())}
          onClick={async () => (await apply(certAddArgs(cert))) && setCert({ ...EMPTY_CERT })}
        >
          Add
        </button>
      </div>

      <h3>TLS pass-through</h3>
      <p className="muted small">
        The proxy tunnels these hosts' TLS without decrypting it (for certificate pinning, or traffic you shouldn't see).
        Still scope-checked; each connection is recorded without its content.
      </p>
      <div className="toolbar flat">
        {s.passthrough.map((p) => (
          <span key={p} className="tag mono">
            {p}{" "}
            <button className="btn small" onClick={() => apply(["connection", "passthrough", "remove", "--", p])}>
              ×
            </button>
          </span>
        ))}
      </div>
      <div className="toolbar flat">
        <input className="input grow mono" placeholder="bank.test *.pinned.test" value={pass} onChange={(e) => setPass(e.target.value)} />
        <button className="btn primary" disabled={!pass.trim()} onClick={async () => (await apply(passthroughAddArgs(pass))) && setPass("")}>
          Add
        </button>
      </div>

      <h3>Check a target</h3>
      <div className="toolbar flat">
        <input className="input grow mono" placeholder="https://app.test/" value={probe} onChange={(e) => setProbe(e.target.value)} />
        <button className="btn" disabled={!probe.trim()} onClick={async () => setRoute(await exec(["connection", "route", "--", probe.trim()]))}>
          Show route
        </button>
      </div>
      {route && <pre className="mono set-pre small">{JSON.stringify(route, null, 2)}</pre>}

      <div className="row gap set-actions">
        <ConfirmButton label="Clear all" question="Remove every connection option?" onConfirm={() => apply(["connection", "clear"])} />
      </div>
    </div>
  );
}

// ---------------- Match & replace ----------------

interface Rule {
  id: number;
  location: string;
  pattern: string;
  replace: string;
  enabled: boolean;
  comment?: string;
}

const LOCATIONS = ["request-line", "request-header", "request-body", "response-header", "response-body"];

function Rules() {
  const exec = useRunner();
  const [rules, setRules] = useState<Rule[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [draft, setDraft] = useState({ location: "request-header", match: "", replace: "", comment: "", disabled: false });

  // Every rules command answers with the full list.
  const apply = async (args: string[]) => {
    const d = await exec<{ rules: Rule[] }>(args);
    if (d) setRules(d.rules);
    return d;
  };
  useEffect(() => {
    apply(["rules", "list"]);
  }, []);

  const add = async () => {
    const args = ["rules", "add", `--location=${draft.location}`, `--match=${draft.match}`, `--replace=${draft.replace}`];
    if (draft.comment) args.push(`--comment=${draft.comment}`);
    if (draft.disabled) args.push("--disabled");
    if (await apply(args)) setDraft({ ...draft, match: "", replace: "", comment: "" });
  };

  const columns: Column<Rule>[] = [
    {
      key: "enabled",
      label: "On",
      width: 40,
      value: (r) => (r.enabled ? 1 : 0),
      render: (r) => (
        <input
          type="checkbox"
          checked={r.enabled}
          onClick={(e) => e.stopPropagation()}
          onChange={() => apply(["rules", r.enabled ? "disable" : "enable", String(r.id)])}
        />
      ),
    },
    { key: "location", label: "Where", width: 120, value: (r) => r.location },
    { key: "pattern", label: "Match", width: 240, value: (r) => r.pattern, render: (r) => (r.pattern ? <span className="mono">{r.pattern}</span> : <span className="muted">(add header)</span>) },
    { key: "replace", label: "Replace", width: 240, value: (r) => r.replace, render: (r) => (r.replace ? <span className="mono">{r.replace}</span> : <span className="muted">(remove)</span>) },
    { key: "comment", label: "Comment", width: 220, value: (r) => r.comment ?? "" },
  ];

  const header = draft.location.endsWith("-header");
  return (
    <div className="col fill">
      <div className="toolbar">
        <select className="input" value={draft.location} onChange={(e) => setDraft({ ...draft, location: e.target.value })}>
          {LOCATIONS.map((l) => (
            <option key={l}>{l}</option>
          ))}
        </select>
        <input className="input grow mono" placeholder={header ? "match regex (empty: add a header)" : "match regex"} value={draft.match} onChange={(e) => setDraft({ ...draft, match: e.target.value })} />
        <input className="input grow mono" placeholder="replace ($1 groups; empty removes)" value={draft.replace} onChange={(e) => setDraft({ ...draft, replace: e.target.value })} />
        <input className="input" placeholder="comment" value={draft.comment} onChange={(e) => setDraft({ ...draft, comment: e.target.value })} />
        <label className="check">
          <input type="checkbox" checked={draft.disabled} onChange={(e) => setDraft({ ...draft, disabled: e.target.checked })} /> disabled
        </label>
        <button className="btn primary" disabled={!draft.match && !draft.replace} onClick={add}>
          Add rule
        </button>
        <span className="sep" />
        <button className="btn" disabled={selected == null} onClick={() => selected != null && apply(["rules", "remove", String(selected)]).then(() => setSelected(null))}>
          Remove
        </button>
        <ConfirmButton label="Clear all" question="Remove every rule?" disabled={!rules.length} onConfirm={() => apply(["rules", "clear"])} />
      </div>
      <DataTable
        rows={rules}
        columns={columns}
        rowKey={(r) => r.id}
        selected={selected}
        onSelect={(r) => setSelected(r.id)}
        initialSort={{ key: "enabled", desc: false }}
        rowClass={(r) => (r.enabled ? undefined : "set-off")}
        empty="No match-and-replace rules. The proxy applies enabled rules to every request and response it relays."
      />
    </div>
  );
}

// ---------------- Intercept options ----------------

function Intercept() {
  const app = useApp();
  const exec = useRunner();
  const [current, setCurrent] = useState<InterceptSettings | null>(null);
  const [draft, setDraft] = useState<InterceptSettings | null>(null);

  const load = async () => {
    const d = await exec<{ settings: InterceptSettings }>(["intercept", "status"]);
    if (d) {
      setCurrent(d.settings);
      setDraft(d.settings);
    }
  };
  useEffect(() => {
    load();
  }, []);

  // `intercept enable` is the only way to set filters and it turns intercept on, so when
  // it was off we disable it again right away; `disable` keeps the settings.
  const applyDraft = async () => {
    if (!draft || !current) return;
    const ok = await exec(interceptEnableArgs({ ...draft, requests: draft.requests || !draft.responses }));
    if (ok && !current.enabled) await exec(["intercept", "disable"]);
    if (ok) app.toast("Intercept options saved");
    load();
  };

  if (!draft || !current) return <div className="blank">Loading…</div>;
  const set = (patch: Partial<InterceptSettings>) => setDraft({ ...draft, ...patch });
  const changed = JSON.stringify(draft) !== JSON.stringify(current);
  return (
    <div className="detail">
      <div className="detail-head">
        <h2>Intercept options</h2>
        <span className={`tag ${current.enabled ? "set-ok" : ""}`}>intercept {current.enabled ? "on" : "off"}</span>
      </div>
      <p className="muted small">
        {current.enabled
          ? "Intercept is on: saved options apply to the next message the proxy sees."
          : "Intercept is off and stays off when you save; these options apply once you turn it on in Proxy → Intercept."}
      </p>
      <h3>Hold</h3>
      <div className="row gap">
        <label className="check">
          <input type="checkbox" checked={draft.requests} onChange={(e) => set({ requests: e.target.checked })} /> Requests
        </label>
        <label className="check">
          <input type="checkbox" checked={draft.responses} onChange={(e) => set({ responses: e.target.checked })} /> Responses
        </label>
      </div>
      <h3>Only messages matching (regex, empty for all)</h3>
      <div className="form">
        <Field label="Host">
          <input className="input mono" value={draft.host ?? ""} placeholder="example\.com$" onChange={(e) => set({ host: e.target.value })} />
        </Field>
        <Field label="Path">
          <input className="input mono" value={draft.path ?? ""} placeholder="^/api/" onChange={(e) => set({ path: e.target.value })} />
        </Field>
        <Field label="Method">
          <input className="input mono" value={draft.method ?? ""} placeholder="POST|PUT" onChange={(e) => set({ method: e.target.value })} />
        </Field>
      </div>
      <h3>Unanswered messages</h3>
      <div className="form">
        <Field label="Timeout (seconds)">
          <input className="input" type="number" min={1} value={draft.timeout_secs} onChange={(e) => set({ timeout_secs: Number(e.target.value) })} />
        </Field>
        <Field label="Then">
          <select className="input" value={draft.timeout_action} onChange={(e) => set({ timeout_action: e.target.value })}>
            <option value="forward">forward</option>
            <option value="drop">drop</option>
          </select>
        </Field>
      </div>
      {!draft.requests && !draft.responses && <p className="muted small">With neither box checked, requests are held.</p>}
      <div className="row gap set-actions">
        <button className="btn primary" disabled={!changed} onClick={applyDraft}>
          Save
        </button>
        <button className="btn" disabled={!changed} onClick={() => setDraft(current)}>
          Revert
        </button>
      </div>
    </div>
  );
}

// ---------------- TLS / CA ----------------

function Ca() {
  const app = useApp();
  const exec = useRunner();
  const [ca, setCa] = useState<{ cert_path: string; pem: string; sha256: string } | null>(null);

  // `ca export` creates the CA on first use, like the proxy does.
  const load = async () => setCa((await exec<{ cert_path: string; pem: string; sha256: string }>(["ca", "export"])) ?? null);
  useEffect(() => {
    load();
  }, []);

  const init = async (force: boolean) => {
    const d = await exec<{ created: boolean }>(["ca", "init", ...(force ? ["--force"] : [])]);
    if (d) app.toast(d.created ? "New CA created; trust it again in every client" : "The CA already exists");
    load();
  };

  return (
    <div className="detail">
      <div className="detail-head">
        <h2>Interception CA</h2>
      </div>
      <p className="muted small">
        The proxy signs a certificate per HTTPS host with this CA. It is per user (not per project) and stays on this machine.
      </p>
      {ca && (
        <>
          <dl className="facts">
            <dt>Certificate</dt>
            <dd className="mono">{ca.cert_path}</dd>
            <dt>SHA-256</dt>
            <dd className="mono">{ca.sha256}</dd>
          </dl>
          <div className="toolbar flat">
            <button className="btn primary" onClick={() => navigator.clipboard.writeText(ca.pem).then(() => app.toast("PEM copied"))}>
              Copy PEM
            </button>
            <button className="btn" onClick={() => navigator.clipboard.writeText(ca.cert_path).then(() => app.toast("Path copied"))}>
              Copy path
            </button>
            <button className="btn" onClick={() => init(false)}>
              Create if missing
            </button>
            <ConfirmButton
              label="Regenerate…"
              question="Replace the CA? Every client that trusts the old one must trust the new one."
              onConfirm={() => init(true)}
            />
          </div>
          <pre className="code set-pem">{ca.pem}</pre>
        </>
      )}
      <h3>Trust it</h3>
      <dl className="facts">
        <dt>macOS</dt>
        <dd className="mono">sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{ca?.cert_path ?? "ca.pem"}"</dd>
        <dt>Windows</dt>
        <dd className="mono">certutil -addstore -f Root "{ca?.cert_path ?? "ca.pem"}"</dd>
        <dt>Debian/Ubuntu</dt>
        <dd className="mono">
          sudo cp "{ca?.cert_path ?? "ca.pem"}" /usr/local/share/ca-certificates/brainproxy.crt && sudo update-ca-certificates
        </dd>
        <dt>Fedora/RHEL</dt>
        <dd className="mono">sudo cp "{ca?.cert_path ?? "ca.pem"}" /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust</dd>
        <dt>Firefox</dt>
        <dd>Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities → Import (it keeps its own store).</dd>
        <dt>Android / iOS</dt>
        <dd>Install the PEM as a user CA (Android apps must opt in to user CAs); on iOS also enable full trust in About → Certificate Trust Settings.</dd>
      </dl>
    </div>
  );
}

// ---------------- Rules & data ----------------

interface ChecksStatus {
  nuclei_dir: string;
  nuclei?: { repository: string; ref: string; commit: string; source: string; updated_unix: number; templates: number; stored: number; skipped: [string, number][] };
  local_dir: string;
  local_files: number;
}

interface DataFile {
  name: string;
  rules: number[];
  active: string;
  entries: number;
  embedded_entries: number;
}

function RuleData() {
  const app = useApp();
  const exec = useRunner();
  const [checks, setChecks] = useState<ChecksStatus | null>(null);
  const [data, setData] = useState<{ dir: string; embedded_commit: string; files: DataFile[] } | null>(null);
  const [opts, setOpts] = useState({ checksRef: "main", checksFrom: "", dataRef: "main", dataFrom: "" });
  const [busy, setBusy] = useState("");

  const load = async () => {
    setChecks((await exec<ChecksStatus>(["checks", "status"])) ?? null);
    setData((await exec<{ dir: string; embedded_commit: string; files: DataFile[] }>(["scan", "data", "status"])) ?? null);
  };
  useEffect(() => {
    load();
  }, []);

  const job = async (label: string, args: string[]) => {
    setBusy(label);
    const d = await exec(args);
    setBusy("");
    if (d) app.toast(`${label} done`);
    load();
  };

  const from = (flag: string, ref: string, dir: string) => [dir.trim() ? `--from=${dir.trim()}` : `${flag}=${ref.trim() || "main"}`];
  const n = checks?.nuclei;
  return (
    <div className="detail">
      <div className="detail-head">
        <h2>Declarative checks (Nuclei templates)</h2>
      </div>
      {checks && (
        <dl className="facts">
          <dt>Templates</dt>
          <dd>
            {n ? (
              <>
                {n.stored} stored of {n.templates} · {n.repository}@{n.ref} ({n.commit.slice(0, 10)}) · updated{" "}
                {new Date(n.updated_unix * 1000).toLocaleString()}
              </>
            ) : (
              "not downloaded"
            )}
          </dd>
          <dt>Directory</dt>
          <dd className="mono">{checks.nuclei_dir}</dd>
          <dt>Local checks</dt>
          <dd>
            {checks.local_files} files in <span className="mono">{checks.local_dir}</span>
          </dd>
          {!!n?.skipped.length && (
            <>
              <dt>Skipped</dt>
              <dd>{n.skipped.slice(0, 8).map(([why, count]) => `${why} (${count})`).join(" · ")}</dd>
            </>
          )}
        </dl>
      )}
      <div className="toolbar flat">
        <input className="input" title="Branch, tag, or commit" value={opts.checksRef} onChange={(e) => setOpts({ ...opts, checksRef: e.target.value })} />
        <input className="input grow" placeholder="or import a local nuclei-templates checkout" value={opts.checksFrom} onChange={(e) => setOpts({ ...opts, checksFrom: e.target.value })} />
        <ConfirmButton
          label={busy === "Checks update" ? "Updating…" : opts.checksFrom ? "Import" : "Download"}
          disabled={!!busy}
          question={opts.checksFrom ? "Import templates from this directory?" : "Download the Nuclei templates from GitHub?"}
          onConfirm={() => job("Checks update", ["checks", "update", ...from("--ref", opts.checksRef, opts.checksFrom)])}
        />
      </div>

      <div className="detail-head set-section">
        <h2>Scan rule data (ZAP files)</h2>
      </div>
      {data && (
        <>
          <p className="muted small">
            Embedded copy from zap-extensions {data.embedded_commit.slice(0, 10)}; downloads go to <span className="mono">{data.dir}</span>. New
            data applies to commands started afterwards (restart a running proxy).
          </p>
          <table className="set-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Rules</th>
                <th>Using</th>
                <th className="right">Entries</th>
              </tr>
            </thead>
            <tbody>
              {data.files.map((f) => (
                <tr key={f.name}>
                  <td className="mono">{f.name}</td>
                  <td>{f.rules.join(", ")}</td>
                  <td>{f.active}</td>
                  <td className="right">
                    {f.entries}
                    {f.entries !== f.embedded_entries && <span className="muted"> (embedded {f.embedded_entries})</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      <div className="toolbar flat">
        <input className="input" title="Branch, tag, or commit" value={opts.dataRef} onChange={(e) => setOpts({ ...opts, dataRef: e.target.value })} />
        <input className="input grow" placeholder="or a local zap-extensions checkout / directory with the files" value={opts.dataFrom} onChange={(e) => setOpts({ ...opts, dataFrom: e.target.value })} />
        <ConfirmButton
          label={busy === "Data update" ? "Updating…" : opts.dataFrom ? "Import" : "Download"}
          disabled={!!busy}
          question={opts.dataFrom ? "Import the data files from this directory?" : "Download the data files from GitHub?"}
          onConfirm={() => job("Data update", ["scan", "data", "update", ...from("--ref", opts.dataRef, opts.dataFrom)])}
        />
        <ConfirmButton label="Reset to embedded" disabled={!!busy} question="Delete the downloaded copies?" onConfirm={() => job("Data reset", ["scan", "data", "reset"])} />
      </div>
      <AppUpdateSettings />
    </div>
  );
}

// ---------------- Proxy ----------------

interface ProxyStatus {
  running: boolean;
  proxy: {
    listen: string;
    ca_cert?: string;
    usage?: { proxy_url: string; curl: string; env: string; trust_ca_for_tools: string; chromium: string; note?: string };
  } | null;
  proxy_captures: number;
  pending_intercepts: number;
  intercept_enabled: boolean;
}

/** Whether the proxy runs, and how to point a browser, curl, or a shell at it. */
function ProxySetup() {
  const exec = useRunner();
  const [proxy, refresh] = usePoll<ProxyStatus>(() => run(["proxy", "status"]), 3000);
  const start = async () => {
    await exec(["proxy", "start"]);
    refresh();
  };
  const usage = proxy?.proxy?.usage;
  return (
    <div className="detail">
      <div className="detail-head">
        <h2>Proxy</h2>
        <span className={proxy?.running ? "s2" : "muted"}>{proxy?.running ? `listening on ${proxy.proxy?.listen}` : "off"}</span>
        {!proxy?.running && proxy && (
          <button className="btn small primary" onClick={start}>
            Start proxy
          </button>
        )}
      </div>
      {usage ? (
        <dl className="facts">
          <dt>Proxy URL</dt>
          <dd className="mono">{usage.proxy_url}</dd>
          {proxy?.proxy?.ca_cert && (
            <>
              <dt>CA certificate</dt>
              <dd className="mono">{proxy.proxy.ca_cert}</dd>
            </>
          )}
          <dt>Browser</dt>
          <dd>Set the HTTP and HTTPS proxy to {usage.proxy_url} and trust the CA certificate above (or import it into the browser; see TLS / CA).</dd>
          <dt>Chromium</dt>
          <dd className="mono">{usage.chromium}</dd>
          <dt>curl</dt>
          <dd className="mono">{usage.curl}</dd>
          <dt>Shell</dt>
          <dd className="mono">{usage.env}</dd>
          <dt>Captured</dt>
          <dd>
            {proxy?.proxy_captures ?? 0} requests{proxy?.intercept_enabled ? ` · intercept on (${proxy.pending_intercepts} held)` : ""}
          </dd>
        </dl>
      ) : (
        <p className="muted">Start the proxy, then point a browser at it to record traffic into this project.</p>
      )}
    </div>
  );
}

// ---------------- Project ----------------

interface Engagement {
  system: unknown;
  system_file: string | null;
  engagement: { name: string | null; include: string[]; exclude: string[] } | null;
  enforced: boolean;
  rule: string;
}

function Project() {
  const [auto, setAuto] = useState(autoProxy);
  const app = useApp();
  const exec = useRunner();
  const [info, setInfo] = useState<{ path: string; history_count: number } | null>(null);
  const [eng, setEng] = useState<Engagement | null>(null);
  useEffect(() => {
    exec<{ path: string; history_count: number }>(["project", "info"]).then((d) => d && setInfo(d));
    exec<Engagement>(["engagement", "show"]).then((d) => d && setEng(d));
  }, []);

  const e = eng?.engagement;
  return (
    <div className="detail">
      <div className="detail-head">
        <h2>Project</h2>
        <label className="check" style={{ margin: "8px 0 14px" }}>
          <input
            type="checkbox"
            checked={auto}
            onChange={(e) => {
              setAuto(e.target.checked);
              try {
                localStorage.setItem(AUTO_PROXY, e.target.checked ? "on" : "off");
              } catch {
                /* storage unavailable */
              }
            }}
          />{" "}
          Start the proxy when a project opens (port 8080, or the next free one), and stop it when the project closes
        </label>
      </div>
      <dl className="facts">
        <dt>File</dt>
        <dd className="mono">{info?.path ?? app.project}</dd>
        <dt>Storage</dt>
        <dd>
          {app.temp ? (
            <>
              Temporary, {app.temp.ramBacked ? "in memory (RAM)" : "in the temp folder on disk"}: deleted when you discard it.{" "}
              <button className="link" onClick={() => app.saveAs().catch((e) => app.toast(`Not saved: ${e.message}`, "error"))}>
                Save as…
              </button>
            </>
          ) : (
            "Saved project file"
          )}
        </dd>
        <dt>History</dt>
        <dd>{info ? `${info.history_count} requests` : "…"}</dd>
      </dl>
      <h3>Engagement (read-only)</h3>
      {eng && (
        <dl className="facts">
          <dt>Name</dt>
          <dd>{e?.name ?? "unnamed"}</dd>
          <dt>Targets</dt>
          <dd className="mono">{e?.include.join(", ") || "none (nothing can be sent)"}</dd>
          <dt>Excluded</dt>
          <dd className="mono">{e?.exclude.join(", ") || "none"}</dd>
          <dt>System scope</dt>
          <dd className="mono">{eng.system_file ?? (eng.system ? "set" : "none")}</dd>
          <dt>Enforced</dt>
          <dd>{eng.enforced ? "yes" : "no"}</dd>
        </dl>
      )}
      {eng && <p className="muted small">{eng.rule} Start or inspect it with brainproxy engagement start / show.</p>}
    </div>
  );
}

// ---------------- Open source licenses ----------------

/** The projects brainproxy's rules, checks and payloads come from (full terms in NOTICE). */
const CREDITS: { name: string; what: string; license: string; url: string }[] = [
  { name: "OWASP ZAP", what: "Passive and active scan rules, their alert texts, payloads and data files are ported from ZAP and its add-ons. Copyright the ZAP development team.", license: "Apache-2.0", url: "https://github.com/zaproxy/zaproxy" },
  { name: "Retire.js", what: "The database of vulnerable JavaScript library versions behind the Vulnerable JS Library rule, as ZAP's retire add-on ships it. Copyright the Retire.js authors.", license: "Apache-2.0", url: "https://github.com/RetireJS/retire.js" },
  { name: "Nuclei and nuclei-templates", what: "Declarative checks run Nuclei HTTP templates (downloaded on request, not bundled); the template format, DSL and interactsh matchers follow Nuclei and interactsh. Copyright ProjectDiscovery, Inc.", license: "MIT", url: "https://github.com/projectdiscovery/nuclei-templates" },
  { name: "SecLists", what: "Fuzzer wordlists (sqli, xss, ssti, usernames, passwords, ...). Copyright Daniel Miessler.", license: "MIT", url: "https://github.com/danielmiessler/SecLists" },
  { name: "PayloadsAllTheThings", what: "Fuzzer wordlists (sqli, xss, path traversal, command injection, nosqli). Copyright Swissky.", license: "MIT", url: "https://github.com/swisskyrepo/PayloadsAllTheThings" },
  { name: "FuzzDB", what: "Command-injection and time-based SQLi wordlists. Copyright Adam Muntner.", license: "BSD-3-Clause", url: "https://github.com/fuzzdb-project/fuzzdb" },
  { name: "Param Miner", what: "Parameter and header name wordlists. Copyright PortSwigger Web Security and James Kettle.", license: "Apache-2.0", url: "https://github.com/PortSwigger/param-miner" },
  { name: "Big List of Naughty Strings", what: "The naughty-strings wordlist. Copyright Max Woolf.", license: "MIT", url: "https://github.com/minimaxir/big-list-of-naughty-strings" },
  { name: "fuzz.txt", what: "The content-discovery wordlist, by Bo0oM.", license: "WTFPL", url: "https://github.com/Bo0oM/fuzz.txt" },
];

function Licenses() {
  return (
    <div className="detail">
      <h2>Open source licenses</h2>
      <p className="muted">
        brainproxy is licensed under the Apache License 2.0 and builds on the work of these projects. Thank you to
        their authors and contributors.
      </p>
      <h3>Rules, checks and payloads</h3>
      <dl className="facts lic-credits">
        {CREDITS.map((c) => (
          <Fragment key={c.name}>
            <dt>{c.name}</dt>
            <dd>
              {c.what}{" "}
              <span className="lic-tag">{c.license}</span> <span className="mono muted">{c.url}</span>
            </dd>
          </Fragment>
        ))}
      </dl>
      <details className="lic-notice">
        <summary>NOTICE (full attribution and license texts)</summary>
        <pre>{NOTICE}</pre>
      </details>
    </div>
  );
}
