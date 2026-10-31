// Settings › Auth profiles › a profile's macros, session rules and request signers. A macro
// is built by picking requests from Traffic in order and saying what to extract from each
// response; a rule says, for some tools and URLs, what to do before each request goes out; a
// signer says how to compute a rule's signature or JWT, and where its key is.

import { useEffect, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import {
  EMPTY_SIGNER,
  EXTRACT_FROM,
  HMAC_HASHES,
  HMAC_OUTPUTS,
  JWT_ALGS,
  KEY_ENCODINGS,
  TOOLS,
  actionLabel,
  macroAddArgs,
  parseParams,
  ruleAddArgs,
  ruleProblems,
  signerAddArgs,
  signerForm,
  signerLabel,
  signerProblems,
  type Action,
  type ExtractRow,
  type MacroRun,
  type MacroSummary,
  type RuleForm,
  type SessionRule,
  type Signer,
  type SignerForm,
  type Tool,
} from "./sessionRules";

interface Props {
  profile: string;
  macros: MacroSummary[];
  rules: SessionRule[];
  signers: Signer[];
  hasCheckUrl: boolean;
  hasLogin: boolean;
  /** Reload the profile after a change. */
  onChange: () => void;
}

function useExec() {
  const app = useApp();
  return async <T,>(args: string[]): Promise<T | undefined> => {
    try {
      return await run<T>(args);
    } catch (e: any) {
      app.toast(e.message, "error");
      return undefined;
    }
  };
}

export function SessionHandling(p: Props) {
  const exec = useExec();
  const [building, setBuilding] = useState(false);
  const [ruleForm, setRuleForm] = useState<RuleForm | null>(null);
  const [signer, setSigner] = useState<{ form: SignerForm; editing: boolean } | null>(null);
  const [runs, setRuns] = useState<Record<string, MacroRun | string>>({});
  const [busy, setBusy] = useState("");

  const runMacro = async (name: string) => {
    setBusy(name);
    try {
      const d = await run<{ run: MacroRun }>(["auth", "macro", "run", "--", p.profile, name]);
      setRuns((r) => ({ ...r, [name]: d.run }));
    } catch (e: any) {
      // An incomplete run fails with the steps in its message.
      setRuns((r) => ({ ...r, [name]: e.message }));
    }
    setBusy("");
    p.onChange();
  };
  const removeMacro = async (name: string) => {
    if (!(await confirm(`Remove macro ${name}?`, "Session rules that run it must be removed first.", "Remove", "Cancel"))) return;
    if (await exec(["auth", "macro", "remove", "--", p.profile, name])) p.onChange();
  };
  const removeRule = async (id: number) => {
    if (await exec(["auth", "rule", "remove", "--", p.profile, String(id)])) p.onChange();
  };
  const removeSigner = async (name: string) => {
    if (!(await confirm(`Remove signer ${name}?`, "Session rules that use it must be removed first.", "Remove", "Cancel"))) return;
    if (await exec(["auth", "sign", "remove", "--", p.profile, name])) {
      if (signer?.editing && signer.form.name === name) setSigner(null);
      p.onChange();
    }
  };
  const signerNames = p.signers.map((s) => s.name);

  return (
    <>
      <h3>Macros</h3>
      <p className="muted small">
        Requests that run in order with this session (cookies carry through). Each can extract a value — a CSRF token, an
        API token — that later steps use as <span className="mono">{"{{name}}"}</span> and session rules put into requests.
        Values are stored and shown masked; history keeps placeholders.
      </p>
      {p.macros.length === 0 && !building && <div className="muted small">No macros.</div>}
      {p.macros.map((m) => {
        const r = runs[m.name];
        return (
          <div key={m.name} className="sh-card">
            <div className="row gap">
              <strong className="mono">{m.name}</strong>
              <span className="muted small">
                {m.steps} step{m.steps === 1 ? "" : "s"} · extracts {m.vars.join(", ") || "nothing"}
              </span>
              <span className="grow" />
              <button className="btn small" disabled={!!busy} onClick={() => runMacro(m.name)}>
                {busy === m.name ? "Running…" : "Run"}
              </button>
              <button className="btn small" onClick={() => removeMacro(m.name)}>
                Remove
              </button>
            </div>
            <ol className="sh-steps mono small">
              {m.requests.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ol>
            {typeof r === "string" && <pre className="set-err small set-pre">{r}</pre>}
            {r && typeof r !== "string" && (
              <ol className="sh-steps small">
                {r.steps.map((s) => (
                  <li key={s.step}>
                    <span className="mono">
                      {s.method} {s.url}
                    </span>{" "}
                    → {s.status ?? "no response"}
                    {s.history_id != null && <span className="muted"> · #{s.history_id}</span>}
                    {s.error && <span className="set-err"> {s.error}</span>}
                    {s.extracted.map((x) => (
                      <div key={x.var} className="mono">
                        {x.var} = {x.value ?? <span className="set-err">not found</span>}
                      </div>
                    ))}
                  </li>
                ))}
              </ol>
            )}
          </div>
        );
      })}
      {building ? (
        <MacroBuilder
          profile={p.profile}
          onCancel={() => setBuilding(false)}
          onSaved={() => {
            setBuilding(false);
            p.onChange();
          }}
        />
      ) : (
        <div className="row gap set-actions">
          <button className="btn" onClick={() => setBuilding(true)}>
            New macro from Traffic
          </button>
        </div>
      )}

      <h3>Session rules</h3>
      <p className="muted small">
        Before a request of the chosen tools to a matching URL goes out with <span className="mono">--auth {p.profile}</span>,
        the actions run in order. A response that looks logged out (or matches the rule's invalid pattern) refreshes the
        rule's macros, logs in again if it can, and sends the request once more.
      </p>
      {p.rules.length === 0 && !ruleForm && <div className="muted small">No session rules.</div>}
      {p.rules.map((r) => (
        <div key={r.id} className="sh-card">
          <div className="row gap">
            <strong>#{r.id}</strong>
            <span className="small">{r.tools.length ? r.tools.join(", ") : "all tools"}</span>
            <span className="mono small muted">{r.url ?? "any URL"}</span>
            <span className="grow" />
            <button className="btn small" onClick={() => removeRule(r.id)}>
              Remove
            </button>
          </div>
          {r.description && <div className="small">{r.description}</div>}
          <ol className="sh-steps small">
            {r.actions.map((a, i) => (
              <li key={i}>{actionLabel(a)}</li>
            ))}
          </ol>
          {r.invalid && (
            <div className="small muted">
              Stale when the response matches <span className="mono">{r.invalid}</span>
            </div>
          )}
        </div>
      ))}
      {ruleForm ? (
        <RuleBuilder
          form={ruleForm}
          setForm={setRuleForm}
          macros={p.macros.map((m) => m.name)}
          signers={signerNames}
          problems={ruleProblems(ruleForm, p.macros.map((m) => m.name), signerNames, p.hasCheckUrl, p.hasLogin)}
          onSave={async () => {
            if (await exec(ruleAddArgs(p.profile, ruleForm))) {
              setRuleForm(null);
              p.onChange();
            }
          }}
          onCancel={() => setRuleForm(null)}
        />
      ) : (
        <div className="row gap set-actions">
          <button
            className="btn"
            onClick={() =>
              setRuleForm({
                tools: [],
                url: "",
                invalid: "",
                description: "",
                actions: p.macros.length
                  ? [
                      { action: "run_macro", macro: p.macros[0].name, every: 1 },
                      { action: "update", params: [] },
                    ]
                  : [],
              })
            }
          >
            New session rule
          </button>
        </div>
      )}

      <h3>Request signers</h3>
      <p className="muted small">
        An HMAC signature or a JWT, computed as a request goes on the wire. A session rule's <em>Sign request</em> action turns
        one on. A signer holds where its key is, never the key, and history keeps a placeholder.
      </p>
      {p.signers.length === 0 && !signer && <div className="muted small">No signers.</div>}
      {p.signers.map((s, i) => (
        <div key={s.name} className="sh-card">
          <div className="row gap">
            <strong className="mono">{s.name}</strong>
            <span className="muted small">{signerLabel(s)}</span>
            <span className="grow" />
            {i < p.signers.length - 1 && (
              <button
                className="btn small"
                title="Signers run in this order. One that covers another's signature has to run after it."
                onClick={async () => {
                  if (await exec(signerAddArgs(p.profile, signerForm(s)))) p.onChange();
                }}
              >
                Run last
              </button>
            )}
            <button className="btn small" onClick={() => setSigner({ form: signerForm(s), editing: true })}>
              Edit
            </button>
            <button className="btn small" onClick={() => removeSigner(s.name)}>
              Remove
            </button>
          </div>
          <div className="mono small muted">{s.origins.join(", ")}</div>
        </div>
      ))}
      {signer ? (
        <SignerBuilder
          form={signer.form}
          editing={signer.editing}
          setForm={(form) => setSigner({ ...signer, form })}
          problems={signerProblems(signer.form, signer.editing ? [] : signerNames)}
          onSave={async () => {
            if (await exec(signerAddArgs(p.profile, signer.form, signer.editing))) {
              setSigner(null);
              p.onChange();
            }
          }}
          onCancel={() => setSigner(null)}
        />
      ) : (
        <div className="row gap set-actions">
          <button className="btn" onClick={() => setSigner({ form: EMPTY_SIGNER, editing: false })}>
            New signer
          </button>
        </div>
      )}
    </>
  );
}

/** A Traffic row to pick. */
interface Picked {
  id: number;
  method: string;
  url: string;
  status: number | null;
}

export function MacroBuilder(p: { profile: string; onCancel: () => void; onSaved: () => void }) {
  const exec = useExec();
  const [items, setItems] = useState<Picked[]>([]);
  const [filter, setFilter] = useState("");
  const [name, setName] = useState("");
  const [steps, setSteps] = useState<Picked[]>([]);
  const [extract, setExtract] = useState<ExtractRow[]>([]);

  useEffect(() => {
    // Newest first: the requests just made in the browser are the ones wanted.
    exec<{ rows: [number, string, string, number | null][] }>([
      "query",
      "SELECT id, method, url, status FROM history ORDER BY id DESC LIMIT 500",
    ]).then((d) => d && setItems(d.rows.map(([id, method, url, status]) => ({ id, method, url, status }))));
  }, []);

  const shown = items.filter((h) => !filter || `${h.method} ${h.url} ${h.status ?? ""}`.toLowerCase().includes(filter.toLowerCase()));
  const toggle = (h: Picked) =>
    setSteps((s) => (s.some((x) => x.id === h.id) ? s.filter((x) => x.id !== h.id) : [...s, h]));
  const move = (i: number, by: number) =>
    setSteps((s) => {
      const out = [...s];
      const j = i + by;
      if (j < 0 || j >= out.length) return s;
      [out[i], out[j]] = [out[j], out[i]];
      return out;
    });
  const setRow = (i: number, patch: Partial<ExtractRow>) => setExtract((rows) => rows.map((r, k) => (k === i ? { ...r, ...patch } : r)));

  const save = async () => {
    const d = await exec(macroAddArgs(p.profile, name, steps.map((s) => s.id), extract));
    if (d) p.onSaved();
  };

  return (
    <div className="sh-card">
      <div className="form">
        <label>
          <span className="label">Macro name</span>
          <input className="input" value={name} placeholder="csrf" onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="wide">
          <span className="label">Pick requests from Traffic, in the order they should run</span>
          <input className="input" value={filter} placeholder="Filter by method, URL or status" onChange={(e) => setFilter(e.target.value)} />
        </label>
      </div>
      <div className="tree sh-pick">
        {shown.length === 0 && <div className="empty">No requests in Traffic yet. Browse the site through the proxy first.</div>}
        {shown.slice(0, 300).map((h) => {
          const n = steps.findIndex((s) => s.id === h.id);
          return (
            <button key={h.id} className={`tree-item ${n >= 0 ? "on" : ""}`} onClick={() => toggle(h)}>
              <span className="sh-n">{n >= 0 ? n + 1 : ""}</span>
              <span className="muted">#{h.id}</span>
              <span className="grow ellipsis mono">
                {h.method} {h.url}
              </span>
              <span className="muted">{h.status ?? ""}</span>
            </button>
          );
        })}
      </div>
      {steps.length > 0 && (
        <>
          <h4>Steps</h4>
          <ol className="sh-steps small">
            {steps.map((s, i) => (
              <li key={s.id}>
                <span className="mono">
                  {s.method} {s.url}
                </span>{" "}
                <button className="btn small" onClick={() => move(i, -1)} disabled={i === 0}>
                  ↑
                </button>
                <button className="btn small" onClick={() => move(i, 1)} disabled={i === steps.length - 1}>
                  ↓
                </button>
                <button className="btn small" onClick={() => toggle(s)}>
                  ✕
                </button>
              </li>
            ))}
          </ol>
          <h4>Extract values</h4>
          <p className="muted small">
            Later steps use a value as <span className="mono">{"{{name}}"}</span>; their parameters with the same name get it
            too.
          </p>
          {extract.map((x, i) => (
            <div key={i} className="row gap sh-extract">
              <select className="input" value={x.step} onChange={(e) => setRow(i, { step: Number(e.target.value) })}>
                {steps.map((_, k) => (
                  <option key={k} value={k + 1}>
                    step {k + 1}
                  </option>
                ))}
              </select>
              <input className="input" value={x.var} placeholder="variable" onChange={(e) => setRow(i, { var: e.target.value })} />
              <select className="input" value={x.from} onChange={(e) => setRow(i, { from: e.target.value as ExtractRow["from"] })}>
                {EXTRACT_FROM.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.label}
                  </option>
                ))}
              </select>
              <input
                className="input grow mono"
                value={x.expr}
                placeholder={EXTRACT_FROM.find((f) => f.id === x.from)?.hint}
                onChange={(e) => setRow(i, { expr: e.target.value })}
              />
              <button className="btn small" onClick={() => setExtract((rows) => rows.filter((_, k) => k !== i))}>
                ✕
              </button>
            </div>
          ))}
          <button className="btn small" onClick={() => setExtract((rows) => [...rows, { step: 1, var: "", from: "input", expr: "" }])}>
            Add extractor
          </button>
        </>
      )}
      <div className="row gap set-actions">
        <button className="btn primary" disabled={!p.profile || !name.trim() || steps.length === 0} onClick={save}>
          Save macro
        </button>
        <button className="btn" onClick={p.onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function RuleBuilder(p: {
  form: RuleForm;
  setForm: (f: RuleForm) => void;
  macros: string[];
  signers: string[];
  problems: string[];
  onSave: () => void;
  onCancel: () => void;
}) {
  const f = p.form;
  const set = (patch: Partial<RuleForm>) => p.setForm({ ...f, ...patch });
  const setAction = (i: number, a: Action) => set({ actions: f.actions.map((x, k) => (k === i ? a : x)) });
  const toggleTool = (t: Tool) => set({ tools: f.tools.includes(t) ? f.tools.filter((x) => x !== t) : [...f.tools, t] });
  const add = (kind: Action["action"]) => {
    const a: Action =
      kind === "check"
        ? { action: "check", every: 1 }
        : kind === "run_macro"
          ? { action: "run_macro", macro: p.macros[0] ?? "", every: 1 }
          : kind === "update"
            ? { action: "update", params: [] }
            : kind === "sign"
              ? { action: "sign", signer: p.signers[0] ?? "" }
              : { action: "login" };
    set({ actions: [...f.actions, a] });
  };
  return (
    <div className="sh-card">
      <div className="form">
        <div className="wide">
          <span className="label">Tools (none ticked: all)</span>
          <div className="seg">
            {TOOLS.map((t) => (
              <button key={t} className={f.tools.includes(t) ? "on" : ""} onClick={() => toggleTool(t)}>
                {t}
              </button>
            ))}
          </div>
        </div>
        <label>
          <span className="label">URL: host pattern or URL prefix (empty: any, values stay on their macro's origins)</span>
          <input className="input mono" value={f.url} placeholder="*.app.test or https://app.test/api/" onChange={(e) => set({ url: e.target.value })} />
        </label>
        <label>
          <span className="label">Stale-values response regex</span>
          <input className="input mono" value={f.invalid} placeholder="invalid csrf token" onChange={(e) => set({ invalid: e.target.value })} />
        </label>
        <label className="wide">
          <span className="label">Description</span>
          <input className="input" value={f.description} onChange={(e) => set({ description: e.target.value })} />
        </label>
      </div>
      <h4>Actions, in order</h4>
      <ol className="sh-steps small">
        {f.actions.map((a, i) => (
          <li key={i} className="row gap">
            <span className="sh-kind">{a.action === "run_macro" ? "run macro" : a.action}</span>
            {a.action === "check" && (
              <label className="row gap">
                every
                <input className="input sh-num" type="number" min={1} value={a.every} onChange={(e) => setAction(i, { ...a, every: Math.max(1, Number(e.target.value) || 1) })} />
                requests
              </label>
            )}
            {a.action === "run_macro" && (
              <>
                <select className="input" value={a.macro} onChange={(e) => setAction(i, { ...a, macro: e.target.value })}>
                  {p.macros.map((m) => (
                    <option key={m}>{m}</option>
                  ))}
                </select>
                <select
                  className="input"
                  value={a.every === 0 ? "cached" : a.every === 1 ? "each" : "every"}
                  onChange={(e) => setAction(i, { ...a, every: e.target.value === "cached" ? 0 : e.target.value === "each" ? 1 : 10 })}
                >
                  <option value="each">on every request</option>
                  <option value="cached">once, again when stale</option>
                  <option value="every">every N requests</option>
                </select>
                {a.every > 1 && (
                  <input className="input sh-num" type="number" min={2} value={a.every} onChange={(e) => setAction(i, { ...a, every: Math.max(2, Number(e.target.value) || 2) })} />
                )}
              </>
            )}
            {a.action === "update" && (
              <input
                className="input mono grow"
                defaultValue={a.params.map(([k, v]) => (k === v ? k : `${k}=${v}`)).join(", ")}
                placeholder="empty: this rule's macro values, by name; or csrf, X-CSRF-Token=csrf"
                onChange={(e) => setAction(i, { action: "update", params: parseParams(e.target.value) })}
              />
            )}
            {a.action === "login" && <span className="muted">with the profile, if not logged in</span>}
            {a.action === "sign" && (
              <select className="input" value={a.signer} onChange={(e) => setAction(i, { ...a, signer: e.target.value })}>
                {p.signers.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            )}
            <button className="btn small" onClick={() => set({ actions: f.actions.filter((_, k) => k !== i) })}>
              ✕
            </button>
          </li>
        ))}
      </ol>
      <div className="row gap">
        <span className="muted small">Add:</span>
        <button className="btn small" onClick={() => add("check")}>
          Check session
        </button>
        <button className="btn small" disabled={!p.macros.length} onClick={() => add("run_macro")}>
          Run macro
        </button>
        <button className="btn small" onClick={() => add("update")}>
          Update request
        </button>
        <button className="btn small" onClick={() => add("login")}>
          Log in
        </button>
        <button className="btn small" disabled={!p.signers.length} onClick={() => add("sign")}>
          Sign request
        </button>
      </div>
      {p.problems.map((m) => (
        <div key={m} className="set-err small">
          {m}
        </div>
      ))}
      <div className="row gap set-actions">
        <button className="btn primary" disabled={p.problems.length > 0} onClick={p.onSave}>
          Save rule
        </button>
        <button className="btn" onClick={p.onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function SignerBuilder(p: {
  form: SignerForm;
  editing: boolean;
  setForm: (f: SignerForm) => void;
  problems: string[];
  onSave: () => void;
  onCancel: () => void;
}) {
  const f = p.form;
  const set = (patch: Partial<SignerForm>) => p.setForm({ ...f, ...patch });
  return (
    <div className="sh-card">
      <div className="form">
        <label>
          <span className="label">{p.editing ? "Signer name (session rules use it, so it stays)" : "Signer name"}</span>
          <input className="input mono" value={f.name} disabled={p.editing} placeholder="api-hmac" onChange={(e) => set({ name: e.target.value })} />
        </label>
        <div>
          <span className="label">Makes</span>
          <div className="seg">
            <button className={f.kind === "hmac" ? "on" : ""} onClick={() => set({ kind: "hmac" })}>
              HMAC
            </button>
            <button className={f.kind === "jwt" ? "on" : ""} onClick={() => set({ kind: "jwt" })}>
              JWT
            </button>
          </div>
        </div>
        <div>
          <span className="label">Key is in</span>
          <div className="seg">
            <button className={f.keyFrom === "env" ? "on" : ""} onClick={() => set({ keyFrom: "env" })}>
              Env variable
            </button>
            <button className={f.keyFrom === "file" ? "on" : ""} onClick={() => set({ keyFrom: "file" })}>
              File
            </button>
          </div>
        </div>
        <label>
          <span className="label">{f.keyFrom === "env" ? "Environment variable (of the app, read when signing, never stored)" : "Full path of the file (read when signing, never stored)"}</span>
          <input
            className="input mono"
            value={f.key}
            placeholder={f.keyFrom === "env" ? "API_SECRET" : "/home/me/keys/api.pem"}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => set({ key: e.target.value })}
          />
        </label>
        <label>
          <span className="label">Key is written as</span>
          <select className="input" value={f.keyEncoding} onChange={(e) => set({ keyEncoding: e.target.value as SignerForm["keyEncoding"] })}>
            {KEY_ENCODINGS.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
        </label>
        <label className="wide">
          <span className="label">Origins it may sign for, one per line</span>
          <textarea className="input area mono" value={f.origins} placeholder="https://api.test" onChange={(e) => set({ origins: e.target.value })} />
        </label>
        <div>
          <span className="label">Value goes in</span>
          <div className="seg">
            <button className={f.toKind === "header" ? "on" : ""} onClick={() => set({ toKind: "header" })}>
              Header
            </button>
            <button className={f.toKind === "query" ? "on" : ""} onClick={() => set({ toKind: "query" })}>
              Query
            </button>
          </div>
        </div>
        <label>
          <span className="label">{f.toKind === "header" ? "Header name" : "Query parameter"}</span>
          <input className="input mono" value={f.toName} placeholder={f.toKind === "header" ? "X-Signature" : "sig"} onChange={(e) => set({ toName: e.target.value })} />
        </label>
        {f.toKind === "header" && (
          <label>
            <span className="label">Header format</span>
            <input className="input mono" value={f.wrap} placeholder="Bearer {{signature}}" onChange={(e) => set({ wrap: e.target.value })} />
          </label>
        )}
        <label className="wide">
          <span className="label">Headers to set before signing, NAME: TEMPLATE, one per line</span>
          <textarea className="input area mono" value={f.headers} placeholder="X-Timestamp: {{timestamp}}" onChange={(e) => set({ headers: e.target.value })} />
        </label>
        {f.kind === "hmac" ? (
          <>
            <label className="wide">
              <span className="label">String to sign (\n, \r, \t and \\ are escapes)</span>
              <textarea
                className="input area mono"
                value={f.canonical}
                placeholder={"{{method}}\\n{{path}}\\n{{query}}\\n{{header:X-Timestamp}}\\n{{body_sha256}}"}
                onChange={(e) => set({ canonical: e.target.value })}
              />
            </label>
            <label>
              <span className="label">Hash</span>
              <select className="input" value={f.hash} onChange={(e) => set({ hash: e.target.value as SignerForm["hash"] })}>
                {HMAC_HASHES.map((h) => (
                  <option key={h}>{h}</option>
                ))}
              </select>
            </label>
            <label>
              <span className="label">Output</span>
              <select className="input" value={f.output} onChange={(e) => set({ output: e.target.value as SignerForm["output"] })}>
                {HMAC_OUTPUTS.map((o) => (
                  <option key={o}>{o}</option>
                ))}
              </select>
            </label>
          </>
        ) : (
          <>
            <label>
              <span className="label">Algorithm (RS256 takes a PEM private key)</span>
              <select className="input" value={f.jwtAlg} onChange={(e) => set({ jwtAlg: e.target.value as SignerForm["jwtAlg"] })}>
                {JWT_ALGS.map((a) => (
                  <option key={a}>{a}</option>
                ))}
              </select>
            </label>
            <label className="wide">
              <span className="label">Claims, a JSON object template</span>
              <textarea className="input area mono" value={f.claims} placeholder={'{"sub":"admin"}'} onChange={(e) => set({ claims: e.target.value })} />
            </label>
            <label>
              <span className="label">Valid for, seconds (sets iat and exp)</span>
              <input className="input" value={f.ttl} placeholder="300" onChange={(e) => set({ ttl: e.target.value })} />
            </label>
            <label>
              <span className="label">kid header</span>
              <input className="input mono" value={f.kid} onChange={(e) => set({ kid: e.target.value })} />
            </label>
            <label className="check">
              <input type="checkbox" checked={f.resign} onChange={(e) => set({ resign: e.target.checked })} />
              Start from the JWT in the request, claims on top
            </label>
          </>
        )}
      </div>
      <p className="muted small">
        Templates can use <span className="mono">{"{{method}} {{host}} {{path}} {{query}} {{body}} {{body_sha256}} {{body_sha256_base64}} {{timestamp}} {{timestamp_ms}} {{nonce}} {{header:NAME}}"}</span>.
      </p>
      {p.problems.map((m) => (
        <div key={m} className="set-err small">
          {m}
        </div>
      ))}
      <div className="row gap set-actions">
        <button className="btn primary" disabled={p.problems.length > 0} onClick={p.onSave}>
          Save signer
        </button>
        <button className="btn" onClick={p.onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
