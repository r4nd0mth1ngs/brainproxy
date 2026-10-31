// Settings › Auth profiles › a profile's macros and session rules. A macro is built by
// picking requests from Traffic in order and saying what to extract from each response; a
// rule says, for some tools and URLs, what to do before each request goes out.

import { useEffect, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import {
  EXTRACT_FROM,
  TOOLS,
  actionLabel,
  macroAddArgs,
  parseParams,
  ruleAddArgs,
  ruleProblems,
  type Action,
  type ExtractRow,
  type MacroRun,
  type MacroSummary,
  type RuleForm,
  type SessionRule,
  type Tool,
} from "./sessionRules";

interface Props {
  profile: string;
  macros: MacroSummary[];
  rules: SessionRule[];
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
          problems={ruleProblems(ruleForm, p.macros.map((m) => m.name), p.hasCheckUrl, p.hasLogin)}
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
            {a.action === "sign" && <span className="mono">{a.signer}</span>}
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
