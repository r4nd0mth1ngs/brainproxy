// Settings › Auth profiles › a profile's macros, session rules and request signers. A macro
// is built by picking requests from Traffic in order (or pasting raw ones), editing a step's
// request where it needs a value (`{{name}}`), and saying what to extract from each response;
// it is edited in place the same way (`auth macro edit`); a rule says, for some tools
// and URLs, what to do before each request goes out; a signer says how to compute a rule's
// signature or JWT, and where its key is.

import { useEffect, useRef, useState } from "react";
import { historyRequest, run } from "../api";
import { HttpView } from "../ui/HttpView";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { useDialogFocus } from "../ui/dialogFocus";
import {
  EMPTY_SIGNER,
  EXTRACT_FROM,
  HMAC_HASHES,
  HMAC_OUTPUTS,
  JWT_ALGS,
  KEY_ALGS,
  KEY_ENCODINGS,
  TOOLS,
  actionLabel,
  cleanOrigin,
  editedStep,
  inferOrigin,
  insertVar,
  macroAddArgs,
  macroEditArgs,
  macroEditProblem,
  macroEditor,
  parseParams,
  ruleAddArgs,
  ruleProblems,
  signerAddArgs,
  signerForm,
  signerLabel,
  signerProblems,
  stepTextProblem,
  varsBefore,
  type Action,
  type EditorExtract,
  type EditorStep,
  type ExtractRow,
  type MacroDetail,
  type MacroRun,
  type MacroSummary,
  type RuleForm,
  type SessionRule,
  type Signer,
  type SignerForm,
  type StepText,
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
  const [editingMacro, setEditingMacro] = useState<MacroSummary | null>(null);
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
              <button className="btn small" title="Change its steps, their requests, what it extracts or its name, in place" onClick={() => setEditingMacro(m)}>
                Edit…
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
            New macro
          </button>
        </div>
      )}
      {editingMacro && (
        <MacroEditor
          key={editingMacro.name}
          profile={p.profile}
          name={editingMacro.name}
          onClose={() => setEditingMacro(null)}
          onSaved={() => {
            setEditingMacro(null);
            p.onChange();
          }}
        />
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
        An HMAC or private-key signature, a JWT, AWS SigV4 or a Postman script, computed as a request goes on the wire. A session rule's <em>Sign request</em> action turns
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
            {s.kind !== "script" && (
              <button className="btn small" onClick={() => setSigner({ form: signerForm(s), editing: true })}>
                Edit
              </button>
            )}
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

/** Requests from Traffic to pick, newest first, filtered as typed; each picked one shows its place in the order. */
function TrafficPicker(p: { place: (id: number) => number; onPick: (h: Picked) => void }) {
  const exec = useExec();
  const [items, setItems] = useState<Picked[]>([]);
  const [filter, setFilter] = useState("");
  useEffect(() => {
    // Newest first: the requests just made in the browser are the ones wanted.
    exec<{ rows: [number, string, string, number | null][] }>([
      "query",
      "SELECT id, method, url, status FROM history ORDER BY id DESC LIMIT 500",
    ]).then((d) => d && setItems(d.rows.map(([id, method, url, status]) => ({ id, method, url, status }))));
  }, []);
  const shown = items.filter((h) => !filter || `${h.method} ${h.url} ${h.status ?? ""}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <div className="form">
        <label className="wide">
          <span className="label">Pick requests from Traffic, in the order they should run</span>
          <input className="input" value={filter} placeholder="Filter by method, URL or status" onChange={(e) => setFilter(e.target.value)} />
        </label>
      </div>
      <div className="tree sh-pick">
        {shown.length === 0 && <div className="empty">No requests in Traffic yet. Browse the site through the proxy first.</div>}
        {shown.slice(0, 300).map((h) => {
          const n = p.place(h.id);
          return (
            <button key={h.id} className={`tree-item ${n >= 0 ? "on" : ""}`} onClick={() => p.onPick(h)}>
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
    </>
  );
}

/** A step's request being edited: which step (null for a new one), its text when the dialog opened, and its original text. */
interface Editing {
  key: string | null;
  start: StepText;
  was: StepText | null;
}

/**
 * The text of a step to edit: the macro's own from `detail`, a Traffic row's from history, or
 * the text it was given. Null, with a message, for a Traffic row whose body is binary: a macro
 * step is text.
 */
async function stepText(s: EditorStep, detail: MacroDetail | null): Promise<StepText> {
  if (s.kind === "text") return { target: s.target, request: s.request };
  if (s.kind === "kept") {
    const d = detail?.steps[s.n - 1];
    if (!d) throw new Error("The macro is still being read.");
    return { target: d.target, request: d.request };
  }
  const h = await historyRequest(s.id);
  if (h.binary) throw new Error(`Request #${s.id} has a binary body; a macro step is text. Use auth macro add with a file.`);
  return { target: new URL(h.entry.url).origin, request: h.raw };
}

/** Opens a step's request in the editor dialog (`editing`), or reports why it can't. */
function useStepEditor(detail: MacroDetail | null) {
  const app = useApp();
  const [editing, setEditing] = useState<Editing | null>(null);
  const open = async (s: EditorStep) => {
    try {
      const t = await stepText(s, detail);
      // The original text, so saving it unchanged keeps the step what it was.
      setEditing({ key: s.key, start: t, was: s.kind === "text" ? null : t });
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };
  const paste = () => setEditing({ key: null, start: { target: "", request: "" }, was: null });
  return { editing, open, paste, close: () => setEditing(null) };
}

/**
 * One step's request as text: the origin it goes to and the raw request, in the editor Replay
 * uses, with buttons that put {{name}} at the caret for the values earlier steps extract.
 */
function StepTextDialog(p: { title: string; start: StepText; vars: string[]; onCancel: () => void; onSave: (t: StepText) => void }) {
  const [request, setRequest] = useState(p.start.request);
  // A pasted request's origin follows its Host header until one is typed.
  const [target, setTarget] = useState<string | null>(p.start.target || null);
  const origin = target ?? inferOrigin(request);
  const t = { target: cleanOrigin(origin), request };
  const problem = stepTextProblem(t);
  const editor = useRef<HTMLTextAreaElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  useDialogFocus(dialog);
  const put = (name: string) => {
    const el = editor.current;
    const r = insertVar(request, el?.selectionStart ?? request.length, el?.selectionEnd ?? request.length, name);
    setRequest(r.value);
    requestAnimationFrame(() => {
      el?.focus();
      el?.setSelectionRange(r.caret, r.caret);
    });
  };
  return (
    <div
      className="confirm-backdrop"
      onKeyDown={(e) => {
        // Its own Esc: the macro dialog under it stays open.
        if (e.key !== "Escape") return;
        e.stopPropagation();
        p.onCancel();
      }}
    >
      <div ref={dialog} className="confirm-dialog finding-dialog sh-text-dialog" role="dialog" aria-modal="true" aria-labelledby="step-text-title">
        <h2 id="step-text-title">{p.title}</h2>
        <div className="form">
          <label className="wide">
            <span className="label">Origin it goes to</span>
            <input className="input mono" value={origin} placeholder="https://app.test" onChange={(e) => setTarget(e.target.value)} />
          </label>
        </div>
        <div className="sh-request">
          <HttpView title="Request" value={request} onChange={setRequest} editorRef={editor} placeholder={"POST /login HTTP/1.1\nHost: app.test\n\nuser={{username}}&csrf={{csrf}}"} />
        </div>
        <div className="row gap sh-vars small">
          <span className="muted">Put in a value:</span>
          {p.vars.map((v) => (
            <button key={v} className="btn small mono" onMouseDown={(e) => e.preventDefault()} onClick={() => put(v)} title={`Insert {{${v}}} at the caret`}>
              {`{{${v}}}`}
            </button>
          ))}
        </div>
        <p className="muted small">
          Values extracted by earlier steps, and the profile's username and password, go in as <span className="mono">{"{{name}}"}</span>.
          Content-Length is set when the step runs.
        </p>
        {problem && request && <div className="muted small">{problem}</div>}
        <div className="row gap finding-dialog-actions">
          <div className="toolbar-end">
            <button className="btn" onClick={p.onCancel}>
              Cancel
            </button>
            <button className="btn primary" disabled={!!problem} title={problem ?? undefined} onClick={() => p.onSave(t)}>
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** The steps of a macro being built or edited: each can move, have its request edited, or be taken out. */
function StepList(p: {
  steps: EditorStep[];
  note: (s: EditorStep) => string;
  move: (i: number, by: number) => void;
  edit: (s: EditorStep) => void;
  takeOut: (s: EditorStep) => void;
}) {
  return (
    <ol className="sh-steps small">
      {p.steps.map((s, i) => (
        <li key={s.key}>
          <span className="mono">{s.line}</span>
          {p.note(s) && <span className="muted"> · {p.note(s)}</span>}{" "}
          <button className="btn small" aria-label={`Edit step ${i + 1}'s request`} title="Edit its request" onClick={() => p.edit(s)}>
            Edit request
          </button>
          <button className="btn small" aria-label={`Move step ${i + 1} up`} onClick={() => p.move(i, -1)} disabled={i === 0}>
            ↑
          </button>
          <button className="btn small" aria-label={`Move step ${i + 1} down`} onClick={() => p.move(i, 1)} disabled={i === p.steps.length - 1}>
            ↓
          </button>
          <button className="btn small" aria-label={`Take out step ${i + 1}`} onClick={() => p.takeOut(s)}>
            ✕
          </button>
        </li>
      ))}
    </ol>
  );
}

/** `steps` with step `i` moved `by` places, or as they were at either end. */
function moved<T>(steps: T[], i: number, by: number): T[] {
  const j = i + by;
  if (j < 0 || j >= steps.length) return steps;
  const out = [...steps];
  [out[i], out[j]] = [out[j], out[i]];
  return out;
}

export function MacroBuilder(p: { profile: string; onCancel: () => void; onSaved: () => void }) {
  const app = useApp();
  const [name, setName] = useState("");
  const [steps, setSteps] = useState<EditorStep[]>([]);
  const [extract, setExtract] = useState<ExtractRow[]>([]);
  const pasted = useRef(0);
  const ed = useStepEditor(null);

  const toggle = (h: Picked) => {
    const key = `history${h.id}`;
    setSteps((s) => (s.some((x) => x.key === key) ? s.filter((x) => x.key !== key) : [...s, { key, kind: "history", id: h.id, line: `${h.method} ${h.url}` }]));
  };
  const setRow = (i: number, patch: Partial<ExtractRow>) => setExtract((rows) => rows.map((r, k) => (k === i ? { ...r, ...patch } : r)));
  const saveText = (t: StepText) => {
    const e = ed.editing;
    if (!e) return;
    if (e.key === null) {
      const key = `text${++pasted.current}`;
      setSteps((s) => [...s, editedStep({ key, kind: "text", target: "", request: "", line: "" }, t, null)]);
    } else setSteps((s) => s.map((x) => (x.key === e.key ? editedStep(x, t, e.was) : x)));
    ed.close();
  };

  const save = async () => {
    const call = macroAddArgs(p.profile, name, steps, extract);
    try {
      await run(call.args, { requestFiles: call.requestFiles });
      p.onSaved();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  return (
    <div className="sh-card">
      <div className="form">
        <label>
          <span className="label">Macro name</span>
          <input className="input" value={name} placeholder="csrf" onChange={(e) => setName(e.target.value)} />
        </label>
      </div>
      <TrafficPicker place={(id) => steps.findIndex((s) => s.key === `history${id}`)} onPick={toggle} />
      <button className="btn small" onClick={ed.paste}>
        Add a raw request
      </button>
      {steps.length > 0 && (
        <>
          <h4>Steps</h4>
          <StepList
            steps={steps}
            note={(s) => (s.kind === "text" ? "edited" : "")}
            move={(i, by) => setSteps((s) => moved(s, i, by))}
            edit={ed.open}
            takeOut={(s) => setSteps((all) => all.filter((x) => x.key !== s.key))}
          />
          <h4>Extract values</h4>
          <p className="muted small">
            Later steps use a value as <span className="mono">{"{{name}}"}</span> (Edit request puts it in); their parameters with
            the same name get it too.
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
      {ed.editing && (
        <StepTextDialog
          title={ed.editing.key === null ? "Add a raw request" : `Edit step ${steps.findIndex((s) => s.key === ed.editing!.key) + 1}'s request`}
          start={ed.editing.start}
          vars={varsBefore(
            steps,
            extract.map((x) => ({ key: steps[x.step - 1]?.key ?? "", var: x.var })),
            ed.editing.key,
          )}
          onCancel={ed.close}
          onSave={saveText}
        />
      )}
    </div>
  );
}

/**
 * Edits a macro in place: its steps (reordered, taken out, added from Traffic or pasted, their
 * requests edited), its extractors and its name.
 */
function MacroEditor(p: { profile: string; name: string; onClose: () => void; onSaved: () => void }) {
  const [start, setStart] = useState<{ steps: EditorStep[]; extract: EditorExtract[] } | null>(null);
  const [detail, setDetail] = useState<MacroDetail | null>(null);
  const [revision, setRevision] = useState<string | undefined>();
  const [name, setName] = useState(p.name);
  const [steps, setSteps] = useState<EditorStep[]>([]);
  const [extract, setExtract] = useState<EditorExtract[]>([]);
  const [adding, setAdding] = useState(false);
  const pasted = useRef(0);
  const ed = useStepEditor(detail);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  useDialogFocus(dialog);

  useEffect(() => {
    run<{ macro: MacroDetail; revision: string }>(["auth", "macro", "show", "--", p.profile, p.name]).then(
      (d) => {
        const e = macroEditor(d.macro);
        setDetail(d.macro);
        setStart(e);
        setSteps(e.steps);
        setExtract(e.extract);
        setRevision(d.revision);
      },
      (e) => setError(e.message),
    );
  }, []);

  // A step taken out takes its extractors with it.
  const takeOut = (key: string) => {
    setSteps((s) => s.filter((x) => x.key !== key));
    setExtract((rows) => rows.filter((x) => x.key !== key));
  };
  const pick = (h: Picked) => {
    const key = `history${h.id}`;
    if (steps.some((s) => s.key === key)) return takeOut(key);
    setSteps((s) => [...s, { key, kind: "history", id: h.id, line: `${h.method} ${h.url}` }]);
  };
  const setRow = (i: number, patch: Partial<EditorExtract>) => setExtract((rows) => rows.map((r, k) => (k === i ? { ...r, ...patch } : r)));
  const saveText = (t: StepText) => {
    const e = ed.editing;
    if (!e) return;
    if (e.key === null) {
      const key = `text${++pasted.current}`;
      setSteps((s) => [...s, editedStep({ key, kind: "text", target: "", request: "", line: "" }, t, null)]);
    } else setSteps((s) => s.map((x) => (x.key === e.key ? editedStep(x, t, e.was) : x)));
    ed.close();
  };
  const problem = start ? macroEditProblem(steps, extract, name) : "Reading the macro…";

  const save = async () => {
    if (!start) return;
    const call = macroEditArgs(p.profile, p.name, start, steps, extract, revision, name);
    if (!call) return p.onClose();
    setBusy(true);
    setError(null);
    try {
      await run(call.args, { requestFiles: call.requestFiles });
      p.onSaved();
    } catch (e: any) {
      setError(e.message);
    }
    setBusy(false);
  };

  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && p.onClose()}>
      <div ref={dialog} className="confirm-dialog finding-dialog" role="dialog" aria-modal="true" aria-labelledby="edit-macro-title">
        <h2 id="edit-macro-title">Edit macro {p.name}</h2>
        <p>
          It keeps its place, and session rules that run it go on running it, under a new name too. Saving a change records you as the one who set it. An extractor moves with its step.
        </p>
        <div className="form">
          <label>
            <span className="label">Name</span>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
        </div>
        <h4>Steps</h4>
        <StepList
          steps={steps}
          note={(s) => (s.kind === "history" ? `new, from #${s.id}` : s.kind === "text" ? "edited" : "")}
          move={(i, by) => setSteps((s) => moved(s, i, by))}
          edit={ed.open}
          takeOut={(s) => takeOut(s.key)}
        />
        <div className="row gap">
          {!adding && (
            <button className="btn small" disabled={!start} onClick={() => setAdding(true)}>
              Add steps from Traffic
            </button>
          )}
          <button className="btn small" disabled={!start} onClick={ed.paste}>
            Add a raw request
          </button>
        </div>
        {adding && <TrafficPicker place={(id) => steps.findIndex((s) => s.key === `history${id}`)} onPick={pick} />}
        <h4>Extract values</h4>
        {extract.map((x, i) => (
          <div key={i} className="row gap sh-extract">
            <select className="input" aria-label="Step" value={x.key} onChange={(e) => setRow(i, { key: e.target.value })}>
              {steps.map((s, k) => (
                <option key={s.key} value={s.key}>
                  step {k + 1}
                </option>
              ))}
            </select>
            <input className="input" aria-label="Variable" value={x.var} placeholder="variable" onChange={(e) => setRow(i, { var: e.target.value })} />
            <select className="input" aria-label="Where it is" value={x.from} onChange={(e) => setRow(i, { from: e.target.value as EditorExtract["from"] })}>
              {EXTRACT_FROM.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
            <input
              className="input grow mono"
              aria-label="What to look for"
              value={x.expr}
              placeholder={EXTRACT_FROM.find((f) => f.id === x.from)?.hint}
              onChange={(e) => setRow(i, { expr: e.target.value })}
            />
            <button className="btn small" aria-label="Take out this extractor" onClick={() => setExtract((rows) => rows.filter((_, k) => k !== i))}>
              ✕
            </button>
          </div>
        ))}
        <button className="btn small" disabled={!steps.length} onClick={() => setExtract((rows) => [...rows, { key: steps[0].key, var: "", from: "input", expr: "" }])}>
          Add extractor
        </button>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <div className="row gap finding-dialog-actions">
          <div className="toolbar-end">
            <button className="btn" disabled={busy} onClick={p.onClose}>
              Cancel
            </button>
            <button className="btn primary" disabled={busy || !!problem} title={problem ?? undefined} onClick={save}>
              {busy ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
        {ed.editing && (
          <StepTextDialog
            title={ed.editing.key === null ? "Add a raw request" : `Edit step ${steps.findIndex((s) => s.key === ed.editing!.key) + 1}'s request`}
            start={ed.editing.start}
            vars={varsBefore(steps, extract, ed.editing.key)}
            onCancel={ed.close}
            onSave={saveText}
          />
        )}
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

export function SignerBuilder(p: {
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
            <button className={f.kind === "key" ? "on" : ""} onClick={() => set({ kind: "key" })}>
              Private key
            </button>
            <button className={f.kind === "jwt" ? "on" : ""} onClick={() => set({ kind: "jwt" })}>
              JWT
            </button>
            <button className={f.kind === "sigv4" ? "on" : ""} onClick={() => set({ kind: "sigv4" })}>
              AWS SigV4
            </button>
          </div>
        </div>
        <div>
          <span className="label">{f.kind === "sigv4" ? "Secret access key is in" : "Key is in"}</span>
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
        {f.kind !== "sigv4" && f.kind !== "key" && (
        <label>
          <span className="label">Key is written as</span>
          <select className="input" value={f.keyEncoding} onChange={(e) => set({ keyEncoding: e.target.value as SignerForm["keyEncoding"] })}>
            {KEY_ENCODINGS.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
        </label>
        )}
        <label className="wide">
          <span className="label">Origins it may sign for, one per line</span>
          <textarea className="input area mono" value={f.origins} placeholder="https://api.test" onChange={(e) => set({ origins: e.target.value })} />
        </label>
        {f.kind !== "sigv4" && (
        <>
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
        </>
        )}
        {f.kind === "sigv4" ? (
          <>
            <label>
              <span className="label">Region</span>
              <input className="input mono" value={f.region} placeholder="eu-west-1" onChange={(e) => set({ region: e.target.value })} />
            </label>
            <label>
              <span className="label">Service</span>
              <input className="input mono" value={f.service} placeholder="execute-api" onChange={(e) => set({ service: e.target.value })} />
            </label>
            <div>
              <span className="label">Access key id is in</span>
              <div className="seg">
                <button className={f.accessFrom === "env" ? "on" : ""} onClick={() => set({ accessFrom: "env" })}>
                  Env variable
                </button>
                <button className={f.accessFrom === "file" ? "on" : ""} onClick={() => set({ accessFrom: "file" })}>
                  File
                </button>
              </div>
            </div>
            <label>
              <span className="label">{f.accessFrom === "env" ? "Environment variable" : "Full path of the file"}</span>
              <input className="input mono" value={f.access} placeholder={f.accessFrom === "env" ? "AWS_ACCESS_KEY_ID" : "/home/me/keys/aws-id"} autoComplete="off" spellCheck={false} onChange={(e) => set({ access: e.target.value })} />
            </label>
            <div>
              <span className="label">Session token, if any, is in</span>
              <div className="seg">
                <button className={f.tokenFrom === "env" ? "on" : ""} onClick={() => set({ tokenFrom: "env" })}>
                  Env variable
                </button>
                <button className={f.tokenFrom === "file" ? "on" : ""} onClick={() => set({ tokenFrom: "file" })}>
                  File
                </button>
              </div>
            </div>
            <label>
              <span className="label">{f.tokenFrom === "env" ? "Environment variable (optional)" : "Full path of the file (optional)"}</span>
              <input className="input mono" value={f.token} placeholder={f.tokenFrom === "env" ? "AWS_SESSION_TOKEN" : ""} autoComplete="off" spellCheck={false} onChange={(e) => set({ token: e.target.value })} />
            </label>
          </>
        ) : f.kind === "key" ? (
          <>
            <label className="wide">
              <span className="label">String to sign (\n, \r, \t and \\ are escapes)</span>
              <textarea className="input area mono" value={f.canonical} placeholder={"{{method}}\\n{{path}}\\n{{body_sha256}}"} onChange={(e) => set({ canonical: e.target.value })} />
            </label>
            <label>
              <span className="label">Algorithm (a PEM private key; ES and EdDSA keys as PKCS#8)</span>
              <select className="input" value={f.keyAlg} onChange={(e) => set({ keyAlg: e.target.value as SignerForm["keyAlg"] })}>
                {KEY_ALGS.map((a) => (
                  <option key={a}>{a}</option>
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
        ) : f.kind === "hmac" ? (
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
              <span className="label">Algorithm (all but HS* take a PEM private key)</span>
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
