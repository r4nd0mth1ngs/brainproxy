// Settings › Match & replace: the rules, an editor for a new one, and a tester that tries rules
// on a pasted message or a history row without sending anything (`rules test`).

import { useEffect, useState } from "react";
import { bodyText, inTauri, isBinary, textBytes } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { useRunner } from "../ui/useRunner";
import {
  EMPTY_DRAFT,
  HTTP_ENGINES,
  LOCATIONS,
  MATCHERS,
  addArgs,
  describeMatch,
  describeReplace,
  describeScope,
  describeWhere,
  draftProblem,
  enginesFor,
  failureNote,
  importQuestion,
  importSummary,
  isNamed,
  isScripted,
  scriptQuestion,
  skippedReason,
  takesName,
  testArgs,
  testProblem,
  testedNote,
  testedProblems,
  testedSides,
  withLocation,
  type Draft,
  type Failure,
  type Rule,
  type Skipped,
  type TestResult,
  type TestWhat,
} from "./matchReplace.ts";

const GROUPS = ["Request", "Response", "WebSocket"];

/** A script file's path, from the app's file dialog; null if cancelled. In a browser the path is typed. */
async function chooseScript(): Promise<string | null> {
  const dialog = await import("@tauri-apps/plugin-dialog");
  const p = await dialog.open({ filters: [{ name: "JavaScript", extensions: ["js", "mjs"] }], multiple: false });
  return typeof p === "string" ? p : null;
}

export function MatchReplace() {
  const app = useApp();
  const exec = useRunner();
  const [rules, setRules] = useState<Rule[]>([]);
  const [skipped, setSkipped] = useState<Skipped[]>([]);
  const [failures, setFailures] = useState<Failure[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const set = (d: Partial<Draft>) => setDraft((old) => ({ ...old, ...d }));

  // Every rules command that changes them answers with the full list.
  const apply = async (args: string[], input?: string) => {
    const d = await exec<{ rules: Rule[]; skipped?: Skipped[]; failures?: Failure[]; host_warning?: string }>(args, input);
    if (d) setRules(d.rules);
    if (d) setSkipped(d.skipped ?? []);
    if (d) setFailures(d.failures ?? []);
    if (d?.host_warning) app.toast(d.host_warning, "error");
    return d;
  };
  useEffect(() => {
    apply(["rules", "list"]);
  }, []);

  const problem = draftProblem(draft);
  const add = async () => {
    // A script is code: it runs only after this was read and agreed to.
    if (isScripted(draft) && !(await confirm("Add a rule that runs a script", scriptQuestion(draft.script), "Add rule", "Cancel"))) return;
    if (await apply(addArgs(draft))) setDraft({ ...draft, match: "", replace: "", comment: "" });
  };
  const copy = async () => {
    await navigator.clipboard.writeText(JSON.stringify(rules, null, 2));
    app.toast(`${rules.length} rule${rules.length === 1 ? "" : "s"} copied as JSON`);
  };
  // What is on the clipboard is read as `rules list` JSON; each rule is checked as one added by hand is.
  const paste = async () => {
    const text = await navigator.clipboard.readText().catch(() => "");
    const summary = importSummary(text);
    if (!summary) return app.toast("The clipboard holds no rules: copy them as JSON here, or from brainproxy rules list.", "error");
    if (await confirm("Import rules", importQuestion(summary), "Import", "Cancel")) await apply(["rules", "import", "-"], text);
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
          aria-label={`Rule ${r.id} enabled`}
          checked={r.enabled}
          onClick={(e) => e.stopPropagation()}
          onChange={() => apply(["rules", r.enabled ? "disable" : "enable", String(r.id)])}
        />
      ),
    },
    { key: "id", label: "#", width: 44, value: (r) => r.id, align: "right" },
    { key: "location", label: "Where", width: 190, value: (r) => describeWhere(r) },
    { key: "pattern", label: "Match", width: 220, value: (r) => r.pattern, render: (r) => (r.pattern ? <span className="mono">{describeMatch(r)}</span> : <span className="muted">{describeMatch(r)}</span>) },
    {
      key: "replace",
      label: "Replace",
      width: 220,
      value: (r) => describeReplace(r),
      render: (r) => {
        const why = skippedReason(r, skipped);
        if (why) return <span className="warn-text" title={why}>{describeReplace(r)}: not applied ({why})</span>;
        const failed = failureNote(r, failures);
        if (failed) return <span className="warn-text" title={failed}>{describeReplace(r)}: {failed}</span>;
        if (r.replacer === "script") return <span title={`${r.script?.file ?? ""}\nsha256 ${r.script?.sha256 ?? ""}`}>{describeReplace(r)}</span>;
        return r.replace && r.action !== "remove" ? <span className="mono">{r.replace}</span> : <span className="muted">{describeReplace(r)}</span>;
      },
    },
    { key: "scope", label: "Applies to", width: 200, value: (r) => describeScope(r) },
    { key: "comment", label: "Comment", width: 200, value: (r) => r.comment ?? "" },
  ];

  const named = isNamed(draft);
  const header = draft.location.endsWith("-header");
  const noMatch = named && draft.action === "add";
  const noReplace = named && draft.action === "remove";
  const scripted = isScripted(draft);
  return (
    <div className="col fill">
      <div className="toolbar">
        <select className="input" aria-label="Where the rule works" value={draft.location} onChange={(e) => setDraft(withLocation(draft, e.target.value))}>
          {GROUPS.map((g) => (
            <optgroup key={g} label={g}>
              {LOCATIONS.filter((l) => l.group === g).map((l) => (
                <option key={l.id} value={l.id}>
                  {l.label}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        {takesName(draft.location) && (
          <input
            className="input mono"
            style={{ width: 150 }}
            placeholder={header ? "header name (empty: each line)" : "parameter name"}
            aria-label={header ? "Header name" : "Parameter name"}
            value={draft.name}
            onChange={(e) => set({ name: e.target.value })}
          />
        )}
        {named && (
          <select className="input" aria-label="What to do with it" value={draft.action} onChange={(e) => set({ action: e.target.value })}>
            <option value="set">Set</option>
            <option value="add">Add</option>
            <option value="remove">Remove</option>
          </select>
        )}
        <select className="input" aria-label="How the match is read" value={draft.matcher} disabled={noMatch} onChange={(e) => set({ matcher: e.target.value })}>
          {MATCHERS.map((m) => (
            <option key={m.id} value={m.id}>
              {m.label}
            </option>
          ))}
        </select>
        <input
          className="input grow mono"
          placeholder={noMatch ? "(add takes no match)" : header && !named ? "match (empty: add a header)" : named || !["request-line", "request-body", "response-body"].includes(draft.location) ? "match (empty: the whole value)" : "match"}
          aria-label="Match"
          disabled={noMatch}
          value={noMatch ? "" : draft.match}
          onChange={(e) => set({ match: e.target.value })}
        />
        <select
          className="input"
          aria-label="What makes the replacement"
          title="Text you type, or a script: a JavaScript file whose replace(match, ctx) returns what to write for each match"
          value={draft.replacer}
          disabled={noReplace}
          onChange={(e) => set({ replacer: e.target.value === "script" ? "script" : "text" })}
        >
          <option value="text">Text</option>
          <option value="script">Script</option>
        </select>
        {scripted && !noReplace ? (
          <>
            <input
              className="input grow mono"
              placeholder="script file: defines replace(match, ctx)"
              aria-label="Script file"
              value={draft.script}
              onChange={(e) => set({ script: e.target.value })}
            />
            {inTauri && (
              <button
                className="btn"
                onClick={async () => {
                  const file = await chooseScript();
                  if (file) set({ script: file });
                }}
              >
                Choose…
              </button>
            )}
          </>
        ) : (
          <input
            className="input grow mono"
            placeholder={noReplace ? "(removed)" : draft.matcher === "regex" ? "replace ($1 groups; empty removes)" : "replace"}
            aria-label="Replace"
            disabled={noReplace}
            value={noReplace ? "" : draft.replace}
            onChange={(e) => set({ replace: e.target.value })}
          />
        )}
      </div>
      <div className="toolbar">
        <span className="muted">Applies to</span>
        {enginesFor(draft.location).map((e) => (
          <label className="check" key={e.id}>
            <input
              type="checkbox"
              checked={draft.appliesTo.includes(e.id)}
              onChange={(ev) => set({ appliesTo: ev.target.checked ? [...draft.appliesTo, e.id] : draft.appliesTo.filter((x) => x !== e.id) })}
            />{" "}
            {e.label}
          </label>
        ))}
        <input className="input mono" style={{ width: 170 }} placeholder="host regex (any host)" aria-label="Host regex" value={draft.host} onChange={(e) => set({ host: e.target.value })} />
        <input className="input" placeholder="comment" aria-label="Comment" value={draft.comment} onChange={(e) => set({ comment: e.target.value })} />
        <label className="check">
          <input type="checkbox" checked={draft.disabled} onChange={(e) => set({ disabled: e.target.checked })} /> disabled
        </label>
        <button className="btn primary" disabled={!!problem} title={problem ?? undefined} onClick={add}>
          Add rule
        </button>
        <span className="grow" />
        <div className="toolbar-end">
          <button className="btn" disabled={selected == null} onClick={() => selected != null && apply(["rules", "remove", String(selected)]).then(() => setSelected(null))}>
            Remove
          </button>
          <button
            className="btn"
            disabled={!rules.length}
            onClick={async () => (await confirm("Clear all rules", "Remove every match-and-replace rule?", "Remove all", "Cancel")) && apply(["rules", "clear"]).then(() => setSelected(null))}
          >
            Clear all
          </button>
          <button className="btn" disabled={!rules.length} title="Copy the rules as JSON, to import into another project" onClick={copy}>
            Copy as JSON
          </button>
          <button className="btn" title="Add the rules on the clipboard (JSON, as copied here or printed by brainproxy rules list)" onClick={paste}>
            Import
          </button>
        </div>
      </div>
      <Split id="rules" dir="col" initial={0.45}>
        <DataTable
          rows={rules}
          columns={columns}
          rowKey={(r) => r.id}
          selected={selected}
          onSelect={(r) => setSelected(r.id)}
          initialSort={{ key: "id", desc: false }}
          rowClass={(r) => (r.enabled && !skippedReason(r, skipped) ? undefined : "set-off")}
          empty="No match-and-replace rules. A rule rewrites what the proxy relays and, if it says so, what Replay, the Fuzzer and scans send."
        />
        <Tester draft={draft} selected={rules.some((r) => r.id === selected) ? selected : null} />
      </Split>
    </div>
  );
}

/** Tries rules on a message without sending anything. */
function Tester(p: { draft: Draft; selected: number | null }) {
  const exec = useRunner();
  // What to try: the rule in the editor, the selected saved rule, or an engine's enabled rules.
  const [what, setWhat] = useState("draft");
  const [message, setMessage] = useState("auto");
  const [history, setHistory] = useState("");
  const [host, setHost] = useState("");
  const [text, setText] = useState("");
  const [result, setResult] = useState<TestResult | null>(null);
  const [side, setSide] = useState("request");
  const [original, setOriginal] = useState(false);

  const tried: TestWhat = what === "draft" ? { kind: "draft", draft: p.draft } : what === "selected" ? { kind: "rule", id: p.selected ?? 0 } : { kind: "engine", engine: what };
  const on = { message, history, host };
  const problem = what === "selected" && p.selected == null ? "Select a rule in the table." : testProblem(tried, on, text);
  const test = async () => {
    // Text typed here has \n line endings; the CLI reads a head with those as `send` does.
    const r = await exec<TestResult>(testArgs(tried, on), history.trim() ? undefined : textBytes(text));
    if (!r) return;
    setResult(r);
    setOriginal(false);
    const sides = testedSides(r);
    if (!sides.some((s) => s.id === side)) setSide(sides[0]?.id ?? "request");
  };

  const sides = result ? testedSides(result) : [];
  const shown = sides.find((s) => s.id === side) ?? sides[0];
  const body = shown ? (original && shown.tested.original ? shown.tested.original : shown.tested.result) : null;
  return (
    <div className="col fill">
      <div className="toolbar">
        <span className="muted">Test</span>
        <select className="input" aria-label="Which rules to test" value={what} onChange={(e) => setWhat(e.target.value)}>
          <option value="draft">The rule above</option>
          <option value="selected">The selected rule{p.selected != null ? ` (#${p.selected})` : ""}</option>
          {HTTP_ENGINES.map((e) => (
            <option key={e.id} value={e.id}>
              Enabled rules, as {e.label} applies them
            </option>
          ))}
        </select>
        <span className="muted">on</span>
        <select className="input" aria-label="What the message is" value={message} disabled={!!history.trim()} onChange={(e) => setMessage(e.target.value)}>
          <option value="auto">Request or response</option>
          <option value="request">Request</option>
          <option value="response">Response</option>
          <option value="ws-to-server">WebSocket message to server</option>
          <option value="ws-to-client">WebSocket message to client</option>
        </select>
        <input className="input mono" style={{ width: 150 }} placeholder="host (from Host header)" aria-label="Host the message is for" disabled={!!history.trim()} value={host} onChange={(e) => setHost(e.target.value)} />
        <span className="muted">or history</span>
        <input className="input mono" style={{ width: 80 }} placeholder="# id" aria-label="History id" value={history} onChange={(e) => setHistory(e.target.value)} />
        <button className="btn primary" disabled={!!problem} title={problem ?? "Nothing is sent"} onClick={test}>
          Test
        </button>
      </div>
      <Split id="rules-test" dir="row">
        <HttpView title="Message" value={text} onChange={setText} placeholder="Paste a request, a response or a WebSocket message. Nothing is sent." />
        <HttpView
          title={shown ? (original ? `${shown.label} before` : `${shown.label} after`) : "After the rules"}
          value={body ? bodyText(body) : ""}
          binary={isBinary(body)}
          placeholder="The message after the rules, and which rules changed it."
          extra={
            shown && (
              <>
                <span className={shown.tested.changed ? "" : "muted"}>{testedNote(shown.tested)}</span>
                {testedProblems(shown.tested, result?.skipped).map((problem) => (
                  <span key={problem} className="warn-text" role="alert">
                    {problem}
                  </span>
                ))}
                {sides.length > 1 && (
                  <div className="seg">
                    {sides.map((s) => (
                      <button key={s.id} className={shown.id === s.id ? "on" : ""} onClick={() => setSide(s.id)}>
                        {s.label}
                      </button>
                    ))}
                  </div>
                )}
                {shown.tested.original && (
                  <div className="seg">
                    <button className={original ? "on" : ""} onClick={() => setOriginal(true)}>
                      Before
                    </button>
                    <button className={original ? "" : "on"} onClick={() => setOriginal(false)}>
                      After
                    </button>
                  </div>
                )}
              </>
            )
          }
        />
      </Split>
    </div>
  );
}
