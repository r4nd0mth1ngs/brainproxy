// Scans › Rules › Passive: the passive checks written as scripts (`scan script`): add one, test
// a file on a history row, name a changed file again, remove one. Switching them on and off is
// the rules table's (`scan enable|disable script:NAME`). The arguments are in scriptChecks.ts.

import { useRef, useState } from "react";
import { inTauri, run } from "../api";
import { useApp } from "../store";
import { ask, confirm } from "../ui/Confirm";
import { useDialogFocus } from "../ui/dialogFocus";
import {
  historyId,
  pinFor,
  scriptAddArgs,
  scriptNameProblem,
  scriptRemoveArgs,
  SCRIPT_LIST_ARGS,
  scriptTestArgs,
  testNote,
  type ScriptCheck,
  type ScriptTest,
} from "./scriptChecks.ts";

/** A script file's path; null if cancelled. In a browser (the dev bridge) the path is typed. */
async function chooseScript(): Promise<string | null> {
  if (inTauri) {
    const dialog = await import("@tauri-apps/plugin-dialog");
    const p = await dialog.open({ filters: [{ name: "JavaScript", extensions: ["js", "mjs"] }], multiple: false });
    return typeof p === "string" ? p : null;
  }
  return (await ask("Script file", "Its full path on this computer.", "Choose", "Cancel"))?.trim() || null;
}

/** The script checks, each with its file, what stops it running, and Test… and Remove. */
export function ScriptChecks({ scripts, changed }: { scripts: ScriptCheck[]; changed: () => void }) {
  const app = useApp();
  const [editing, setEditing] = useState<{ name: string; file: string } | null>(null);

  const remove = async (s: ScriptCheck) => {
    if (!(await confirm(`Remove the script check ${s.name}?`, "Its findings stay until a rescan, which removes the ones nobody triaged. The file itself is kept.", "Remove", "Cancel")))
      return;
    try {
      await run(scriptRemoveArgs(s.name));
      app.toast(`Removed the script check ${s.name}`);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    changed();
  };

  return (
    <>
      {scripts.length > 0 && (
        <ul className="script-checks" aria-label="Script checks">
          {scripts.map((s) => (
            <li key={s.name}>
              <b>{s.name}</b>
              <span className="mono small muted" title={`sha256 ${s.sha256}`}>
                {s.file}
              </span>
              {!s.enabled && <span className="muted small">off</span>}
              {s.problem && <span className="s5 small">Doesn't run: {s.problem}</span>}
              <span className="grow" />
              <button className="btn small" onClick={() => setEditing({ name: s.name, file: s.file })} title="Run it on a history row, or name its file again after a change">
                Test…
              </button>
              <button className="btn small" onClick={() => remove(s)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {editing && (
        <ScriptCheckDialog
          initial={editing}
          known={scripts.some((s) => s.name === editing.name)}
          close={() => setEditing(null)}
          saved={() => {
            setEditing(null);
            changed();
          }}
        />
      )}
    </>
  );
}

/** Opens the dialog to add a script check. */
export function AddScriptCheck({ changed }: { changed: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="btn" onClick={() => setOpen(true)} title="Add a passive check written in JavaScript">
        Add script check…
      </button>
      {open && (
        <ScriptCheckDialog
          initial={{ name: "", file: "" }}
          known={false}
          close={() => setOpen(false)}
          saved={() => {
            setOpen(false);
            changed();
          }}
        />
      )}
    </>
  );
}

/**
 * Name, file, and a test on a history row. `known`: it is an existing check (the name is fixed
 * and adding names its file again). Adding under a name already taken asks first.
 */
function ScriptCheckDialog(p: { initial: { name: string; file: string }; known: boolean; close: () => void; saved: () => void }) {
  const app = useApp();
  const [name, setName] = useState(p.initial.name);
  const [file, setFile] = useState(p.initial.file);
  const [row, setRow] = useState("");
  const [busy, setBusy] = useState(false);
  // The last test, of which file: an add of that file is pinned to the text tested.
  const [tested, setTested] = useState<(ScriptTest & { file: string }) | null>(null);
  const [error, setError] = useState("");
  const box = useRef<HTMLFormElement>(null);
  useDialogFocus(box);

  const nameProblem = scriptNameProblem(name.trim());
  const id = historyId(row);
  const pin = pinFor(tested, file.trim());

  const pick = async () => {
    try {
      const f = await chooseScript();
      if (f) setFile(f);
    } catch (e: any) {
      setError(e.message);
    }
  };

  const test = async () => {
    if (!file.trim() || id == null) return;
    setBusy(true);
    setError("");
    try {
      const t = await run<ScriptTest>(scriptTestArgs(file.trim(), id));
      setTested({ ...t, file: file.trim() });
    } catch (e: any) {
      setTested(null);
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const add = async () => {
    const n = name.trim();
    if (nameProblem || !file.trim()) return;
    setBusy(true);
    setError("");
    try {
      // The names as they are now, not as last polled: an add under a name already taken
      // replaces that check's file, so it asks first.
      if (!p.known) {
        const { scripts } = await run<{ scripts: ScriptCheck[] }>(SCRIPT_LIST_ARGS);
        if (
          scripts.some((s) => s.name === n) &&
          !(await confirm(`Replace the script check ${n}?`, "A script check already has that name: it would run this file instead.", "Replace", "Cancel"))
        ) {
          setBusy(false);
          return;
        }
      }
      await run(scriptAddArgs(n, file.trim(), pin));
      app.toast(p.known ? `The script check ${n} runs ${file.trim()} as it is now` : `Added the script check ${n}. Rescan to run it over the history there already is.`);
      p.saved();
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };

  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && p.close()}>
      <form
        ref={box}
        className="confirm-dialog script-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="script-title"
        aria-describedby="script-help"
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
      >
        <h2 id="script-title">{p.known ? `Script check ${p.initial.name}` : "Add a script check"}</h2>
        <p id="script-help">
          A JavaScript file whose <code>check(exchange)</code> is given each recorded request and response and returns findings. It runs with no file
          or network access and under a time limit, and sends nothing. The file is pinned by its sha256: if it changes, the check stops until you name
          it again here.
        </p>
        <div className="form">
          <label>
            <span>Name</span>
            <input
              className="input"
              value={name}
              disabled={p.known}
              autoFocus={!p.known}
              spellCheck={false}
              placeholder="letters, digits, _ - ."
              aria-invalid={!!name && !!nameProblem}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          {name && nameProblem && <p className="script-error">{nameProblem}</p>}
          <label>
            <span>File</span>
            <span className="row gap">
              <input className="input mono grow" value={file} spellCheck={false} placeholder="/path/to/check.js" onChange={(e) => setFile(e.target.value)} />
              <button type="button" className="btn" onClick={pick}>
                Choose…
              </button>
            </span>
          </label>
          <label>
            <span>Test on history #</span>
            <span className="row gap">
              <input className="input" style={{ width: 120 }} value={row} inputMode="numeric" placeholder="id in Traffic" onChange={(e) => setRow(e.target.value)} />
              <button type="button" className="btn" disabled={busy || !file.trim() || id == null} onClick={test} title="Run the file's check on that row's request and response. Nothing is saved or sent.">
                Test
              </button>
            </span>
          </label>
        </div>
        {tested && (
          <div className="script-test" role="status">
            <p>{testNote(tested)}</p>
            {tested.findings.length > 0 && (
              <ul>
                {tested.findings.map((f, i) => (
                  <li key={i}>
                    <span className={`dot-risk risk-${f.risk}`} /> {f.name} <span className="muted">({f.risk}, {f.confidence} confidence)</span>
                    {f.evidence && <span className="mono small"> {f.evidence}</span>}
                  </li>
                ))}
              </ul>
            )}
            {tested.file !== file.trim() && <p className="muted small">Another file was chosen since the test: test it to pin what is added to what was tested.</p>}
          </div>
        )}
        {error && (
          <p className="script-error" role="alert">
            {error}
          </p>
        )}
        <div className="row gap">
          {pin && <span className="muted small">Adds the file as tested (sha256 {pin.slice(0, 12)}…)</span>}
          <span className="grow" />
          <button type="button" className="btn" onClick={p.close}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={busy || !!nameProblem || !file.trim()}>
            {p.known ? "Name file again" : "Add"}
          </button>
        </div>
      </form>
    </div>
  );
}
