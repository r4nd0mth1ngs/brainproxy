// Settings › Keyboard: every action with its shortcut, to change, clear or reset. Bindings are the
// person's (kept in the app's local storage), the same in every project.

import { useMemo, useRef, useState } from "react";
import { useApp } from "../store";
import { whereLabel } from "../nav";
import { bindingOf, clashes, conflicts, setOverrides, withBinding, type Action, type Overrides } from "../ui/actions.ts";
import { bindProblem, chordOf, formatChord, isMac } from "../ui/chords.ts";
import { confirm } from "../ui/Confirm";
import { useActionList, useKeyLabel, useOverrides } from "../ui/useActions.ts";
import { rank } from "../ui/fuzzy.ts";

const MAC = isMac();

/** A chord waiting for the person to say what happens to the actions that already have it. */
interface Pending {
  id: string;
  chord: string;
  others: Action[];
}

export function Keyboard() {
  const app = useApp();
  const all = useActionList();
  const overrides = useOverrides();
  const [filter, setFilter] = useState("");
  const [recording, setRecording] = useState<string | null>(null);
  const [problem, setProblem] = useState<{ id: string; text: string } | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const paletteKey = useKeyLabel("app.palette");

  const list = useMemo(() => all.filter((a) => !a.unbindable), [all]);
  const clash = useMemo(() => conflicts(list, overrides), [list, overrides]);
  const shown = useMemo(() => {
    if (!filter.trim()) return list;
    // Matches the title, its heading, where it applies and the shortcut as shown.
    return rank(filter, list, (a) => a.title, (a) => `${a.group} ${whereLabel(a.where)} ${keysOf(a, overrides)}`).map((r) => r.item);
  }, [list, filter, overrides]);
  const groups = useMemo(() => {
    const out: string[] = [];
    for (const a of shown) if (!out.includes(a.group)) out.push(a.group);
    return out;
  }, [shown]);
  const titleOf = (id: string) => list.find((a) => a.id === id)?.title ?? id;

  const save = (o: Overrides) => {
    if (!setOverrides(o)) app.toast("The shortcut changed for now, but it couldn't be saved: the app's storage is unavailable.", "error");
  };
  const bind = (a: Action, chord: string | null) => save(withBinding(overrides, a, chord));

  const recorded = (a: Action, chord: string) => {
    setRecording(null);
    const why = bindProblem(chord);
    if (why) return setProblem({ id: a.id, text: why });
    setProblem(null);
    const others = clashes(list, overrides, a, chord);
    if (others.length) return setPending({ id: a.id, chord, others });
    bind(a, chord);
  };

  const resetAll = async () => {
    if (!(await confirm("Reset every shortcut?", "Each action goes back to its default shortcut, or none. Your changes are lost.", "Reset all", "Keep mine"))) return;
    setPending(null);
    setProblem(null);
    save({});
  };

  const changed = Object.keys(overrides).length;
  return (
    <div className="detail keys">
      <div className="keys-head">
        <h2>Keyboard</h2>
        <p className="muted">
          Shortcuts for the app's actions, the same in every project. The command palette
          {paletteKey ? ` (${paletteKey})` : ""} runs any action by name. Shortcuts don't run while you type in a text field, except ones that are meant to there (such as
          Send in Replay). In lists and dialogs the usual keys (arrows, Enter, Esc, Tab) work as they always do.
        </p>
        <div className="row gap">
          <input className="input search" style={{ width: 280 }} placeholder="Find an action or a shortcut" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <span className="grow" />
          {clash.size > 0 && <span className="tag keys-warn">{clash.size} actions share a shortcut</span>}
          <button className="btn" disabled={changed === 0} onClick={resetAll} title="Every action back to its default shortcut">
            Reset all to defaults
          </button>
        </div>
      </div>
      {groups.map((g) => (
        <section key={g} className="keys-group">
          <h3>{g}</h3>
          <div className="keys-list" role="list">
            {shown
              .filter((a) => a.group === g)
              .map((a) => {
                const chord = bindingOf(a, overrides);
                const isChanged = Object.hasOwn(overrides, a.id);
                const others = clash.get(a.id);
                return (
                  <div key={a.id} className="keys-row" role="listitem">
                    <div className="keys-what">
                      <span>{a.title}</span>
                      <span className="muted small">{whereLabel(a.where)}{a.typing ? ", also while typing" : ""}</span>
                      {others && <span className="keys-clash small">Also the shortcut of {others.map(titleOf).join(", ")}: only one runs.</span>}
                      {problem?.id === a.id && <span className="keys-clash small">{problem.text}</span>}
                      {pending?.id === a.id && (
                        <span className="confirm small">
                          <span>
                            {formatChord(pending.chord, MAC)} is {pending.others.map((o) => o.title).join(", ")}.
                          </span>
                          <button
                            className="btn small primary"
                            onClick={() => {
                              let o = withBinding(overrides, a, pending.chord);
                              for (const other of pending.others) o = withBinding(o, other, null);
                              setPending(null);
                              save(o);
                            }}
                          >
                            Use it here instead
                          </button>
                          <button className="btn small" onClick={() => setPending(null)}>
                            Cancel
                          </button>
                        </span>
                      )}
                    </div>
                    <Recorder
                      chord={chord}
                      recording={recording === a.id}
                      start={() => {
                        setProblem(null);
                        setPending(null);
                        setRecording(a.id);
                      }}
                      stop={() => setRecording((r) => (r === a.id ? null : r))}
                      done={(c) => recorded(a, c)}
                      label={a.title}
                    />
                    <div className="keys-actions">
                      <button className="btn small" disabled={!chord} onClick={() => bind(a, null)} title="No shortcut for this action">
                        Clear
                      </button>
                      <button
                        className="btn small"
                        disabled={!isChanged}
                        onClick={() => bind(a, a.keys ?? null)}
                        title={a.keys ? `Back to ${formatChord(a.keys, MAC)}` : "Back to no shortcut"}
                      >
                        Reset
                      </button>
                    </div>
                  </div>
                );
              })}
          </div>
        </section>
      ))}
      {shown.length === 0 && <p className="muted">No action matches “{filter.trim()}”.</p>}
    </div>
  );
}

const keysOf = (a: Action, o: Overrides) => {
  const c = bindingOf(a, o);
  return c ? formatChord(c, MAC) : "";
};

/** The shortcut, and a button that records the next chord pressed (Esc cancels, leaving it cancels). */
function Recorder(p: { chord: string | null; recording: boolean; start: () => void; stop: () => void; done: (chord: string) => void; label: string }) {
  const ref = useRef<HTMLButtonElement>(null);
  return (
    <button
      ref={ref}
      className={`keys-chord${p.recording ? " on" : ""}`}
      aria-label={p.recording ? `Press the new shortcut for ${p.label}, or Esc to cancel` : `Change the shortcut for ${p.label}`}
      title={p.recording ? "Press the new shortcut, or Esc to cancel" : "Click, then press the new shortcut"}
      onClick={() => (p.recording ? p.stop() : p.start())}
      onBlur={p.stop}
      // Space presses a button when it comes up: not after it was recorded (or refused).
      onKeyUp={(e) => e.key === " " && e.preventDefault()}
      onKeyDown={(e) => {
        if (!p.recording) return;
        // Leaving with Tab cancels (the blur does).
        if (e.key === "Tab" && !e.ctrlKey && !e.metaKey && !e.altKey) return;
        // Taken here: the key being recorded mustn't run anything.
        e.preventDefault();
        e.stopPropagation();
        if (e.key === "Escape") return p.stop();
        const chord = chordOf(e.nativeEvent, MAC);
        if (chord) p.done(chord);
      }}
    >
      {p.recording ? "Press keys…" : p.chord ? <kbd className="kbd">{formatChord(p.chord, MAC)}</kbd> : <span className="muted">None</span>}
    </button>
  );
}
