// The command palette: every action that can run here, found by typing a few letters of it.
// Arrow keys move, Enter runs, Esc closes. An action runs once the palette has closed, so a
// question it asks (stop running sends? discard?) comes up as it would from its button.

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { bindingOf, matches, type Action } from "./actions.ts";
import { chordOf, formatChord } from "./chords.ts";
import { rank } from "./fuzzy.ts";
import { useDialogFocus } from "./dialogFocus";
import { useActionList, useOverrides } from "./useActions.ts";

/** Actions run from the palette lately, latest first; shown first when nothing is typed. */
let recentRuns: string[] = [];

/** The actions the palette offers in `view`: runnable, not hidden, and for here. */
export function paletteActions(list: Action[], view: string): Action[] {
  return list.filter((a) => a.run && !a.noPalette && !a.hidden && ((a.where ?? "global") === "global" || a.where === view));
}

/** With nothing typed: recent runs, then this view's, then the rest, each group together. */
function byDefault(list: Action[], view: string): { a: Action; heading: string }[] {
  const recent = recentRuns.map((id) => list.find((a) => a.id === id)).filter((a): a is Action => !!a && !a.disabled).slice(0, 5);
  const rest = list.filter((a) => !recent.includes(a));
  const groups: string[] = [];
  for (const a of rest) if (!groups.includes(a.group)) groups.push(a.group);
  // This view's own actions first.
  groups.sort((x, y) => Number(rest.some((a) => a.group === y && a.where === view)) - Number(rest.some((a) => a.group === x && a.where === view)));
  return [...recent.map((a) => ({ a, heading: "Recently used" })), ...groups.flatMap((g) => rest.filter((a) => a.group === g).map((a) => ({ a, heading: g })))];
}

function highlight(text: string, at: number[]): ReactNode {
  if (!at.length) return text;
  const set = new Set(at);
  return [...text].map((c, i) => (set.has(i) ? <mark key={i}>{c}</mark> : c));
}

export function Palette({ view, mac, close }: { view: string; mac: boolean; close: () => void }) {
  const all = useActionList();
  const overrides = useOverrides();
  const [query, setQuery] = useState("");
  const [at, setAt] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  useDialogFocus(box);

  const offered = useMemo(() => paletteActions(all, view), [all, view]);
  const rows = useMemo(() => {
    if (!query.trim()) return byDefault(offered, view).map(({ a, heading }) => ({ a, heading, marks: [] as number[] }));
    // Disabled ones after the rest.
    const ranked = rank(query, offered, (a) => a.title, (a) => `${a.group} ${a.keywords ?? ""}`);
    return [...ranked.filter((r) => !r.item.disabled), ...ranked.filter((r) => r.item.disabled)].map((r) => ({ a: r.item, heading: "", marks: r.at }));
  }, [offered, query, view]);
  useEffect(() => setAt(0), [query]);
  const sel = Math.min(at, rows.length - 1);

  useEffect(() => {
    listRef.current?.querySelector(`[data-row="${sel}"]`)?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const choose = (a: Action | undefined) => {
    if (!a || a.disabled) return;
    recentRuns = [a.id, ...recentRuns.filter((id) => id !== a.id)].slice(0, 10);
    close();
    // After the palette is gone, so focus is back where it was and a question it asks shows alone.
    setTimeout(() => a.run?.());
  };

  const move = (d: number) => rows.length && setAt((sel + d + rows.length) % rows.length);
  const onKey = (e: React.KeyboardEvent) => {
    // Kept here: nothing else runs while the palette is open.
    e.stopPropagation();
    // Its own shortcut closes it again.
    if (matches("app.palette", chordOf(e.nativeEvent, mac))) {
      e.preventDefault();
      return close();
    }
    const step = { ArrowDown: 1, ArrowUp: -1, PageDown: 8, PageUp: -8 }[e.key];
    if (step != null) {
      e.preventDefault();
      // Page keys stop at the ends; arrows wrap round.
      if (Math.abs(step) > 1) setAt(Math.max(0, Math.min(rows.length - 1, sel + step)));
      else move(step);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (!e.nativeEvent.isComposing) choose(rows[sel]?.a);
    } else if (e.key === "Escape") {
      e.preventDefault();
      close();
    } else if (e.key === "Tab") e.preventDefault();
  };

  const id = (i: number) => `palette-row-${i}`;
  return (
    <div className="confirm-backdrop palette-backdrop" onMouseDown={(e) => e.target === e.currentTarget && close()} onKeyDown={onKey}>
      <div ref={box} className="palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <input
          className="palette-input"
          autoFocus
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-activedescendant={rows.length ? id(sel) : undefined}
          aria-autocomplete="list"
          placeholder="Type a command or a view…"
          spellCheck={false}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="palette-list" id="palette-list" role="listbox" ref={listRef} aria-label="Commands">
          {rows.length === 0 && <div className="palette-empty muted">No command matches “{query.trim()}”.</div>}
          {rows.map(({ a, heading, marks }, i) => {
            const chord = bindingOf(a, overrides);
            return (
              <div key={a.id}>
                {heading && heading !== rows[i - 1]?.heading && (
                  <div className="palette-heading" role="presentation">
                    {heading}
                  </div>
                )}
                <div
                  id={id(i)}
                  data-row={i}
                  role="option"
                  aria-selected={i === sel}
                  aria-disabled={a.disabled ? true : undefined}
                  className={`palette-row${i === sel ? " on" : ""}${a.disabled ? " off" : ""}`}
                  onMouseMove={() => i !== sel && setAt(i)}
                  onClick={() => choose(a)}
                >
                  <span className="palette-title">{highlight(a.title, marks)}</span>
                  {a.disabled ? <span className="palette-note">{a.disabled}</span> : !heading && <span className="palette-note">{a.group}</span>}
                  {chord && <kbd className="kbd">{formatChord(chord, mac)}</kbd>}
                </div>
              </div>
            );
          })}
        </div>
        <div className="palette-foot muted">
          <span>
            <kbd className="kbd">↑</kbd> <kbd className="kbd">↓</kbd> to move
          </span>
          <span>
            <kbd className="kbd">{mac ? "↩" : "Enter"}</kbd> to run
          </span>
          <span>
            <kbd className="kbd">Esc</kbd> to close
          </span>
          <span className="grow" />
          <span>Shortcuts: Settings › Keyboard</span>
        </div>
      </div>
    </div>
  );
}
