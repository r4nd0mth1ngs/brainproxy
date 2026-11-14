// Comparer: items sent from other tools (or pasted, or loaded from history), two of them
// picked as A and B, diffed by line, word, or byte. `brainproxy diff` only compares history
// entries, so items are diffed here (Myers); for two history entries the CLI's similarity
// is shown as well.

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { bodyText, rawResponse, run, type HistoryEntry } from "../api";
import { useApp } from "../store";
import { Split } from "../ui/Split";
import { shownSimilarity, type Similarity } from "./comparerSimilarity.ts";

export type Unit = "lines" | "words" | "bytes";
type Op = 0 | 1 | -1; // equal, insert (B only), delete (A only)
export type Edit = [Op, string];

function tokens(text: string, unit: Unit): string[] {
  if (unit === "lines") return text.split(/(?<=\n)/);
  if (unit === "words") return text.match(/\s+|[^\s]+/g) ?? [];
  return Array.from(text);
}

// ponytail: past this many edits the diff gives up and shows A deleted, B inserted.
const MAX_EDITS = 4000;

/** Myers O(ND) diff of two token lists, common prefix and suffix trimmed first. */
export function diff(a: string[], b: string[]): Edit[] {
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const head: Edit[] = a.slice(0, pre).map((t) => [0, t]);
  const tail: Edit[] = a.slice(a.length - suf).map((t) => [0, t]);
  const x0 = a.slice(pre, a.length - suf);
  const y0 = b.slice(pre, b.length - suf);
  return [...head, ...myers(x0, y0), ...tail];
}

function myers(a: string[], b: string[]): Edit[] {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = []; // trace[d] = v[-d-1 ..= d+1] before step d
  for (let d = 0; d <= Math.min(max, MAX_EDITS); d++) {
    trace.push(v.slice(off - d - 1, off + d + 2));
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1] < v[off + k + 1]) ? v[off + k + 1] : v[off + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) return backtrack(a, b, trace);
    }
  }
  return [...a.map((t): Edit => [-1, t]), ...b.map((t): Edit => [1, t])];
}

function backtrack(a: string[], b: string[], trace: Int32Array[]): Edit[] {
  const out: Edit[] = [];
  let x = a.length;
  let y = b.length;
  for (let d = trace.length - 1; d >= 0; d--) {
    const get = (k: number) => trace[d][k + d + 1];
    const k = x - y;
    const prevK = k === -d || (k !== d && get(k - 1) < get(k + 1)) ? k + 1 : k - 1;
    const prevX = get(prevK);
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) out.push([0, a[--x]]), y--;
    if (d > 0) {
      if (x === prevX) out.push([1, b[--y]]);
      else out.push([-1, a[--x]]);
    }
  }
  return out.reverse();
}

/** Consecutive edits with the same op joined, for inline rendering. */
function runs(edits: Edit[], keep: (op: Op) => boolean): Edit[] {
  const out: Edit[] = [];
  for (const [op, t] of edits) {
    if (!keep(op)) continue;
    const last = out[out.length - 1];
    if (last && last[0] === op) last[1] += t;
    else out.push([op, t]);
  }
  return out;
}

const CLS: Record<Op, string | undefined> = { 0: undefined, 1: "cmp-ins", [-1]: "cmp-del" };

function inline(edits: Edit[]): ReactNode[] {
  return edits.map(([op, t], i) => (op === 0 ? t : <span key={i} className={CLS[op]}>{t}</span>));
}

/** Line diff as aligned rows: changed runs pair A's deleted lines with B's inserted ones. */
function rows(edits: Edit[]): { a: string | null; b: string | null; op: Op }[] {
  const out: { a: string | null; b: string | null; op: Op }[] = [];
  for (let i = 0; i < edits.length; ) {
    if (edits[i][0] === 0) {
      out.push({ a: edits[i][1], b: edits[i][1], op: 0 });
      i++;
      continue;
    }
    const del: string[] = [];
    const ins: string[] = [];
    for (; i < edits.length && edits[i][0] !== 0; i++) (edits[i][0] < 0 ? del : ins).push(edits[i][1]);
    for (let j = 0; j < Math.max(del.length, ins.length); j++) out.push({ a: del[j] ?? null, b: ins[j] ?? null, op: 1 });
  }
  return out;
}

const strip = (l: string) => l.replace(/\r?\n$/, "");

// ---------------- view ----------------

export function ComparerView() {
  const app = useApp();
  const items = app.comparer;
  const [pick, setPick] = useState<{ a: number | null; b: number | null }>({ a: null, b: null });
  const [unit, setUnit] = useState<Unit>("lines");
  const [layout, setLayout] = useState<"side" | "unified">("side");
  const [paste, setPaste] = useState("");
  const [hist, setHist] = useState({ a: "", b: "", part: "response" as "request" | "response" | "response-body" });
  const [similarity, setSimilarity] = useState<Similarity | null>(null);

  // When the list changes, compare the last two items, so "send, send" compares those two.
  useEffect(() => setPick({ a: items.length > 1 ? items.length - 2 : null, b: items.length ? items.length - 1 : null }), [items]);

  const A = pick.a != null ? items[pick.a] : undefined;
  const B = pick.b != null ? items[pick.b] : undefined;
  const edits = useMemo(() => (A == null || B == null ? null : diff(tokens(A, unit), tokens(B, unit))), [A, B, unit]);
  const stats = useMemo(() => {
    if (!edits) return null;
    let del = 0;
    let ins = 0;
    for (const [op] of edits) op < 0 ? del++ : op > 0 && ins++;
    return { del, ins };
  }, [edits]);

  const add = (text: string) => app.setComparer([...items, text]);
  const remove = (i: number) => app.setComparer(items.filter((_, j) => j !== i));

  const fromHistory = async () => {
    const ids = [hist.a, hist.b].map((s) => s.trim().replace(/^#/, ""));
    if (!ids.every((s) => /^\d+$/.test(s))) return app.toast("Enter two history ids", "error");
    try {
      const [ea, eb, d] = await Promise.all([
        run<HistoryEntry>(["history", "show", ids[0], "--max-body", "2000000"]),
        run<HistoryEntry>(["history", "show", ids[1], "--max-body", "2000000"]),
        run<{ similarity: number }>(["diff", ids[0], ids[1], "--part", hist.part, "--mode", unit, "--max-changes", "0"]),
      ]);
      const part = (e: HistoryEntry) => (hist.part === "request" ? bodyText(e.request) : hist.part === "response" ? rawResponse(e) : bodyText(e.response?.body));
      const [a, b] = [part(ea), part(eb)];
      app.setComparer([...items, a, b]);
      setSimilarity({ a, b, unit, value: d.similarity });
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const cliSimilarity = shownSimilarity(similarity, A, B, unit);
  return (
    <Split id="comparer" dir="row" initial={0.3}>
      <div className="col fill cmp-items">
        <div className="toolbar">
          <span className="label">Items</span>
          <span className="grow" />
          <button className="btn small" disabled={!items.length} onClick={() => app.setComparer([])}>
            Clear all
          </button>
        </div>
        <div className="cmp-list">
          {items.length === 0 && <div className="empty">Send requests or responses here from Traffic, Replay, or Fuzzer, or paste below.</div>}
          {items.map((t, i) => (
            <div key={i} className={`cmp-item ${pick.a === i || pick.b === i ? "on" : ""}`}>
              <div className="seg">
                <button className={pick.a === i ? "on" : ""} onClick={() => setPick({ ...pick, a: i })} title="Compare as A">
                  A
                </button>
                <button className={pick.b === i ? "on" : ""} onClick={() => setPick({ ...pick, b: i })} title="Compare as B">
                  B
                </button>
              </div>
              <div className="cmp-item-text">
                <div className="mono ellipsis">{t.split("\n", 1)[0] || "(empty first line)"}</div>
                <div className="muted small">
                  #{i + 1} · {new TextEncoder().encode(t).length} bytes · {t.split("\n").length} lines
                </div>
              </div>
              <button className="icon-btn" title="Remove" onClick={() => remove(i)}>
                ×
              </button>
            </div>
          ))}
        </div>
        <div className="cmp-add">
          <textarea className="code dec-text" spellCheck={false} placeholder="Paste an item" value={paste} onChange={(e) => setPaste(e.target.value)} />
          <div className="row gap">
            <button
              className="btn small"
              disabled={!paste}
              onClick={() => {
                add(paste);
                setPaste("");
              }}
            >
              Add item
            </button>
          </div>
          <div className="label">From history</div>
          <div className="row gap">
            <input className="input mono fz-num" placeholder="#A" value={hist.a} onChange={(e) => setHist({ ...hist, a: e.target.value })} />
            <input className="input mono fz-num" placeholder="#B" value={hist.b} onChange={(e) => setHist({ ...hist, b: e.target.value })} />
            <select className="input" value={hist.part} onChange={(e) => setHist({ ...hist, part: e.target.value as typeof hist.part })}>
              <option value="request">request</option>
              <option value="response">response</option>
              <option value="response-body">response body</option>
            </select>
            <button className="btn small" onClick={fromHistory}>
              Compare
            </button>
          </div>
        </div>
      </div>
      <div className="col fill">
        <div className="toolbar">
          <div className="seg">
            {(["lines", "words", "bytes"] as Unit[]).map((u) => (
              <button key={u} className={unit === u ? "on" : ""} onClick={() => setUnit(u)}>
                {u === "lines" ? "Lines" : u === "words" ? "Words" : "Bytes"}
              </button>
            ))}
          </div>
          <div className="seg">
            <button className={layout === "side" ? "on" : ""} onClick={() => setLayout("side")}>
              Side by side
            </button>
            <button className={layout === "unified" ? "on" : ""} onClick={() => setLayout("unified")}>
              Unified
            </button>
          </div>
          <span className="grow" />
          {stats && (
            <span className="muted">
              {stats.del === 0 && stats.ins === 0 ? "Identical" : `${stats.del} ${unit} removed · ${stats.ins} added`}
              {cliSimilarity != null && ` · similarity ${(cliSimilarity * 100).toFixed(1)}%`}
            </span>
          )}
        </div>
        {!edits ? (
          <div className="blank">
            <p>Pick an item as A and another as B.</p>
          </div>
        ) : unit === "lines" ? (
          <LineDiff edits={edits} layout={layout} />
        ) : layout === "side" ? (
          <div className="cmp-sides">
            <pre className="code cmp-pane">{inline(runs(edits, (op) => op <= 0))}</pre>
            <pre className="code cmp-pane">{inline(runs(edits, (op) => op >= 0))}</pre>
          </div>
        ) : (
          <pre className="code cmp-pane">{inline(runs(edits, () => true))}</pre>
        )}
      </div>
    </Split>
  );
}

function LineDiff({ edits, layout }: { edits: Edit[]; layout: "side" | "unified" }) {
  if (layout === "unified")
    return (
      <div className="code cmp-pane cmp-lines">
        {edits.map(([op, t], i) => (
          <div key={i} className={CLS[op]}>
            <span className="cmp-sign">{op < 0 ? "-" : op > 0 ? "+" : " "}</span>
            {strip(t)}
          </div>
        ))}
      </div>
    );
  return (
    <div className="code cmp-pane cmp-grid">
      {rows(edits).map((r, i) => [
        <div key={`a${i}`} className={r.op ? (r.a == null ? "cmp-gap" : "cmp-del") : undefined}>
          {r.a == null ? "" : strip(r.a)}
        </div>,
        <div key={`b${i}`} className={r.op ? (r.b == null ? "cmp-gap" : "cmp-ins") : undefined}>
          {r.b == null ? "" : strip(r.b)}
        </div>,
      ])}
    </div>
  );
}
