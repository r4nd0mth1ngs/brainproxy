// Viewer and editor for one raw HTTP message: Raw (highlighted, editable when onChange is
// given), Pretty (JSON and form bodies formatted), Hex, and for responses Render (HTML in a
// sandboxed iframe with no network, images), with a search bar.
// Line endings are shown and edited as \n; `send` turns the head's back into CRLF and an
// edit keeps the body's own (see message.ts).

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { decode, encodeAll } from "./urlencode";
import { RENDER_CAP, renderable } from "./render";
import { textBytes } from "../api";
import { normalizeHead, withBody } from "./message";

type Mode = "raw" | "pretty" | "hex" | "render";

/** Most body characters a read-only view shows before "Show all". */
const VIEW_CAP = 100_000;

export function normalize(raw: string): string {
  return raw.replace(/\r\n/g, "\n");
}

function splitMessage(text: string): [string, string, string] {
  const i = text.indexOf("\n\n");
  return i < 0 ? [text, "", ""] : [text.slice(0, i), "\n\n", text.slice(i + 2)];
}

type Range = [number, number];

/**
 * `text` with search matches marked, and the parts of `ranges` (offsets into the whole
 * message; `text` starts at `offset`) marked as a payload. Marking only wraps text, so the
 * editor's backdrop stays aligned with what is typed.
 */
function marks(text: string, query: string, key: string, offset = 0, ranges: Range[] = []): ReactNode[] {
  const local = ranges.map(([s, e]): Range => [Math.max(s - offset, 0), Math.min(e - offset, text.length)]).filter(([s, e]) => s < e);
  if (!query && !local.length) return [text];
  const hits: Range[] = [];
  if (query) {
    const lower = text.toLowerCase();
    const q = query.toLowerCase();
    for (let i = lower.indexOf(q); i >= 0; i = lower.indexOf(q, i + q.length)) hits.push([i, i + q.length]);
  }
  const cuts = [...new Set([0, text.length, ...hits.flat(), ...local.flat()])].sort((a, b) => a - b);
  const out: ReactNode[] = [];
  for (let i = 0; i + 1 < cuts.length; i++) {
    const [a, b] = [cuts[i], cuts[i + 1]];
    const piece = text.slice(a, b);
    const hit = hits.some(([s, e]) => a >= s && b <= e);
    const payload = local.some(([s, e]) => a >= s && b <= e);
    if (!hit && !payload) out.push(piece);
    else out.push(<mark key={`${key}${a}`} className={payload ? (hit ? "payload hit" : "payload") : undefined} title={payload ? "Payload" : undefined}>{piece}</mark>);
  }
  return out;
}

/** Colors the start line and header names; marks search matches and `ranges` everywhere. */
function highlight(text: string, query: string, ranges: Range[] = []): ReactNode[] {
  const [head, sep, body] = splitMessage(text);
  const lines = head.split("\n");
  const out: ReactNode[] = [];
  let at = 0;
  lines.forEach((line, n) => {
    if (n > 0) out.push("\n");
    const start = at;
    at += line.length + 1;
    if (n === 0) {
      const m = /^(\S+)(\s+)(\S+)(.*)$/.exec(line);
      if (m && /^HTTP\//.test(m[1])) {
        const cls = Number(m[3]) >= 500 ? "s5" : Number(m[3]) >= 400 ? "s4" : Number(m[3]) >= 300 ? "s3" : "s2";
        out.push(<span key="v" className="h-ver">{m[1]}</span>, m[2], <span key="s" className={`h-status ${cls}`}>{m[3]}</span>, <span key="r" className="h-reason">{m[4]}</span>);
      } else if (m) {
        const url = start + m[1].length + m[2].length;
        out.push(
          <span key="m" className="h-method">{marks(m[1], "", "m", start, ranges)}</span>,
          m[2],
          <span key="u" className="h-url">{marks(m[3], query, "u", url, ranges)}</span>,
          <span key="v" className="h-ver">{marks(m[4], "", "w", url + m[3].length, ranges)}</span>,
        );
      } else out.push(...marks(line, query, `l${n}`, start, ranges));
      return;
    }
    const c = line.indexOf(":");
    if (c > 0) {
      out.push(<span key={`h${n}`} className="h-name">{marks(line.slice(0, c), query, `n${n}`, start, ranges)}</span>, ":", <span key={`v${n}`} className="h-value">{marks(line.slice(c + 1), query, `v${n}`, start + c + 1, ranges)}</span>);
    } else out.push(...marks(line, query, `l${n}`, start, ranges));
  });
  out.push(sep, <span key="body" className="h-body">{marks(body, query, "b", head.length + sep.length, ranges)}</span>);
  return out;
}

function pretty(text: string): string {
  const [head, sep, body] = splitMessage(text);
  const t = body.trim();
  if (/^[[{]/.test(t)) {
    try {
      return head + sep + JSON.stringify(JSON.parse(t), null, 2);
    } catch {
      /* not JSON */
    }
  }
  if (/content-type:\s*application\/x-www-form-urlencoded/i.test(head) && t) {
    const lines = t.split("&").map((kv) => {
      const [k, v = ""] = kv.split("=");
      const dec = (s: string) => {
        try {
          return decodeURIComponent(s.replace(/\+/g, " "));
        } catch {
          return s;
        }
      };
      return `${dec(k)} = ${dec(v)}`;
    });
    return head + sep + lines.join("\n");
  }
  return text;
}

function hexdump(all: Uint8Array): string {
  const bytes = all.subarray(0, 65536);
  const rows: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    rows.push(`${off.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return rows.join("\n");
}

export function HttpView(p: {
  value: string;
  onChange?: (v: string) => void;
  title: ReactNode;
  extra?: ReactNode;
  placeholder?: string;
  /** Initial search text, e.g. a finding's evidence. */
  highlight?: string;
  /** The text holds a binary body, one char per byte (see `bodyText`). */
  binary?: boolean;
  /** Parts of the text (offsets with line breaks as \n) marked as a payload in the Raw view. */
  ranges?: Range[];
}) {
  const [mode, setMode] = useState<Mode>("raw");
  const [query, setQuery] = useState(p.highlight ?? "");
  useEffect(() => setQuery(p.highlight ?? ""), [p.highlight]);
  const back = useRef<HTMLPreElement>(null);
  const editor = useRef<HTMLTextAreaElement>(null);

  // Replaces the editor's selection with f(selection) and keeps the result selected.
  const transformSelection = (f: (s: string) => string) => {
    const el = editor.current;
    if (!el || !p.onChange || el.selectionStart === el.selectionEnd) return;
    const { selectionStart: a, selectionEnd: b, value } = el;
    const next = f(value.slice(a, b));
    p.onChange(withBody(value.slice(0, a) + next + value.slice(b), p.value));
    requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(a, a + next.length);
    });
  };
  const text = useMemo(() => normalize(p.value), [p.value]);
  // Render is offered only for responses; a request shown after one falls back to Raw.
  const isResponse = text.startsWith("HTTP/");
  const view: Mode = mode === "render" && !isResponse ? "raw" : mode;
  const [big, setBig] = useState(false);
  useEffect(() => setBig(false), [text]);
  const tooBig = text.length > RENDER_CAP && !big;
  // From the body's own bytes: a PNG's signature holds \r\n.
  const rendered = useMemo(() => (view === "render" && !tooBig ? renderable(normalizeHead(p.value)) : null), [view, tooBig, p.value]);
  const editable = !!p.onChange && view === "raw";
  const shown = useMemo(() => (view === "pretty" ? pretty(text) : text), [view, text]);
  const bytes = useMemo(() => textBytes(p.value, p.binary), [p.value, p.binary]);
  // WebKit lays a long <pre> out again after any change elsewhere on the page (about 0.7 s
  // for 1.7 MB), so a read-only view shows the headers and a slice of the body: from the
  // start, or around the first search match. Search counts still cover the whole message.
  const [all, setAll] = useState(false);
  useEffect(() => setAll(false), [text]);
  const slice = useMemo(() => {
    const [head, sep, body] = splitMessage(shown);
    if (editable || all || body.length <= VIEW_CAP) return { text: shown, hidden: 0 };
    const at = query ? body.toLowerCase().indexOf(query.toLowerCase()) : -1;
    const from = at < VIEW_CAP / 2 ? 0 : body.lastIndexOf("\n", at - VIEW_CAP / 2) + 1;
    return { text: head + sep + body.slice(from, from + VIEW_CAP), hidden: body.length - VIEW_CAP };
  }, [shown, editable, all, query]);
  // Offsets are into the whole text as it is: not Pretty's, nor a slice of it.
  const ranges = view === "raw" && slice.text === shown ? p.ranges : undefined;
  const nodes = useMemo(() => (view === "hex" ? [hexdump(bytes)] : highlight(slice.text, query, ranges)), [view, slice, bytes, query, ranges]);
  const hits = useMemo(() => {
    if (!query) return 0;
    const l = shown.toLowerCase();
    const q = query.toLowerCase();
    let n = 0;
    for (let i = l.indexOf(q); i >= 0; i = l.indexOf(q, i + q.length)) n++;
    return n;
  }, [shown, query]);

  return (
    <div className="msg">
      <div className="msg-bar">
        <span className="msg-title">{p.title}</span>
        <div className="seg">
          {(isResponse ? ["raw", "pretty", "hex", "render"] : ["raw", "pretty", "hex"]).map((m) => (
            <button key={m} className={view === m ? "on" : ""} onClick={() => setMode(m as Mode)}>
              {m === "raw" ? "Raw" : m === "pretty" ? "Pretty" : m === "hex" ? "Hex" : "Render"}
            </button>
          ))}
        </div>
        <div className="toolbar-end">
          {editable && (
            <div className="seg">
              <button onMouseDown={(e) => e.preventDefault()} onClick={() => transformSelection(encodeAll)} title="URL-encode the selection (⌘/Ctrl+U)">
                Encode
              </button>
              <button onMouseDown={(e) => e.preventDefault()} onClick={() => transformSelection((s) => decode(s, true))} title="URL-decode the selection (⌘/Ctrl+Shift+U)">
                Decode
              </button>
            </div>
          )}
          {p.extra}
        </div>
      </div>
      <div className="code-wrap">
        {view === "render" ? (
          <div className="render">
            {tooBig ? (
              <div className="blank">
                {(text.length / 1048576).toFixed(1)} MB response
                <button className="btn small" onClick={() => setBig(true)}>
                  Render anyway
                </button>
              </div>
            ) : rendered?.kind === "html" ? (
              <>
                <div className="render-note muted">Scripts, forms and remote resources are blocked.</div>
                {/* sandbox="": no scripts, origin, forms, popups or navigation; the injected CSP blocks every request. */}
                <iframe title="Rendered response" sandbox="" srcDoc={rendered.srcdoc} referrerPolicy="no-referrer" />
              </>
            ) : rendered?.kind === "image" ? (
              <img alt="Response image" src={rendered.src} />
            ) : (
              <div className="blank">Can't render this content type ({rendered?.kind === "none" ? rendered.type : ""}).</div>
            )}
          </div>
        ) : editable ? (
          <>
            <pre className="code backdrop" ref={back} aria-hidden>
              {nodes}
              {"\n"}
            </pre>
            <textarea
              ref={editor}
              className="code editor"
              onKeyDown={(e) => {
                if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "u") {
                  e.preventDefault();
                  transformSelection(e.shiftKey ? (s) => decode(s, true) : encodeAll);
                }
              }}
              spellCheck={false}
              value={text}
              placeholder={p.placeholder}
              onChange={(e) => p.onChange!(withBody(e.target.value, p.value))}
              onScroll={(e) => {
                if (back.current) back.current.scrollTop = e.currentTarget.scrollTop;
              }}
            />
          </>
        ) : (
          <pre className="code">{text ? nodes : <span className="muted">{p.placeholder}</span>}</pre>
        )}
      </div>
      <div className="msg-foot">
        <input className="search" placeholder="Search" value={query} onChange={(e) => setQuery(e.target.value)} />
        <span className="muted">{query ? `${hits} match${hits === 1 ? "" : "es"}` : `${bytes.length} bytes`}</span>
        {slice.hidden > 0 && view !== "hex" && (
          <button className="link small" onClick={() => setAll(true)} title="Long messages make the whole window slow">
            {Math.round(slice.hidden / 1024)} KB not shown · Show all
          </button>
        )}
      </div>
    </div>
  );
}
