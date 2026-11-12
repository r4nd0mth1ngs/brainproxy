// Fuzzer (Intruder): a request template with §-marked positions, payload sets, and attack
// options, started as `fuzz run --background`; a run's progress and results are polled from
// `fuzz status` / `fuzz results`, and each result's exchange is read with `history show`.

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { bodyText, historyRequest, isBinary, MAX_BODY, rawResponse, run, withScheme, type HistoryEntry } from "../api";
import { originOf, useApp } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { markable, normalizeHead, splitRaw, templateBytes, withBody } from "../ui/message";
import { Menu, useMenu } from "../ui/Menu";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { useActions } from "../ui/useActions.ts";
import { subTabActions } from "../nav";

const M = "§";

type Mode = "sniper" | "battering-ram" | "pitchfork" | "cluster-bomb";

const MODES: { id: Mode; label: string; help: string }[] = [
  { id: "sniper", label: "Sniper", help: "One payload set; each position in turn, the others keep their value." },
  { id: "battering-ram", label: "Battering ram", help: "One payload set; the same payload in every position at once." },
  { id: "pitchfork", label: "Pitchfork", help: "One set per position, walked in step (the shortest set ends the attack)." },
  { id: "cluster-bomb", label: "Cluster bomb", help: "One set per position, every combination." },
];

type Source = "builtin" | "list" | "range" | "file";

interface PayloadSet {
  source: Source;
  wordlist: string; // built-in list name (`brainproxy wordlists list`)
  list: string; // one payload per line
  from: string;
  to: string;
  step: string;
  file: string;
  process: string; // comma-separated chain, e.g. "url,base64"
}

const NEW_SET: PayloadSet = { source: "builtin", wordlist: "sqli", list: "", from: "1", to: "100", step: "1", file: "", process: "" };

interface Wordlist {
  name: string;
  description: string;
  caution: string | null;
  count: number;
  sources: { repo: string; path: string; license: string }[];
}

// The built-in lists never change while the app runs; load them once.
let wordlistsCache: Promise<Wordlist[]> | null = null;
const loadWordlists = () =>
  (wordlistsCache ??= run<{ lists: Wordlist[] }>(["wordlists", "list"]).then(
    (d) => d.lists,
    (e) => {
      wordlistsCache = null;
      throw e;
    },
  ));

interface Options {
  concurrency: string;
  rate: string;
  maxRequests: string;
  timeout: string;
  grep: string; // one regex per line
  extract: string;
  matchStatus: string;
  stopOnMatch: boolean;
  encode: boolean;
  store: "all" | "matches" | "none";
  auth: string;
  http2: boolean;
}

const DEFAULTS: Options = {
  concurrency: "10",
  rate: "",
  maxRequests: "",
  timeout: "30",
  grep: "",
  extract: "",
  matchStatus: "",
  stopOnMatch: false,
  encode: true,
  store: "all",
  auth: "",
  http2: false,
};

const BLANK = `GET /?q=${M}test${M} HTTP/1.1\nHost: \nUser-Agent: brainproxy\nAccept: */*\n\n`;

const positionCount = (raw: string) => Math.floor((raw.split(M).length - 1) / 2);

/** scheme://host from the Host header, for templates typed by hand. */
function guessTarget(raw: string): string {
  const host = /^host:\s*(\S+)/im.exec(raw)?.[1];
  return host ? `${/:443$/.test(host) ? "https" : "http"}://${host.replace(/:443$/, "")}` : "";
}

/** Marks query and body parameter values (form, JSON) as positions. */
export function autoMark(raw: string, binary = false): string {
  // The body keeps its line endings (a multipart body needs its CRLF). In a binary body
  // "§" is the byte 0xA7, not a marker, and nothing there is marked.
  const { head: h, sep, body: b } = splitRaw(normalizeHead(raw));
  const head = h.split(M).join("");
  let body = binary ? b : b.split(M).join("");
  const nl = head.indexOf("\n");
  const line = (nl < 0 ? head : head.slice(0, nl)).replace(/([?&][^=&#\s]+=)([^&#\s]*)/g, `$1${M}$2${M}`);
  const t = binary ? "" : body.trim();
  if (/^[[{]/.test(t)) {
    body = body.replace(/("(?:[^"\\]|\\.)*"\s*:\s*)(?:"((?:[^"\\]|\\.)*)"|(-?\d[\d.eE+-]*|true|false|null))/g, (_m, key, str, lit) =>
      str !== undefined ? `${key}"${M}${str}${M}"` : `${key}${M}${lit}${M}`,
    );
  } else if (/^[^=&\s]+=[^&\s]*(&[^=&\s]+=[^&\s]*)*$/.test(t)) {
    body = body.replace(/(^|&)([^=&\s]+=)([^&\s]*)/g, `$1$2${M}$3${M}`);
  }
  return line + (nl < 0 ? "" : head.slice(nl)) + (sep ? "\n\n" + body : "");
}

/** Fills an empty Host header (as in the blank template) from the target scheme://host[:port]. */
export function fillHost(raw: string, target: string): string {
  return raw.replace(/^(host:)[ \t]*(?=\r?\n|$)/im, `$1 ${target.replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "")}`);
}

export function payloadSpec(s: PayloadSet): string {
  if (s.source === "builtin") return `wordlist:${s.wordlist}`;
  if (s.source === "range") return `range:${s.from}-${s.to}${s.step && s.step !== "1" ? `:${s.step}` : ""}`;
  if (s.source === "file") return `file:${s.file}`;
  // ponytail: list: escapes commas as \, ; a payload ending in a backslash before the next one is misread.
  const items = s.list.split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l !== "");
  return "list:" + items.map((p) => p.replace(/,/g, "\\,")).join(",");
}

export function FuzzerView() {
  const app = useApp();
  const [sub, setSub] = useState<"attack" | "results" | "runs">("attack");
  const [runId, setRunId] = useState<number | null>(null);

  const open = (id: number) => {
    setRunId(id);
    setSub("results");
  };

  useActions(
    subTabActions("fuzzer", "Fuzzer", [["attack", "Attack"], ["results", "Results"], ["runs", "Runs"]] as const, (s) => {
      app.setTab("fuzzer");
      setSub(s);
    }),
  );
  return (
    <div className="col fill">
      <div className="subtabs">
        <button className={sub === "attack" ? "on" : ""} onClick={() => setSub("attack")}>
          Attack
        </button>
        <button className={sub === "results" ? "on" : ""} onClick={() => setSub("results")}>
          Results{runId != null ? ` · run ${runId}` : ""}
        </button>
        <button className={sub === "runs" ? "on" : ""} onClick={() => setSub("runs")}>
          Runs
        </button>
      </div>
      <div className="fill" hidden={sub !== "attack"}>
        <Attack onStarted={open} onShow={() => setSub("attack")} active={sub === "attack"} />
      </div>
      <div className="fill" hidden={sub !== "results"}>
        {runId == null ? (
          <div className="blank">
            <p>Start an attack, or open a previous run from Runs.</p>
          </div>
        ) : (
          // key: each run has its own polling state.
          <RunResults key={runId} id={runId} active={app.tab === "fuzzer" && sub === "results"} />
        )}
      </div>
      <div className="fill" hidden={sub !== "runs"}>
        <Runs active={app.tab === "fuzzer" && sub === "runs"} current={runId} onOpen={open} />
      </div>
    </div>
  );
}

// ---------------- Attack (positions, payloads, options) ----------------

function Attack({ onStarted, onShow, active }: { onStarted: (id: number) => void; onShow: () => void; active: boolean }) {
  const app = useApp();
  const [raw, setRaw] = useState(BLANK);
  // The template holds a binary body, one char per byte (see `bodyText`).
  const [binary, setBinary] = useState(false);
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<Mode>("sniper");
  const [sets, setSets] = useState<PayloadSet[]>([{ ...NEW_SET }]);
  const [opts, setOpts] = useState<Options>(DEFAULTS);
  const [busy, setBusy] = useState(false);
  const [lists, setLists] = useState<Wordlist[]>([]);
  const editor = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    loadWordlists().then(setLists, () => {});
  }, []);
  const back = useRef<HTMLPreElement>(null);

  // A request sent from another tool replaces the template.
  useEffect(() => {
    const h = app.fuzzerInput;
    if (!h) return;
    setRaw(autoMark(h.raw, !!h.binary));
    setBinary(!!h.binary);
    setTarget(h.target);
    onShow();
  }, [app.fuzzerInput]); // onShow only switches the sub-tab

  const positions = positionCount(markable(raw, binary));
  const needed = mode === "pitchfork" || mode === "cluster-bomb" ? Math.max(1, positions) : 1;
  // Keep one payload set per needed slot; extra sets are kept hidden in case the mode flips back.
  useEffect(() => {
    if (sets.length < needed) setSets((ss) => [...ss, ...Array.from({ length: needed - ss.length }, () => ({ ...NEW_SET }))]);
  }, [needed, sets.length]);

  const addMark = () => {
    const el = editor.current;
    if (!el) return;
    const { selectionStart: a, selectionEnd: b } = el;
    setRaw(raw.slice(0, a) + M + raw.slice(a, b) + M + raw.slice(b));
    requestAnimationFrame(() => {
      el.focus();
      el.setSelectionRange(a + 1, b + 1);
    });
  };

  const start = async () => {
    const to = withScheme(target || guessTarget(raw));
    if (!to) return app.toast("Set a target (scheme://host[:port]) or a Host header", "error");
    if (!positions) return app.toast("Mark at least one payload position with §value§", "error");
    setTarget(to);
    const used = sets.slice(0, needed);
    // The raw request goes on stdin: argv can't hold NUL bytes or megabytes, and `ps` shows it.
    const args = ["fuzz", "run", "--background", `--mode=${mode}`, `--target=${to}`];
    used.forEach((s, i) => {
      args.push(`--payloads=${payloadSpec(s)}`);
      if (s.process.trim()) args.push(`--process=${i + 1}=${s.process.trim()}`);
    });
    const num = (flag: string, v: string) => v.trim() && args.push(`--${flag}=${v.trim()}`);
    num("concurrency", opts.concurrency);
    num("rate", opts.rate);
    num("max-requests", opts.maxRequests);
    num("timeout", opts.timeout);
    num("extract", opts.extract);
    num("match-status", opts.matchStatus.replace(/\s+/g, ""));
    num("auth", opts.auth);
    for (const g of opts.grep.split("\n")) num("grep", g);
    if (opts.stopOnMatch) args.push("--stop-on-match");
    if (!opts.encode) args.push("--no-encode");
    if (opts.http2) args.push("--http2");
    args.push(`--store=${opts.store}`, "-");
    setBusy(true);
    try {
      const d = await run<{ run: RunInfo }>(args, templateBytes(fillHost(raw, to), binary));
      onStarted(d.run.id);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    setBusy(false);
  };
  useActions([{ id: "fuzzer.start", title: "Start the attack", group: "Fuzzer", where: "fuzzer", hidden: !active, disabled: busy ? "Starting…" : false, run: start }]);

  // Content discovery: GET /§path§ on the target with the built-in path list. GET only,
  // since some listed endpoints (e.g. /actuator/shutdown) act on POST.
  const discoverContent = () => {
    const to = withScheme(target || guessTarget(raw));
    if (!to) return app.toast("Set a target first (scheme://host[:port])", "error");
    const host = to.replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "");
    setTarget(to);
    setRaw(`GET /${M}path${M} HTTP/1.1\nHost: ${host}\nUser-Agent: brainproxy\nAccept: */*\n\n`);
    setBinary(false);
    setMode("sniper");
    setSets([{ ...NEW_SET, wordlist: "content-discovery" }]);
    setOpts((o) => ({ ...o, matchStatus: "200,204,301,302,307,308,401,403,405,500", stopOnMatch: false }));
    app.toast("Content discovery set up: GET /§path§ with 5,384 paths. Review, then Start attack.");
  };

  const setSet = (i: number, patch: Partial<PayloadSet>) => setSets((ss) => ss.map((s, j) => (j === i ? { ...s, ...patch } : s)));
  const opt = <K extends keyof Options>(k: K, v: Options[K]) => setOpts((o) => ({ ...o, [k]: v }));
  const modeInfo = MODES.find((m) => m.id === mode)!;

  return (
    <div className="col fill">
      <div className="toolbar">
        <button className="btn primary" disabled={busy} onClick={start}>
          {busy ? "Starting…" : "Start attack"}
        </button>
        <span className="label">Target</span>
        <input className="input mono" style={{ width: 280 }} placeholder="https://example.com" value={target} onChange={(e) => setTarget(e.target.value)} />
        <span className="sep" />
        <button className="btn" onClick={addMark} title="Wrap the selection in § markers">
          Add §
        </button>
        <button className="btn" onClick={() => setRaw(raw.split(M).join(""))}>
          Clear §
        </button>
        <button className="btn" onClick={() => setRaw(autoMark(raw, binary))} title="Mark every query and body parameter value">
          Auto §
        </button>
        <span className="sep" />
        <button className="btn" onClick={discoverContent} title="Look for files and directories on the target (GET /§path§ with the built-in content-discovery list)">
          Discover content
        </button>
        <span className="grow" />
        <span className="muted">
          {positions} position{positions === 1 ? "" : "s"}
        </span>
      </div>
      <Split id="fuzzer-attack" dir="row" initial={0.58}>
        <div className="msg">
          <div className="msg-bar">
            <span className="msg-title">Request template</span>
            <span className="muted small">Payloads replace each §value§ (the value is kept where a position is not attacked)</span>
          </div>
          <div className="code-wrap">
            <pre className="code backdrop" ref={back} aria-hidden>
              {marked(raw)}
              {"\n"}
            </pre>
            <textarea
              ref={editor}
              className="code editor"
              spellCheck={false}
              value={raw}
              onChange={(e) => setRaw(withBody(e.target.value, raw))}
              onScroll={(e) => {
                if (back.current) back.current.scrollTop = e.currentTarget.scrollTop;
              }}
            />
          </div>
        </div>
        <div className="fz-config">
          <section>
            <div className="label">Attack type</div>
            <div className="seg">
              {MODES.map((m) => (
                <button key={m.id} className={mode === m.id ? "on" : ""} onClick={() => setMode(m.id)}>
                  {m.label}
                </button>
              ))}
            </div>
            <p className="muted small">{modeInfo.help}</p>
          </section>
          {sets.slice(0, needed).map((s, i) => (
            <section key={i}>
              <div className="row gap">
                <span className="label">Payload set {i + 1}</span>
                {needed > 1 && <span className="muted small">position {i + 1}</span>}
                <span className="grow" />
                <div className="seg">
                  {(["builtin", "list", "range", "file"] as Source[]).map((src) => (
                    <button key={src} className={s.source === src ? "on" : ""} onClick={() => setSet(i, { source: src })}>
                      {src === "builtin" ? "Built-in" : src === "list" ? "List" : src === "range" ? "Numbers" : "File"}
                    </button>
                  ))}
                </div>
              </div>
              {s.source === "builtin" && (
                <BuiltinPicker
                  lists={lists}
                  value={s.wordlist}
                  onChange={(wordlist) => setSet(i, { wordlist })}
                  onEdit={(text) => setSet(i, { source: "list", list: text })}
                />
              )}
              {s.source === "list" && (
                <>
                  <textarea className="code fz-list" spellCheck={false} placeholder="One payload per line" value={s.list} onChange={(e) => setSet(i, { list: e.target.value })} />
                  <div className="row gap">
                    <span className="muted small">{s.list.split("\n").filter(Boolean).length} payloads</span>
                    <span className="grow" />
                    <button className="btn small" onClick={() => navigator.clipboard.readText().then((t) => setSet(i, { list: (s.list ? s.list.replace(/\n?$/, "\n") : "") + t }))}>
                      Paste
                    </button>
                    <button className="btn small" onClick={() => setSet(i, { list: "" })}>
                      Clear
                    </button>
                  </div>
                </>
              )}
              {s.source === "range" && (
                <div className="row gap">
                  <span className="muted">From</span>
                  <input className="input mono fz-num" value={s.from} onChange={(e) => setSet(i, { from: e.target.value })} />
                  <span className="muted">to</span>
                  <input className="input mono fz-num" value={s.to} onChange={(e) => setSet(i, { to: e.target.value })} />
                  <span className="muted">step</span>
                  <input className="input mono fz-num" value={s.step} onChange={(e) => setSet(i, { step: e.target.value })} />
                </div>
              )}
              {s.source === "file" && (
                <input className="input mono" placeholder="/path/to/wordlist.txt (one payload per line)" value={s.file} onChange={(e) => setSet(i, { file: e.target.value })} />
              )}
              <div className="row gap">
                <span className="muted">Processing</span>
                <input
                  className="input mono grow"
                  placeholder="e.g. url  or  prefix:admin,base64"
                  title="Applied left to right: url, url-all, base64, base64url, hex, html, gzip, zlib, deflate, md5, sha1, sha256, sha512, upper, lower, prefix:TEXT, suffix:TEXT"
                  value={s.process}
                  onChange={(e) => setSet(i, { process: e.target.value })}
                />
              </div>
            </section>
          ))}
          <section>
            <div className="label">Match</div>
            <Field label="Grep">
              <textarea className="code fz-grep" spellCheck={false} placeholder="Regex per line; a hit marks the result" value={opts.grep} onChange={(e) => opt("grep", e.target.value)} />
            </Field>
            <Field label="Extract">
              <input className="input mono grow" placeholder="Regex; first group saved per result" value={opts.extract} onChange={(e) => opt("extract", e.target.value)} />
            </Field>
            <Field label="Statuses">
              <input className="input mono grow" placeholder="e.g. 200,302" value={opts.matchStatus} onChange={(e) => opt("matchStatus", e.target.value)} />
            </Field>
            <label className="check">
              <input type="checkbox" checked={opts.stopOnMatch} onChange={(e) => opt("stopOnMatch", e.target.checked)} /> Stop at the first match
            </label>
            <label className="check" title="Payloads placed in the URL or a form body get spaces, quotes, <>, # and non-ASCII percent-encoded; & = ' and existing %XX are kept">
              <input type="checkbox" checked={opts.encode} onChange={(e) => opt("encode", e.target.checked)} /> URL-encode payloads in the URL and form bodies
            </label>
          </section>
          <section>
            <div className="label">Engine</div>
            <div className="row gap fz-wrap">
              <Field label="Threads">
                <input className="input mono fz-num" value={opts.concurrency} onChange={(e) => opt("concurrency", e.target.value)} />
              </Field>
              <Field label="Req/s">
                <input className="input mono fz-num" placeholder="∞" value={opts.rate} onChange={(e) => opt("rate", e.target.value)} />
              </Field>
              <Field label="Max">
                <input className="input mono fz-num" placeholder="all" value={opts.maxRequests} onChange={(e) => opt("maxRequests", e.target.value)} />
              </Field>
              <Field label="Timeout s">
                <input className="input mono fz-num" value={opts.timeout} onChange={(e) => opt("timeout", e.target.value)} />
              </Field>
            </div>
            <div className="row gap fz-wrap">
              <Field label="History">
                <select className="input" value={opts.store} onChange={(e) => opt("store", e.target.value as Options["store"])}>
                  <option value="all">store all exchanges</option>
                  <option value="matches">store matches only</option>
                  <option value="none">store none</option>
                </select>
              </Field>
              <Field label="Auth profile">
                <input className="input mono fz-num" style={{ width: 110 }} placeholder="none" value={opts.auth} onChange={(e) => opt("auth", e.target.value)} />
              </Field>
              <label className="check">
                <input type="checkbox" checked={opts.http2} onChange={(e) => opt("http2", e.target.checked)} /> HTTP/2
              </label>
            </div>
          </section>
        </div>
      </Split>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="row gap fz-field">
      <span className="muted">{label}</span>
      {children}
    </div>
  );
}

/** The template with each §value§ position highlighted. */
function marked(text: string): ReactNode[] {
  const parts = text.split(M);
  return parts.map((p, i) =>
    i % 2 === 1 && i < parts.length - 1 ? (
      <span key={i} className="fz-pos">
        {M}
        {p}
        {M}
      </span>
    ) : (
      p
    ),
  );
}

// ---------------- Results ----------------

interface RunInfo {
  id: number;
  time: string;
  state: string;
  mode: string;
  target: string;
  positions: number;
  total: number;
  done: number;
  matched: number;
  errors: number;
  error: string | null;
}

interface Summary {
  run: RunInfo;
  baseline: { status: number | null; words: number; count: number; min_length: number; max_length: number } | null;
  distinct_shapes: number;
  outliers: { rule: string; items: { idx: number }[] };
  errors: { error: string; count: number }[];
}

interface Table {
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
}

interface Result {
  idx: number;
  position: number | null;
  payloads: string;
  status: number | null;
  length: number | null;
  words: number | null;
  lines: number | null;
  duration_ms: number | null;
  matched: boolean;
  grep: string;
  extract: string | null;
  error: string | null;
  history_id: number | null;
}

const LIVE = new Set(["queued", "running", "stopping"]);

/** `fuzz results` rows: payloads and grep are JSON text in the cells. */
function toResults(t: Table): Result[] {
  const col = Object.fromEntries(t.columns.map((c, i) => [c, i]));
  const list = (v: unknown) => {
    if (typeof v !== "string") return "";
    try {
      return (JSON.parse(v) as string[]).join(" | ");
    } catch {
      return v; // cut at the CLI's cell limit
    }
  };
  return t.rows.map((r) => ({
    idx: r[col.idx] as number,
    position: r[col.position] as number | null,
    payloads: list(r[col.payloads]),
    status: r[col.status] as number | null,
    length: r[col.length] as number | null,
    words: r[col.words] as number | null,
    lines: r[col.lines] as number | null,
    duration_ms: r[col.duration_ms] as number | null,
    matched: r[col.matched] === 1,
    grep: list(r[col.grep]),
    extract: r[col.extract] as string | null,
    error: r[col.error] as string | null,
    history_id: r[col.history_id] as number | null,
  }));
}

const statusClass = (s: number | null) => (s == null ? "s0" : s >= 500 ? "s5" : s >= 400 ? "s4" : s >= 300 ? "s3" : "s2");

const PAGE = 5000;

function RunResults({ id, active }: { id: number; active: boolean }) {
  const app = useApp();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [rows, setRows] = useState<Result[]>([]);
  const [final, setFinal] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [entry, setEntry] = useState<HistoryEntry | null>(null);
  const [filter, setFilter] = useState({ text: "", matched: false, outliers: false, hideErrors: false });
  const lastIdx = useRef(-1);
  const busy = useRef(false);
  const { menu, open, close } = useMenu();

  // While the run is live, fetch results after the last idx seen. Workers finish out of order,
  // so a row can land behind that cursor; once the run ends, everything is fetched once more.
  usePoll(
    async () => {
      if (busy.current) return;
      busy.current = true;
      try {
        const s = await run<Summary>(["fuzz", "status", String(id), "--top", "1000"]);
        setSummary(s);
        const done = !LIVE.has(s.run.state);
        let after = done ? -1 : lastIdx.current;
        const got: Result[] = [];
        for (;;) {
          const t = await run<Table>(["fuzz", "results", String(id), `--after=${after}`, "--limit", String(PAGE)]);
          const page = toResults(t);
          got.push(...page);
          if (!t.truncated || !page.length) break;
          after = page[page.length - 1].idx;
        }
        if (got.length) lastIdx.current = Math.max(lastIdx.current, got[got.length - 1].idx);
        if (done) {
          setRows(got);
          setFinal(true);
        } else if (got.length) {
          setRows((r) => {
            const seen = new Set(r.map((x) => x.idx));
            return [...r, ...got.filter((x) => !seen.has(x.idx))];
          });
        }
      } catch (e: any) {
        app.toast(e.message, "error");
        setFinal(true);
      } finally {
        busy.current = false;
      }
    },
    1000,
    active && !final,
  );

  const selectedRow = rows.find((r) => r.idx === selected);
  const historyId = selectedRow?.history_id ?? null;
  useEffect(() => {
    if (historyId == null) return setEntry(null);
    let live = true;
    run<HistoryEntry>(["history", "show", String(historyId), MAX_BODY])
      .then((e) => live && setEntry(e))
      .catch((e) => live && app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [historyId, app.toast]);

  const outliers = useMemo(() => new Set(summary?.outliers.items.map((o) => o.idx)), [summary]);
  const shown = useMemo(() => {
    const t = filter.text.toLowerCase();
    return rows.filter(
      (r) =>
        (!t || r.payloads.toLowerCase().includes(t) || (r.extract ?? "").toLowerCase().includes(t) || String(r.status) === t) &&
        (!filter.matched || r.matched) &&
        (!filter.outliers || outliers.has(r.idx)) &&
        (!filter.hideErrors || !r.error),
    );
  }, [rows, filter, outliers]);

  const stop = () => run(["fuzz", "stop", String(id)]).catch((e) => app.toast(e.message, "error"));

  const columns = useMemo<Column<Result>[]>(
    () => [
      { key: "idx", label: "#", width: 56, value: (r) => r.idx, align: "right" },
      ...(summary?.run.mode === "sniper" ? [{ key: "pos", label: "Pos", width: 44, value: (r: Result) => (r.position == null ? null : r.position + 1), align: "right" as const }] : []),
      { key: "payloads", label: "Payload", width: 240, value: (r) => r.payloads },
      {
        key: "status",
        label: "Status",
        width: 58,
        value: (r) => r.status,
        render: (r) => (r.error ? <span className="s5">error</span> : <span className={statusClass(r.status)}>{r.status ?? "—"}</span>),
        align: "right",
      },
      { key: "length", label: "Length", width: 70, value: (r) => r.length, align: "right" },
      { key: "words", label: "Words", width: 60, value: (r) => r.words, align: "right" },
      { key: "lines", label: "Lines", width: 56, value: (r) => r.lines, align: "right" },
      { key: "ms", label: "Time", width: 64, value: (r) => r.duration_ms, render: (r) => (r.duration_ms == null ? "" : `${r.duration_ms} ms`), align: "right" },
      {
        key: "flags",
        label: "Flags",
        width: 110,
        value: (r) => (r.matched ? 2 : 0) + (outliers.has(r.idx) ? 1 : 0),
        render: (r) => (
          <>
            {r.matched && <span className="tag fz-tag-match">match</span>}
            {outliers.has(r.idx) && <span className="tag fz-tag-outlier">outlier</span>}
          </>
        ),
      },
      { key: "grep", label: "Grep", width: 140, value: (r) => r.grep },
      { key: "extract", label: "Extract", width: 160, value: (r) => r.extract },
      { key: "error", label: "Error", width: 200, value: (r) => r.error, render: (r) => <span className="s5">{r.error}</span> },
    ],
    [summary?.run.mode, outliers],
  );

  const toRepeater = (h: HistoryEntry) => app.sendToRepeater({ raw: bodyText(h.request), binary: isBinary(h.request), target: originOf(h.url), title: `fuzz ${id}` });
  const withEntry = (r: Result, f: (h: HistoryEntry) => void) =>
    r.history_id == null
      ? app.toast("This result is not in history (see the run's History setting)", "error")
      : historyRequest(r.history_id).then(({ entry }) => f(entry), (e) => app.toast(e.message, "error"));

  const rowMenu = (r: Result, ev: React.MouseEvent) =>
    open(ev, [
      { label: "Send to Replay", action: () => withEntry(r, toRepeater), disabled: r.history_id == null },
      { label: "Send response to Diff", action: () => withEntry(r, (h) => app.sendToComparer(rawResponse(h))), disabled: r.history_id == null },
      { label: "Copy payload", action: () => navigator.clipboard.writeText(r.payloads) },
    ]);

  const s = summary?.run;
  const live = s ? LIVE.has(s.state) : true;
  const b = summary?.baseline;
  return (
    <div className="col fill">
      <div className="toolbar">
        <span className={`fz-state ${s?.state ?? ""}`}>{s?.state ?? "loading"}</span>
        <div className="fz-progress" title={s ? `${s.done} of ${s.total}` : ""}>
          <div style={{ width: `${s && s.total ? (100 * s.done) / s.total : 0}%` }} />
        </div>
        <span className="muted">
          {s ? `${s.done}/${s.total} · ${s.matched} matched · ${s.errors} errors` : ""}
        </span>
        <button className="btn" disabled={!s || !live || s.state === "stopping"} onClick={stop}>
          Stop
        </button>
        <span className="sep" />
        <input className="input" style={{ width: 180 }} placeholder="Filter: payload, extract, status" value={filter.text} onChange={(e) => setFilter({ ...filter, text: e.target.value })} />
        <label className="check">
          <input type="checkbox" checked={filter.matched} onChange={(e) => setFilter({ ...filter, matched: e.target.checked })} /> Matched
        </label>
        <label className="check">
          <input type="checkbox" checked={filter.outliers} onChange={(e) => setFilter({ ...filter, outliers: e.target.checked })} /> Outliers
        </label>
        <label className="check">
          <input type="checkbox" checked={filter.hideErrors} onChange={(e) => setFilter({ ...filter, hideErrors: e.target.checked })} /> Hide errors
        </label>
        <span className="grow" />
        <span className="muted small" title={summary?.outliers.rule}>
          {b ? `Baseline ${b.status ?? "—"} · ${b.words} words · ${b.count}× · ${summary!.distinct_shapes} shapes` : ""}
        </span>
      </div>
      {s?.error && <div className="error">{s.error}</div>}
      <Split id="fuzzer-results" dir="col" initial={0.5}>
        <DataTable
          rows={shown}
          columns={columns}
          rowKey={(r) => r.idx}
          selected={selected}
          onSelect={(r) => setSelected(r.idx)}
          onActivate={(r) => withEntry(r, toRepeater)}
          onContextMenu={rowMenu}
          rowClass={(r) => (r.matched ? "fz-match" : outliers.has(r.idx) ? "fz-outlier" : undefined)}
          initialSort={{ key: "idx", desc: false }}
          empty={live ? "Waiting for results…" : "No results."}
        />
        <Split id="fuzzer-msg" dir="row">
          <HttpView title="Request" value={entry ? bodyText(entry.request) : ""} binary={isBinary(entry?.request)} placeholder={selectedRow && selectedRow.history_id == null ? "Not stored in history" : "Select a result"} />
          <HttpView
            title="Response"
            value={entry ? rawResponse(entry) : ""}
            binary={isBinary(entry?.response?.body)}
            placeholder={selectedRow?.error ?? entry?.entry.error ?? ""}
            extra={entry?.duration_ms != null && <span className="muted">{entry.duration_ms} ms · history #{entry.id}</span>}
          />
        </Split>
      </Split>
      <Menu menu={menu} close={close} />
    </div>
  );
}

// ---------------- Runs ----------------

function Runs({ active, current, onOpen }: { active: boolean; current: number | null; onOpen: (id: number) => void }) {
  const [selected, setSelected] = useState<number | null>(current);
  const [list] = usePoll<Table>(() => run(["fuzz", "list", "--limit", "200"]), 2000, active);
  const rows = useMemo(() => {
    if (!list) return [];
    const col = Object.fromEntries(list.columns.map((c, i) => [c, i]));
    return list.rows.map((r) => Object.fromEntries(Object.keys(col).map((k) => [k, r[col[k]]])) as unknown as RunInfo);
  }, [list]);

  return (
    <div className="col fill">
      <div className="toolbar">
        <button className="btn primary" disabled={selected == null} onClick={() => selected != null && onOpen(selected)}>
          Open results
        </button>
        <span className="muted">Double-click a run to open its results</span>
      </div>
      <DataTable
        rows={rows}
        columns={[
          { key: "id", label: "Run", width: 56, value: (r: RunInfo) => r.id, align: "right" },
          { key: "time", label: "Started", width: 170, value: (r: RunInfo) => r.time.replace("T", " ").replace(/\.\d+Z$/, "") },
          { key: "state", label: "State", width: 90, value: (r: RunInfo) => r.state, render: (r: RunInfo) => <span className={`fz-state ${r.state}`}>{r.state}</span> },
          { key: "mode", label: "Mode", width: 100, value: (r: RunInfo) => r.mode },
          { key: "target", label: "Target", width: 240, value: (r: RunInfo) => r.target },
          { key: "progress", label: "Done", width: 100, value: (r: RunInfo) => r.done, render: (r: RunInfo) => `${r.done}/${r.total}`, align: "right" },
          { key: "matched", label: "Matched", width: 70, value: (r: RunInfo) => r.matched, align: "right" },
          { key: "errors", label: "Errors", width: 64, value: (r: RunInfo) => r.errors, align: "right" },
        ]}
        rowKey={(r) => r.id}
        selected={selected}
        onSelect={(r) => setSelected(r.id)}
        onActivate={(r) => onOpen(r.id)}
        initialSort={{ key: "id", desc: true }}
        empty="No fuzz runs yet."
      />
    </div>
  );
}

/** Built-in list picker: name and size, with the description, caution, and source of the chosen one. */
function BuiltinPicker(p: { lists: Wordlist[]; value: string; onChange: (name: string) => void; onEdit: (text: string) => void }) {
  const app = useApp();
  const w = p.lists.find((l) => l.name === p.value);
  const edit = () =>
    run<{ entries: string[] }>(["wordlists", "show", p.value])
      .then((d) => p.onEdit(d.entries.join("\n")))
      .catch((e) => app.toast(e.message, "error"));
  return (
    <div className="fz-builtin">
      <div className="row gap">
        <select className="input grow" value={p.value} onChange={(e) => p.onChange(e.target.value)}>
          {p.lists.map((l) => (
            <option key={l.name} value={l.name}>
              {l.name} ({l.count.toLocaleString()})
            </option>
          ))}
        </select>
        <button className="btn small" onClick={edit} title="Copy the list into an editable list">
          Edit as list
        </button>
      </div>
      {w && (
        <>
          <p className="muted small">{w.description}</p>
          {w.caution && <p className="fz-caution small">⚠ {w.caution}</p>}
          <p className="muted small">
            From{" "}
            {w.sources
              .map((s) => `${s.repo.replace("https://github.com/", "")} (${s.license})`)
              .filter((v, i, a) => a.indexOf(v) === i)
              .join(", ")}
          </p>
        </>
      )}
    </div>
  );
}
