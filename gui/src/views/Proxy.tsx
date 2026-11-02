import { useEffect, useMemo, useRef, useState } from "react";
import { bodyText, historyRequest, hostOf, isBinary, MAX_BODY, pathOf, rawResponse, run, textBytes, type Body, type HistoryEntry, type HistoryItem } from "../api";
import { originOf, useApp, type Handoff } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Menu, useMenu } from "../ui/Menu";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { WebSockets } from "./WebSockets";

export function ProxyView() {
  const [sub, setSub] = useState<"history" | "intercept" | "ws">("history");
  return (
    <div className="col fill">
      <div className="subtabs">
        <button className={sub === "intercept" ? "on" : ""} onClick={() => setSub("intercept")}>
          Intercept
        </button>
        <button className={sub === "history" ? "on" : ""} onClick={() => setSub("history")}>
          Traffic
        </button>
        <button className={sub === "ws" ? "on" : ""} onClick={() => setSub("ws")}>
          WebSockets
        </button>
      </div>
      <div className="fill" hidden={sub !== "history"}>
        <History />
      </div>
      <div className="fill" hidden={sub !== "intercept"}>
        <Intercept active={sub === "intercept"} />
      </div>
      <div className="fill" hidden={sub !== "ws"}>
        <WebSockets active={sub === "ws"} />
      </div>
    </div>
  );
}

// ---------------- HTTP history ----------------

const statusClass = (s: number | null) => (s == null ? "s0" : s >= 500 ? "s5" : s >= 400 ? "s4" : s >= 300 ? "s3" : "s2");

const COLUMNS: Column<HistoryItem>[] = [
  { key: "id", label: "#", width: 56, value: (r) => r.id, align: "right" },
  { key: "host", label: "Host", width: 170, value: (r) => hostOf(r.url) },
  { key: "method", label: "Method", width: 64, value: (r) => r.method, render: (r) => <span className="method">{r.method}</span> },
  { key: "path", label: "URL", width: 340, value: (r) => pathOf(r.url) },
  {
    key: "status",
    label: "Status",
    width: 58,
    value: (r) => r.status,
    render: (r) => (r.error ? <span className="s5" title={r.error}>error</span> : <span className={statusClass(r.status)}>{r.status ?? "—"}</span>),
    align: "right",
  },
  { key: "length", label: "Length", width: 70, value: (r) => r.resp_body_length, align: "right" },
  { key: "mime", label: "MIME", width: 110, value: (r) => (r.resp_content_type ?? "").split(";")[0] },
  { key: "title", label: "Title", width: 180, value: (r) => r.title },
  { key: "source", label: "Source", width: 70, value: (r) => r.source },
  { key: "ms", label: "Time", width: 60, value: (r) => r.duration_ms, render: (r) => (r.duration_ms == null ? "" : `${r.duration_ms} ms`), align: "right" },
  {
    key: "notes",
    label: "Notes",
    width: 160,
    value: (r) => [r.note, ...r.tags].filter(Boolean).join(" "),
    render: (r) => (
      <>
        {r.tags.map((t) => (
          <span key={t} className="tag">
            {t}
          </span>
        ))}
        {r.note && <span className="note">{r.note}</span>}
      </>
    ),
  },
];

const SOURCES = ["proxy", "send", "crawl", "crawl-browser", "fuzz", "scan", "import", "auth", "race", "ws"];

function History() {
  const app = useApp();
  const [rows, setRows] = useState<HistoryItem[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [entry, setEntry] = useState<HistoryEntry | null>(null);
  // Refused requests (outside the engagement scope) are mostly browser background noise.
  const [filter, setFilter] = useState({ text: "", sources: new Set<string>(), hideErrors: false, hideAssets: false, hideRefused: true });
  const lastId = useRef(0);
  const { menu, open, close } = useMenu();

  // Fetch only new rows each tick (ids only grow).
  usePoll(async () => {
    for (;;) {
      const d = await run<{ items: HistoryItem[] }>(["history", "list", "--after", String(lastId.current), "--limit", "2000"]);
      if (!d.items.length) return;
      lastId.current = d.items[d.items.length - 1].id;
      // Overlapping polls can fetch the same rows; keep each id once.
      setRows((r) => {
        const max = r.length ? r[r.length - 1].id : 0;
        return [...r, ...d.items.filter((i) => i.id > max)];
      });
      if (d.items.length < 2000) return;
    }
  }, 1500);

  useEffect(() => {
    if (selected == null) return setEntry(null);
    let live = true;
    run<HistoryEntry>(["history", "show", String(selected), "--max-body", "2000000"])
      .then((e) => live && setEntry(e))
      .catch((e) => live && app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [selected, app.toast]);

  const refused = useMemo(() => rows.filter((r) => r.error?.startsWith("out of scope")).length, [rows]);
  const shown = useMemo(() => {
    const t = filter.text.toLowerCase();
    return rows.filter(
      (r) =>
        (!t || r.url.toLowerCase().includes(t) || (r.title ?? "").toLowerCase().includes(t) || r.method.toLowerCase() === t) &&
        (filter.sources.size === 0 || filter.sources.has(r.source)) &&
        (!filter.hideErrors || (r.status != null && r.status < 400)) &&
        (!filter.hideAssets || !/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\?|$)/i.test(r.url)) &&
        (!filter.hideRefused || !r.error?.startsWith("out of scope")),
    );
  }, [rows, filter]);

  const handoff = (id: number, f: (h: Handoff & { entry: HistoryEntry }) => void) =>
    historyRequest(id).then(
      (h) => f({ raw: h.raw, binary: h.binary, target: originOf(h.entry.url), entry: h.entry }),
      (e) => app.toast(e.message, "error"),
    );

  const rowMenu = (r: HistoryItem, ev: React.MouseEvent) =>
    open(ev, [
      { label: "Send to Replay", action: () => handoff(r.id, (h) => app.sendToRepeater({ ...h, title: pathOf(r.url).slice(0, 24) })) },
      { label: "Send to Fuzzer", action: () => handoff(r.id, app.sendToFuzzer) },
      { label: "Send request to Diff", action: () => handoff(r.id, (h) => app.sendToComparer(h.raw)) },
      { label: "Send response to Diff", action: () => handoff(r.id, (h) => app.sendToComparer(rawResponse(h.entry))) },
      "-",
      { label: "Copy URL", action: () => navigator.clipboard.writeText(r.url) },
      {
        label: "Add note…",
        action: () => {
          const text = window.prompt("Note for #" + r.id, r.note ?? "");
          if (text == null) return;
          run(["history", "note", String(r.id), ...(text ? ["--", text] : [])])
            .then(() => setRows((rs) => rs.map((x) => (x.id === r.id ? { ...x, note: text || null } : x))))
            .catch((e) => app.toast(e.message, "error"));
        },
      },
      {
        label: "Highlight",
        action: () =>
          run(["history", "tag", String(r.id), "--add", "highlight"])
            .then(() => setRows((rs) => rs.map((x) => (x.id === r.id ? { ...x, tags: [...new Set([...x.tags, "highlight"])] } : x))))
            .catch((e) => app.toast(e.message, "error")),
      },
    ]);

  const toggleSource = (s: string) =>
    setFilter((f) => {
      const sources = new Set(f.sources);
      sources.has(s) ? sources.delete(s) : sources.add(s);
      return { ...f, sources };
    });

  return (
    <div className="col fill">
      <div className="toolbar">
        <input className="input" style={{ width: 260 }} placeholder="Filter: URL, title, or method" value={filter.text} onChange={(e) => setFilter({ ...filter, text: e.target.value })} />
        <div className="seg">
          {SOURCES.map((s) => (
            <button key={s} className={filter.sources.has(s) ? "on" : ""} onClick={() => toggleSource(s)}>
              {s}
            </button>
          ))}
        </div>
        <label className="check">
          <input type="checkbox" checked={filter.hideErrors} onChange={(e) => setFilter({ ...filter, hideErrors: e.target.checked })} /> 2xx/3xx only
        </label>
        <label className="check">
          <input type="checkbox" checked={filter.hideAssets} onChange={(e) => setFilter({ ...filter, hideAssets: e.target.checked })} /> Hide static assets
        </label>
        <label className="check" title="Requests the proxy refused because their host is outside the engagement scope (often browser background traffic)">
          <input type="checkbox" checked={filter.hideRefused} onChange={(e) => setFilter({ ...filter, hideRefused: e.target.checked })} /> Hide out-of-scope
          {filter.hideRefused && refused > 0 && <span className="muted"> ({refused})</span>}
        </label>
        <span className="grow" />
        <span className="muted">
          {shown.length === rows.length ? `${rows.length} items` : `${shown.length} of ${rows.length} items`}
        </span>
      </div>
      <Split id="history" dir="col" initial={0.5}>
        <DataTable
          rows={shown}
          columns={COLUMNS}
          rowKey={(r) => r.id}
          selected={selected}
          onSelect={(r) => setSelected(r.id)}
          onActivate={(r) => handoff(r.id, (h) => app.sendToRepeater({ ...h, title: pathOf(r.url).slice(0, 24) }))}
          onContextMenu={rowMenu}
          rowClass={(r) => (r.tags.includes("highlight") ? "hl" : undefined)}
          initialSort={{ key: "id", desc: true }}
          empty="No traffic yet. Start the proxy and point a browser at it, or use Replay."
        />
        <Split id="history-msg" dir="row">
          <HttpView title="Request" value={entry ? bodyText(entry.request) : ""} binary={isBinary(entry?.request)} placeholder="Select a request" />
          <HttpView
            title="Response"
            value={entry ? rawResponse(entry) : ""}
            binary={isBinary(entry?.response?.body)}
            placeholder={entry?.entry.error ?? ""}
            extra={entry?.duration_ms != null && <span className="muted">{entry.duration_ms} ms</span>}
          />
        </Split>
      </Split>
      <Menu menu={menu} close={close} />
    </div>
  );
}

// ---------------- Intercept ----------------

interface Held {
  id: number;
  time: string;
  direction: "request" | "response" | "ws-to-server" | "ws-to-client";
  state: string;
  method: string;
  url: string;
  status: number | null;
  length: number;
}

export interface InterceptSettings {
  enabled: boolean;
  requests: boolean;
  responses: boolean;
  ws_to_server?: boolean;
  ws_to_client?: boolean;
  host?: string;
  path?: string;
  method?: string;
  timeout_secs: number;
  timeout_action: string;
}

/** `intercept enable` arguments for these settings. Enable replaces every setting, so the
 * filters are passed back each time or they would be cleared. */
export function interceptEnableArgs(s: InterceptSettings): string[] {
  const opt = (flag: string, v?: string) => (v ? [`${flag}=${v}`] : []);
  return [
    "intercept",
    "enable",
    ...(s.requests ? ["--requests"] : []),
    ...(s.responses ? ["--responses"] : []),
    ...(s.ws_to_server ? ["--ws-to-server"] : []),
    ...(s.ws_to_client ? ["--ws-to-client"] : []),
    ...opt("--host", s.host),
    ...opt("--path", s.path),
    ...opt("--method", s.method),
    "--timeout",
    String(s.timeout_secs),
    "--timeout-action",
    s.timeout_action,
  ];
}

const HELD_TITLE: Record<Held["direction"], string> = {
  request: "Request to",
  response: "Response from",
  "ws-to-server": "WebSocket message to",
  "ws-to-client": "WebSocket message from",
};

function Intercept({ active }: { active: boolean }) {
  const app = useApp();
  const [settings, refreshSettings] = usePoll<{ settings: InterceptSettings; pending: number }>(() => run(["intercept", "status"]), 2000, active);
  const [held, refreshHeld] = usePoll<{ items: Held[] }>(() => run(["intercept", "list"]), 1000, active);
  const [current, setCurrent] = useState<number | null>(null);
  // binary: the text holds one char per byte; truncated: only the first 2 MB arrived, so it can't be edited.
  const [message, setMessage] = useState<{ original: string; text: string; binary: boolean; truncated: boolean } | null>(null);
  const items = held?.items ?? [];

  // Follow the oldest held message unless the user picked one that is still held.
  useEffect(() => {
    if (current != null && items.some((i) => i.id === current)) return;
    setCurrent(items[0]?.id ?? null);
  }, [items, current]);

  useEffect(() => {
    if (current == null) return setMessage(null);
    run<{ message: Body }>(["intercept", "show", String(current), MAX_BODY])
      .then((d) => {
        const text = bodyText(d.message);
        setMessage({ original: text, text, binary: isBinary(d.message), truncated: !!d.message.truncated });
      })
      .catch(() => setMessage(null));
  }, [current]);

  const s = settings?.settings;
  const toggle = async (patch: Partial<InterceptSettings>) => {
    const next = { ...s!, ...patch };
    try {
      if (!next.enabled) await run(["intercept", "disable"]);
      else await run(interceptEnableArgs(next));
      refreshSettings();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const decide = async (how: "forward" | "drop") => {
    if (current == null || !message) return;
    try {
      if (how === "drop") await run(["intercept", "drop", String(current)]);
      else if (message.text !== message.original) await run(["intercept", "forward", String(current), "--file=-"], textBytes(message.text, message.binary));
      else await run(["intercept", "forward", String(current)]);
      setCurrent(null);
      refreshHeld();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const item = items.find((i) => i.id === current);
  return (
    <div className="col fill">
      <div className="toolbar">
        <button
          className={`btn ${s?.enabled ? "primary" : ""}`}
          onClick={() => s && toggle({ enabled: !s.enabled, requests: s.enabled ? s.requests : s.requests || !(s.responses || s.ws_to_server || s.ws_to_client) })}
        >
          Intercept is {s?.enabled ? "on" : "off"}
        </button>
        <label className="check">
          <input type="checkbox" checked={!!s?.requests} disabled={!s?.enabled} onChange={(e) => toggle({ requests: e.target.checked })} /> Requests
        </label>
        <label className="check">
          <input type="checkbox" checked={!!s?.responses} disabled={!s?.enabled} onChange={(e) => toggle({ responses: e.target.checked })} /> Responses
        </label>
        <label className="check" title="WebSocket messages from the browser (text and binary)">
          <input type="checkbox" checked={!!s?.ws_to_server} disabled={!s?.enabled} onChange={(e) => toggle({ ws_to_server: e.target.checked })} /> WS to server
        </label>
        <label className="check" title="WebSocket messages from the server (text and binary)">
          <input type="checkbox" checked={!!s?.ws_to_client} disabled={!s?.enabled} onChange={(e) => toggle({ ws_to_client: e.target.checked })} /> WS to client
        </label>
        <span className="sep" />
        <button className="btn primary" disabled={!message} onClick={() => decide("forward")}>
          Forward{message && message.text !== message.original ? " edited" : ""}
        </button>
        <button className="btn" disabled={!message} onClick={() => decide("drop")}>
          Drop
        </button>
        <button
          className="btn"
          disabled={!message || message.truncated || item?.direction !== "request"}
          onClick={() => item && message && app.sendToRepeater({ raw: message.text, binary: message.binary, target: originOf(item.url) })}
        >
          Send to Replay
        </button>
        {message?.truncated && (
          <span className="tag" title="Only the first 2 MB is shown. Forward or drop it as is, or use the CLI to edit it.">
            Over 2 MB: read-only
          </span>
        )}
        <span className="grow" />
        <span className="muted">{s ? `Unanswered messages are ${s.timeout_action === "drop" ? "dropped" : "forwarded"} after ${s.timeout_secs} s` : ""}</span>
      </div>
      <Split id="intercept" dir="col" initial={0.28}>
        <DataTable
          rows={items}
          columns={[
            { key: "id", label: "#", width: 50, value: (r: Held) => r.id, align: "right" },
            { key: "dir", label: "Direction", width: 80, value: (r: Held) => r.direction },
            { key: "method", label: "Method", width: 64, value: (r: Held) => r.method },
            { key: "url", label: "URL", width: 420, value: (r: Held) => r.url },
            { key: "status", label: "Status", width: 60, value: (r: Held) => r.status, align: "right" },
            { key: "len", label: "Length", width: 70, value: (r: Held) => r.length, align: "right" },
          ]}
          rowKey={(r) => r.id}
          selected={current}
          onSelect={(r) => setCurrent(r.id)}
          initialSort={{ key: "id", desc: false }}
          empty={s?.enabled ? "Waiting for traffic through the proxy…" : "Intercept is off. Turn it on to hold requests before they are sent."}
        />
        <HttpView
          title={item ? `${HELD_TITLE[item.direction]} ${hostOf(item.url.replace(/^ws/, "http"))}` : "Message"}
          value={message?.text ?? ""}
          binary={message?.binary}
          onChange={message && !message.truncated ? (text) => setMessage({ ...message, text }) : undefined}
          placeholder="Nothing held"
        />
      </Split>
    </div>
  );
}
