// Proxy → WebSockets: connections the proxy relayed (or Replay opened) and their messages;
// and Replay's WebSocket mode (`ws send`).

import { useEffect, useRef, useState } from "react";
import { bodyText, cancelCli, historyRequest, hostOf, isBinary, pathOf, requireWhole, run, type Body } from "../api";
import { useApp, type RepeaterTab } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Menu, useMenu } from "../ui/Menu";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { beginCall, endCall, replayCalls, stopCall, tabSlot, useTabSlot } from "./replayCalls";
import { optionsProblem } from "./replayOptions";
import { OptionsRow, OptionsToggle, useSendOptions } from "./SendOptions";
import { arrow, joinMessages, splitMessages, wsOrigin, wsSendArgs, wsSendInput, type WsConnection, type WsMessage, type WsSendResult } from "./ws";

const PREVIEW = 300;

/** One message with its whole payload; throws when it is over 2 MB (cut short). */
async function wholeMessage(connection: number, id: number): Promise<WsMessage> {
  const d = await run<{ items: WsMessage[] }>(["ws", "messages", String(connection), "--after", String(id - 1), "--limit", "1", "--max-body", "2000000"]);
  const m = d.items[0];
  if (!m || m.id !== id) throw new Error(`Message #${id} not found`);
  requireWhole(m.payload, `Message #${id}`);
  return m;
}

const preview = (b: Body) => {
  const t = isBinary(b) ? `(binary, ${b.length ?? "?"} bytes)` : bodyText(b);
  return t.length > PREVIEW ? t.slice(0, PREVIEW) + "…" : t;
};

const CONN_COLUMNS: Column<WsConnection>[] = [
  { key: "id", label: "#", width: 50, value: (r) => r.id, align: "right" },
  { key: "host", label: "Host", width: 170, value: (r) => hostOf(r.url.replace(/^ws/, "http")) },
  { key: "path", label: "URL", width: 300, value: (r) => pathOf(r.url.replace(/^ws/, "http")) },
  { key: "state", label: "State", width: 70, value: (r) => r.state, render: (r) => <span className={r.state === "open" ? "s2" : "muted"}>{r.state}</span> },
  { key: "messages", label: "Messages", width: 80, value: (r) => r.messages, align: "right" },
  { key: "close", label: "Close", width: 70, value: (r) => r.close_code, align: "right" },
  { key: "source", label: "Source", width: 70, value: (r) => r.source },
  { key: "time", label: "Opened", width: 170, value: (r) => r.time },
  { key: "error", label: "Note", width: 200, value: (r) => r.error ?? r.close_reason },
];

const MSG_COLUMNS: Column<WsMessage>[] = [
  { key: "id", label: "#", width: 56, value: (r) => r.id, align: "right" },
  { key: "dir", label: "", width: 28, value: (r) => r.direction, render: (r) => <span title={r.direction}>{arrow(r.direction)}</span> },
  { key: "opcode", label: "Type", width: 60, value: (r) => r.opcode },
  { key: "length", label: "Length", width: 70, value: (r) => r.length ?? null, align: "right" },
  { key: "payload", label: "Payload", width: 460, value: (r) => preview(r.payload) },
  { key: "intercept", label: "Intercept", width: 80, value: (r) => r.intercept ?? null },
  { key: "time", label: "Time", width: 170, value: (r) => r.time ?? null },
];

/** A Replay handoff for a connection: its handshake and the given messages. */
async function replayHandoff(c: WsConnection, messages: string[]): Promise<Omit<RepeaterTab, "key">> {
  if (c.history_id == null) throw new Error(`Connection #${c.id} has no recorded handshake`);
  const h = await historyRequest(c.history_id);
  return { raw: h.raw, target: wsOrigin(c.url), ws: messages, title: `WS ${pathOf(c.url.replace(/^ws/, "http")).slice(0, 20)}` };
}

export function WebSockets({ active }: { active: boolean }) {
  const app = useApp();
  const [conns] = usePoll<{ items: WsConnection[] }>(() => run(["ws", "list", "--newest", "--limit", "5000"]), 2000, active);
  const [selected, setSelected] = useState<number | null>(null);
  const [messages, setMessages] = useState<WsMessage[]>([]);
  const [current, setCurrent] = useState<number | null>(null);
  const [full, setFull] = useState<WsMessage | null>(null);
  const lastId = useRef(0);
  // The selection a poll's answer is for may have changed while it was on its way.
  const selectedRef = useRef<number | null>(null);
  selectedRef.current = selected;
  const { menu, open, close } = useMenu();
  const conn = conns?.items.find((c) => c.id === selected) ?? null;

  useEffect(() => {
    setMessages([]);
    setCurrent(null);
    lastId.current = 0;
  }, [selected]);

  // New messages of the selected connection (ids only grow).
  usePoll(
    async () => {
      const conn = selectedRef.current;
      if (conn == null) return;
      const d = await run<{ items: WsMessage[] }>(["ws", "messages", String(conn), "--after", String(lastId.current), "--limit", "2000", "--max-body", String(PREVIEW + 1)]);
      if (conn !== selectedRef.current || !d.items.length) return;
      lastId.current = d.items[d.items.length - 1].id!;
      setMessages((m) => {
        const max = m.length ? m[m.length - 1].id! : 0;
        return [...m, ...d.items.filter((i) => i.id! > max)];
      });
    },
    1000,
    active && selected != null,
  );

  useEffect(() => {
    if (current == null || selected == null) return setFull(null);
    let live = true;
    run<{ items: WsMessage[] }>(["ws", "messages", String(selected), "--after", String(current - 1), "--limit", "1", "--max-body", "2000000"])
      .then((d) => live && setFull(d.items[0] ?? null))
      .catch((e) => live && app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [current, selected, app.toast]);

  const toReplay = (c: WsConnection, msgs: string[]) =>
    replayHandoff(c, msgs).then(app.sendToRepeater, (e) => app.toast(e.message, "error"));

  const connMenu = (c: WsConnection, ev: React.MouseEvent) =>
    open(ev, [
      {
        label: "Send to Replay",
        action: () =>
          run<{ items: WsMessage[] }>(["ws", "messages", String(c.id), "--direction", "to-server", "--opcode", "text", "--limit", "20", "--max-body", "2000000"])
            .then((d) => {
              d.items.forEach((m) => requireWhole(m.payload, `Message #${m.id}`));
              return toReplay(c, d.items.map((m) => bodyText(m.payload)));
            })
            .catch((e) => app.toast(e.message, "error")),
      },
      { label: "Copy URL", action: () => navigator.clipboard.writeText(c.url) },
    ]);

  const msgMenu = (m: WsMessage, ev: React.MouseEvent) =>
    open(ev, [
      // Replay sends text messages; binary ones go with `ws send --resend ID`.
      ...(m.opcode === "text"
        ? [
            {
              label: "Send to Replay",
              action: () =>
                conn &&
                wholeMessage(conn.id, m.id!)
                  .then((x) => toReplay(conn, [bodyText(x.payload)]))
                  .catch((e) => app.toast(e.message, "error")),
            },
          ]
        : []),
      {
        label: "Copy payload",
        action: () =>
          conn &&
          wholeMessage(conn.id, m.id!)
            .then((x) => navigator.clipboard.writeText(bodyText(x.payload)))
            .catch((e) => app.toast(e.message, "error")),
      },
    ]);

  const items = conns?.items ?? [];
  return (
    <div className="col fill">
      <div className="toolbar">
        <span className="muted">
          {items.length} connection{items.length === 1 ? "" : "s"}
          {conn ? ` · #${conn.id} ${conn.url}${conn.extensions ? ` · ${conn.extensions}` : ""}` : ""}
        </span>
        <span className="grow" />
        <span className="muted">Hold messages with Intercept (WebSocket boxes).</span>
      </div>
      <Split id="ws" dir="col" initial={0.3}>
        <DataTable
          rows={items}
          columns={CONN_COLUMNS}
          rowKey={(r) => r.id}
          selected={selected}
          onSelect={(r) => setSelected(r.id)}
          onContextMenu={connMenu}
          initialSort={{ key: "id", desc: true }}
          empty="No WebSocket connections yet. They appear here when a browser using the proxy opens one."
        />
        <Split id="ws-msg" dir="row" initial={0.6}>
          <DataTable
            rows={messages}
            columns={MSG_COLUMNS}
            rowKey={(r) => r.id!}
            selected={current}
            onSelect={(r) => setCurrent(r.id)}
            onContextMenu={msgMenu}
            initialSort={{ key: "id", desc: false }}
            empty={selected == null ? "Select a connection" : "No messages"}
          />
          <HttpView
            title={full ? `${arrow(full.direction)} ${full.opcode} #${full.id}${full.compressed ? " (compressed)" : ""}` : "Message"}
            value={full ? bodyText(full.payload) : ""}
            binary={isBinary(full?.payload)}
            placeholder="Select a message"
          />
        </Split>
      </Split>
      <Menu menu={menu} close={close} />
    </div>
  );
}

// ---------------- Replay: WebSocket mode ----------------

// Results survive switching tabs (the tab view remounts), keyed by tab; so does a run in
// flight, so its result lands in its tab and Stop stays (replayCalls.ts).
const resultsByTab = tabSlot<WsSendResult | string | null>(null);

export function WsReplayTab({ tab }: { tab: RepeaterTab }) {
  const app = useApp();
  const [raw, setRaw] = useState(tab.raw);
  const [target, setTarget] = useState(tab.target);
  const [text, setText] = useState(joinMessages(tab.ws ?? []));
  const [wait, setWait] = useState(3);
  const [until, setUntil] = useState("");
  const [result] = useTabSlot(resultsByTab, tab.key);
  const [current, setCurrent] = useState<number | null>(null);
  const [options, setOptions] = useSendOptions(tab);
  const [showOptions, setShowOptions] = useState(false);
  // The run in flight, so Stop can cancel it.
  const [call] = useTabSlot(replayCalls, tab.key);
  const busy = call != null;

  // A new result's rows aren't the old one's.
  useEffect(() => setCurrent(null), [result]);

  const { setRepeater } = app;
  useEffect(() => {
    const t = setTimeout(
      () =>
        setRepeater((ts) => {
          const cur = ts.find((x) => x.key === tab.key);
          const ws = splitMessages(text);
          if (!cur || (cur.raw === raw && cur.target === target && joinMessages(cur.ws ?? []) === joinMessages(ws))) return ts;
          return ts.map((x) => (x.key === tab.key ? { ...x, raw, target, ws } : x));
        }),
      300,
    );
    return () => clearTimeout(t);
  }, [raw, target, text, tab.key, setRepeater]);

  const send = async () => {
    const host = /^host:\s*(\S+)/im.exec(raw)?.[1];
    const to = target || (host ? `${/:443$/.test(host) ? "https" : "http"}://${host.replace(/:443$/, "")}` : "");
    if (!to) return app.toast("Set a target (ws://, wss://, http:// or https://host[:port]) or a Host header", "error");
    const problem = optionsProblem(options);
    if (problem) return app.toast(problem, "error");
    setTarget(to);
    const key = tab.key;
    const id = beginCall(key, "replay-ws-send");
    let r: WsSendResult | string;
    try {
      r = await run<WsSendResult>(wsSendArgs({ target: to, wait, until: until || undefined, options }), { stdin: wsSendInput(raw, splitMessages(text)), call: id });
    } catch (e: any) {
      r = e.kind === "cancelled" ? "Stopped" : (e.message as string);
    }
    // Into the tab even if the view was remounted meanwhile; not if the tab closed.
    if (endCall(key, id)) resultsByTab.update(key, () => r);
  };

  const msgs = typeof result === "object" && result ? result.messages ?? [] : [];
  const rows = msgs.map((m, i) => ({ ...m, idx: i }));
  const shown = current == null ? null : msgs[current];
  const status =
    typeof result === "string"
      ? result
      : result && !result.upgraded
        ? `Not upgraded: ${result.response?.status ?? "?"} ${result.response?.reason ?? ""}`
        : result
          ? `${result.received} received · stopped: ${result.stopped}${result.close?.code ? ` · closed ${result.close.code}` : ""}${result.connection_id ? ` · connection #${result.connection_id}` : ""}${result.error ? ` · ${result.error}` : ""}`
          : "";

  return (
    <div className="col fill">
      <div className="toolbar">
        <button className="btn primary" disabled={busy} onClick={send}>
          {busy ? "Connected…" : "Connect and send"}
        </button>
        {busy && (
          <button className="btn" onClick={() => stopCall(tab.key, cancelCli)} title="Stop the connection">
            Stop
          </button>
        )}
        <span className="label">Target</span>
        <input className="input mono" style={{ width: 240 }} placeholder="wss://example.com" value={target} onChange={(e) => setTarget(e.target.value)} />
        <span className="label" title="Seconds to keep listening after the last message">
          Listen
        </span>
        <input className="input" type="number" min={0} step={0.5} style={{ width: 64 }} value={wait} onChange={(e) => setWait(Math.max(0, Number(e.target.value)))} />
        <span className="label" title="Stop as soon as a received message matches this regex">
          Until
        </span>
        <input className="input mono" style={{ width: 160 }} placeholder="regex (optional)" value={until} onChange={(e) => setUntil(e.target.value)} />
        <OptionsToggle options={options} kind="ws" open={showOptions} onToggle={() => setShowOptions(!showOptions)} />
        <span className="grow" />
        <span className="muted">{status}</span>
      </div>
      {showOptions && <OptionsRow options={options} set={setOptions} kind="ws" />}
      <Split id="ws-replay" dir="row">
        <Split id="ws-replay-in" dir="col" initial={0.5}>
          <HttpView title="Handshake" value={raw} onChange={setRaw} />
          <div className="col fill">
            <div className="toolbar">
              <span className="label">Messages to send (text), separated by a line with ---</span>
            </div>
            <textarea className="input mono fill" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} placeholder={'{"type":"subscribe"}\n---\n{"type":"ping"}'} />
          </div>
        </Split>
        <Split id="ws-replay-out" dir="col" initial={0.5}>
          <DataTable
            rows={rows}
            columns={[
              { key: "idx", label: "#", width: 40, value: (r) => r.idx + 1, align: "right" },
              { key: "dir", label: "", width: 28, value: (r) => r.direction, render: (r) => <span title={r.direction}>{arrow(r.direction)}</span> },
              { key: "opcode", label: "Type", width: 60, value: (r) => r.opcode },
              { key: "ms", label: "At", width: 70, value: (r) => r.elapsed_ms ?? null, render: (r) => `${r.elapsed_ms ?? 0} ms`, align: "right" },
              { key: "payload", label: "Payload", width: 380, value: (r) => preview(r.payload) },
            ]}
            rowKey={(r) => r.idx}
            selected={current}
            onSelect={(r) => setCurrent(r.idx)}
            initialSort={{ key: "idx", desc: false }}
            empty={busy ? "Waiting for replies…" : "Connect to see the conversation"}
          />
          <HttpView
            title={shown ? `${arrow(shown.direction)} ${shown.opcode}` : typeof result === "object" && result && !result.upgraded ? "Response" : "Message"}
            value={shown ? bodyText(shown.payload) : typeof result === "object" && result && !result.upgraded && result.response ? bodyText(result.response.body) : ""}
            binary={isBinary(shown?.payload)}
            placeholder="Select a message"
          />
        </Split>
      </Split>
    </div>
  );
}
