import { useEffect, useState } from "react";
import { bodyText, isBinary, MAX_BODY, run, textBytes, withScheme, type HistoryEntry } from "../api";
import { useApp, type RepeaterTab } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { autoEncodeRequest } from "../ui/urlencode";
import {
  firstOpenable,
  openable,
  parseRaceCount,
  patchOpen,
  plannedTechnique,
  RACE_MAX_HTTP2,
  RACE_MIN,
  raceArgs,
  raceMax,
  raceRows,
  raceSummary,
  sentRequestLine,
  shapeLabel,
  syncNote,
  techniqueLabel,
  type Raced,
  type RaceResult,
  type RaceRow,
} from "./race";
import { tabStore, type TabStore } from "./replayState";
import { BLANK_HANDSHAKE } from "./ws";
import { WsReplayTab } from "./WebSockets";

type SendResult = Pick<HistoryEntry, "id" | "url" | "duration_ms" | "response">;

interface Sent {
  raw: string;
  /** What was actually sent (after auto URL-encoding) and how many characters were encoded. */
  sent: string;
  encoded: number;
  result: SendResult | null;
  error: string | null;
  /** A race (`send --race`): its results and the one open in the response pane. */
  race?: Raced;
}

const BLANK = "GET / HTTP/1.1\nHost: \nUser-Agent: brainproxy\nAccept: */*\n\n";

function responseText(r: SendResult | null): string {
  const resp = r?.response;
  if (!resp) return "";
  return `HTTP/1.1 ${resp.status} ${resp.reason}\n${resp.headers.join("\n")}\n\n${bodyText(resp.body)}`;
}

/** scheme://host from the Host header, for requests typed by hand. */
function guessTarget(raw: string, current: string): string {
  if (current) return current;
  const host = /^host:\s*(\S+)/im.exec(raw)?.[1];
  return host ? `${/:443$/.test(host) ? "https" : "http"}://${host.replace(/:443$/, "")}` : "";
}

export function RepeaterView() {
  const app = useApp();
  const tabs = app.repeater;
  // This project's send history and running sends; see TabState.
  const [store] = useState(() => tabStore<TabState>(EMPTY_TAB));
  useEffect(() => store.start(), [store]);
  const active = tabs.find((t) => t.key === app.repeaterActive) ?? tabs[tabs.length - 1];

  const newTab = () => app.sendToRepeater({ raw: BLANK, target: "" });
  const newWsTab = () => app.sendToRepeater({ raw: BLANK_HANDSHAKE, target: "", ws: [], title: `WS ${tabs.length + 1}` });
  const closeTab = (key: number) => {
    app.setRepeater((ts) => ts.filter((t) => t.key !== key));
    if (key === active?.key) {
      const rest = tabs.filter((t) => t.key !== key);
      app.setRepeaterActive(rest[rest.length - 1]?.key ?? 0);
    }
  };

  return (
    <div className="col fill">
      <div className="subtabs">
        {tabs.map((t) => (
          <button key={t.key} className={t.key === active?.key ? "on" : ""} onClick={() => app.setRepeaterActive(t.key)} onAuxClick={(e) => e.button === 1 && closeTab(t.key)}>
            {t.title}
            <span
              className="x"
              title="Close"
              onClick={(e) => {
                e.stopPropagation();
                closeTab(t.key);
              }}
            >
              ×
            </span>
          </button>
        ))}
        <button onClick={newTab} title="New tab">
          +
        </button>
        <button onClick={newWsTab} title="New WebSocket tab">
          + WS
        </button>
      </div>
      {active ? (
        // key: each tab has its own editor state and send history.
        active.ws ? <WsReplayTab key={active.key} tab={active} /> : <RepeaterTabView key={active.key} tab={active} store={store} />
      ) : (
        <div className="blank">
          <p>Send a request here from Traffic (right-click → Send to Replay, or double-click), or</p>
          <button className="btn primary" onClick={newTab}>
            Start a blank request
          </button>
          <button className="btn" onClick={newWsTab}>
            Start a WebSocket connection
          </button>
        </div>
      )}
    </div>
  );
}

const AUTO_ENCODE = "repeater-auto-encode";
const RACE_COUNT = "repeater-race-count";

const RACE_COLUMNS: Column<RaceRow>[] = [
  { key: "idx", label: "#", width: 50, value: (r) => r.idx + 1, align: "right" },
  { key: "status", label: "Status", width: 70, value: (r) => r.status ?? r.error, render: (r) => r.status ?? <span className="error">{r.error}</span> },
  { key: "length", label: "Length", width: 80, value: (r) => r.length, align: "right" },
  { key: "time", label: "Time (ms)", width: 80, value: (r) => r.duration_ms, align: "right" },
  { key: "id", label: "History", width: 70, value: (r) => r.id, render: (r) => (r.id == null ? "" : `#${r.id}`) },
  { key: "differs", label: "", width: 120, value: (r) => (r.differs ? 1 : 0), render: (r) => (r.differs ? <span className="race-differs-tag">differs</span> : "") },
];

function storedAutoEncode(): boolean {
  try {
    return localStorage.getItem(AUTO_ENCODE) !== "off";
  } catch {
    return true;
  }
}

// Send history, and whether a send or race is running, survive switching tabs (the tab view
// remounts), keyed by tab. A race can run for a while: its result lands here even if the user
// switched away, and coming back shows it still running. The store belongs to the open project's
// Replay view, so the next project starts with none of it.
interface TabState {
  list: Sent[];
  at: number;
  busy: false | "send" | "race";
}
const EMPTY_TAB: TabState = { list: [], at: -1, busy: false };

function RepeaterTabView({ tab, store }: { tab: RepeaterTab; store: TabStore<TabState> }) {
  const app = useApp();
  // Pinned to this project: another may be open by the time a send or race ends.
  const { project } = app;
  const [raw, setRaw] = useState(tab.raw);
  const [target, setTarget] = useState(tab.target);
  const [autoEncode, setAutoEncode] = useState(storedAutoEncode);
  const [sent, setSent] = useState(() => store.get(tab.key));
  const { busy } = sent;
  const [raceCount, setRaceCount] = useState(() => {
    try {
      return localStorage.getItem(RACE_COUNT) || "20";
    } catch {
      return "20";
    }
  });
  const current = sent.list[sent.at];
  const update = (f: (s: TabState) => TabState) => store.update(tab.key, f);

  useEffect(() => {
    setSent(store.get(tab.key));
    return store.listen(tab.key, setSent);
  }, [tab.key, store]);

  // Keep the edited request in the shared tab list so it survives tab switches. Unchanged
  // tabs return the same array, so React skips the update; a new array every time changed
  // the app state, which re-ran this effect every 300 ms and re-ran other views' effects too.
  const { setRepeater } = app;
  useEffect(() => {
    const t = setTimeout(
      () =>
        setRepeater((ts) => {
          const cur = ts.find((x) => x.key === tab.key);
          if (!cur || (cur.raw === raw && cur.target === target)) return ts;
          return ts.map((x) => (x.key === tab.key ? { ...x, raw, target } : x));
        }),
      300,
    );
    return () => clearTimeout(t);
  }, [raw, target, tab.key, setRepeater]);

  const send = async () => {
    const to = withScheme(guessTarget(raw, target));
    if (!to) return app.toast("Set a target (scheme://host[:port]) or a Host header", "error");
    setTarget(to);
    update((s) => ({ ...s, busy: "send" }));
    const { text: sent, encoded } = autoEncode ? autoEncodeRequest(raw) : { text: raw, encoded: 0 };
    let entry: Sent;
    try {
      const result = await run<SendResult>(["send", `--target=${to}`, "-"], { stdin: textBytes(sent, tab.binary), project });
      entry = { raw, sent, encoded, result, error: null };
    } catch (e: any) {
      entry = { raw, sent, encoded, result: null, error: e.message };
    }
    update((s) => ({ list: [...s.list, entry], at: s.list.length, busy: false }));
  };

  const race = async () => {
    // The limit depends on the request line as sent (HTTP/2 or not), after auto URL-encoding.
    const { text: sent, encoded } = autoEncode ? autoEncodeRequest(raw) : { text: raw, encoded: 0 };
    const n = parseRaceCount(raceCount, sent);
    if (n == null) return app.toast(`Race takes ${RACE_MIN} to ${raceMax(sent)} requests (${plannedTechnique(sent)})`, "error");
    const to = withScheme(guessTarget(raw, target));
    if (!to) return app.toast("Set a target (scheme://host[:port]) or a Host header", "error");
    setTarget(to);
    try {
      localStorage.setItem(RACE_COUNT, String(n));
    } catch {
      /* storage unavailable */
    }
    update((s) => ({ ...s, busy: "race" }));
    let entry: Sent;
    try {
      const result = await run<RaceResult>(raceArgs(to, n), { stdin: textBytes(sent, tab.binary), project });
      entry = { raw, sent, encoded, result: null, error: null, race: { result, open: null } };
    } catch (e: any) {
      entry = { raw, sent, encoded, result: null, error: e.message };
    }
    update((s) => ({ list: [...s.list, entry], at: s.list.length, busy: false }));
    // The project closed while it ran: nothing to show the response in.
    if (entry.race && store.live()) {
      const first = firstOpenable(raceRows(entry.race.result));
      if (first != null) openRaced(first, entry.race.result);
    }
  };

  // Opens one raced response in the response pane (`history show`). The race's entry is found by
  // its result (the list may have grown since), and the response only lands if that row is
  // still the one open in it.
  const openRaced = async (idx: number, result: RaceResult) => {
    const item = raceRows(result)[idx];
    update((s) => ({ ...s, list: s.list.map((e) => (e.race?.result === result ? { ...e, race: { result, open: idx }, result: null, error: item.error } : e)) }));
    // A failure's row holds only its error, shown already.
    if (!openable(item)) return;
    const patch = (p: Partial<Sent>) => update((s) => ({ ...s, list: patchOpen(s.list, result, idx, p) }));
    try {
      const entry = await run<HistoryEntry>(["history", "show", String(item.id), MAX_BODY], { project });
      patch({ result: entry, error: null });
    } catch (e: any) {
      patch({ error: e.message });
    }
  };

  const go = (d: number) => {
    const at = sent.at + d;
    if (at < 0 || at >= sent.list.length) return;
    update((s) => ({ ...s, at }));
    setRaw(sent.list[at].raw);
  };

  // Views stay mounted when hidden: only while Replay is showing.
  const showing = app.tab === "repeater";
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (showing && (e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        if (!busy) send();
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  });

  const r = current?.result;
  const raced = current?.race;
  const line = sentRequestLine(raw, autoEncode);
  const rows = raced ? raceRows(raced.result) : [];
  const summary = raced ? raceSummary(raced.result) : null;
  const note = raced ? syncNote(raced.result) : null;
  const response = (
    <HttpView
      title={raced?.open != null ? `Response #${raced.open + 1} of ${rows.length}` : "Response"}
      value={responseText(r ?? null)}
      binary={isBinary(r?.response?.body)}
      placeholder={current?.error ?? (busy ? "Waiting for the response…" : raced ? (raced.open != null ? "Loading the response…" : "Select a response above") : "Send the request to see the response")}
      extra={
        r && (
          <button className="btn small" onClick={() => app.sendToComparer(responseText(r))}>
            To Diff
          </button>
        )
      }
    />
  );
  return (
    <div className="col fill" onKeyDown={() => {}}>
      <div className="toolbar">
        <button className="btn primary" disabled={!!busy} onClick={send} title="Send (⌘/Ctrl+Enter)">
          {busy === "send" ? "Sending…" : "Send"}
        </button>
        <div className="race-ctl" title={`Send the request ${raceCount || "N"} times at once to look for race conditions: ${plannedTechnique(line)}. A request line ending in HTTP/2 uses the single-packet attack (up to ${RACE_MAX_HTTP2}).`}>
          <button className="btn" disabled={!!busy} onClick={race}>
            {busy === "race" ? "Racing…" : "Race"}
          </button>
          <span className="label">×</span>
          <input className="input mono" type="number" aria-label="Race count" min={RACE_MIN} max={raceMax(line)} style={{ width: 64 }} value={raceCount} onChange={(e) => setRaceCount(e.target.value)} />
        </div>
        <div className="seg">
          <button disabled={sent.at <= 0} onClick={() => go(-1)} title="Previous request">
            ‹
          </button>
          <button disabled={sent.at >= sent.list.length - 1} onClick={() => go(1)} title="Next request">
            ›
          </button>
        </div>
        <span className="label">Target</span>
        <input className="input mono" style={{ width: 300 }} placeholder="https://example.com" value={target} onChange={(e) => setTarget(e.target.value)} />
        <label className="check" title="Before sending, percent-encode characters that aren't valid in a URL (spaces, quotes, <>, #, non-ASCII) in the request line and in form bodies. & = ? / and existing %XX stay as typed.">
          <input
            type="checkbox"
            checked={autoEncode}
            onChange={(e) => {
              setAutoEncode(e.target.checked);
              try {
                localStorage.setItem(AUTO_ENCODE, e.target.checked ? "on" : "off");
              } catch {
                /* storage unavailable */
              }
            }}
          />{" "}
          Auto URL-encode
        </label>
        <span className="grow" />
        {!!current?.encoded && (
          <span className="tag" title={`Sent as:\n${current.sent.split("\n")[0]}`}>
            {current.encoded} char{current.encoded === 1 ? "" : "s"} URL-encoded
          </span>
        )}
        {raced && summary && (
          <span className="tag" title={[note, raced.result.race_id && `History rows tagged race:${raced.result.race_id}`].filter(Boolean).join("\n") || undefined}>
            race ×{raced.result.race} · {techniqueLabel(raced.result.sync)}
            {note ? " (partial)" : ""}
          </span>
        )}
        {raced && summary && (
          <span className="muted" title={summary.baseline == null ? undefined : `Compared with the most common result: ${shapeLabel(raced.result.results[summary.baseline])} (first at #${summary.baseline + 1})`}>
            {summary.spread == null ? "no responses" : `spread ${summary.spread} ms`} · {summary.differing ? `${summary.differing} differ from the most common` : "all alike"}
            {summary.errors ? ` · ${summary.errors} failed` : ""}
          </span>
        )}
        {r?.response && (
          <span className="muted">
            {r.response.status} · {r.response.body.length ?? textBytes(bodyText(r.response.body), isBinary(r.response.body)).length} bytes · {r.duration_ms} ms · history #{r.id}
          </span>
        )}
      </div>
      <Split id="repeater" dir="row">
        <HttpView title="Request" value={raw} onChange={setRaw} binary={tab.binary} />
        {raced ? (
          <Split id="repeater-race" dir="col" initial={0.35}>
            <DataTable
              rows={rows}
              columns={RACE_COLUMNS}
              rowKey={(x) => x.idx}
              selected={raced.open}
              onSelect={(x) => openRaced(x.idx, raced.result)}
              rowClass={(x) => (x.differs ? "race-differs" : undefined)}
              initialSort={{ key: "idx", desc: false }}
            />
            {response}
          </Split>
        ) : (
          response
        )}
      </Split>
    </div>
  );
}
