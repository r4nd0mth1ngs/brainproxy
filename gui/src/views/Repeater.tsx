import { useCallback, useEffect, useId, useRef, useState } from "react";
import { bodyText, cancelCli, isBinary, MAX_BODY, run, textBytes, withScheme, type HistoryEntry } from "../api";
import { useApp, type RepeaterTab } from "../store";
import { copyAsCurl, CurlDialog } from "../ui/CurlDialog";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { confirm } from "../ui/Confirm";
import { beginCall, closeQuestion, endCall, failureText, forgetTab, replayCalls, stopCall, tabSlot, useTabSlot } from "./replayCalls";
import { activeLabels, curlOptions, optionsProblem, requestToSend, sendArgs, sendsAsTyped, sentWithNote } from "./replayOptions";
import {
  firstOpenable,
  openable,
  patchOpen,
  plannedTechnique,
  RACE_MAX_HTTP2,
  RACE_MIN,
  raceGroupArgs,
  raceResultForRequest,
  parseGroupRaceCount,
  groupRaceMax,
  racesHttp2,
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
import { OptionsRow, OptionsToggle, useSendOptions } from "./SendOptions";
import { draftFromRequest } from "./manualFinding";
import { BLANK_HANDSHAKE } from "./ws";
import { WsReplayTab } from "./WebSockets";

type SendResult = Pick<HistoryEntry, "id" | "url" | "duration_ms" | "response">;

interface Sent {
  raw: string;
  /** What was actually sent (after auto URL-encoding, or with a CRLF head when sent as typed) and how many characters were encoded. */
  sent: string;
  encoded: number;
  /** The tab's options that weren't the default when this was sent (activeLabels). */
  labels: string[];
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
  const active = tabs.find((t) => t.key === app.repeaterActive) ?? tabs[tabs.length - 1];
  const [raceSelected, setRaceSelected] = useState<number[]>([]);
  const [pasting, setPasting] = useState(false);
  const curlButton = useRef<HTMLButtonElement>(null);
  useEffect(() => setRaceSelected([]), [app.project]);

  const newTab = () => app.sendToRepeater({ raw: BLANK, target: "" });
  const newWsTab = () => app.sendToRepeater({ raw: BLANK_HANDSHAKE, target: "", ws: [], title: `WS ${tabs.length + 1}` });
  const closeTab = async (key: number) => {
    // Closing stops a send still running, which may already have reached the server.
    const q = closeQuestion(key);
    if (q && !(await confirm(q.title, q.message, "Stop and close", "Keep open"))) return;
    forgetTab(key, cancelCli);
    setRaceSelected((keys) => keys.filter((k) => k !== key));
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
          <span key={t.key} style={{ display: "inline-flex", alignItems: "center" }}>
            {!t.ws && (
              <input
                type="checkbox"
                aria-label={`Include ${t.title} in race`}
                title="Race this tab with the active tab, using the active tab's options"
                checked={raceSelected.includes(t.key)}
                onChange={(e) => setRaceSelected((keys) => e.target.checked ? [...keys, t.key] : keys.filter((k) => k !== t.key))}
              />
            )}
            <button
              className={t.key === active?.key ? "on" : ""}
              title={activeLabels(t.options, t.ws ? "ws" : "http").join(", ") || undefined}
              onClick={() => app.setRepeaterActive(t.key)}
              onAuxClick={(e) => e.button === 1 && closeTab(t.key)}
            >
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
          </span>
        ))}
        <button onClick={newTab} title="New tab">
          +
        </button>
        <button onClick={newWsTab} title="New WebSocket tab">
          + WS
        </button>
        <button ref={curlButton} onClick={() => setPasting(true)} title="New tab from a pasted cURL command">
          + cURL
        </button>
      </div>
      {active ? (
        // key: each tab has its own editor state and send history.
        active.ws ? <WsReplayTab key={active.key} tab={active} /> : <RepeaterTabView key={active.key} tab={active} raceSelected={raceSelected} />
      ) : (
        <div className="blank">
          <p>Send a request here from Traffic (right-click → Send to Replay, or double-click), or</p>
          <button className="btn primary" onClick={newTab}>
            Start a blank request
          </button>
          <button className="btn" onClick={newWsTab}>
            Start a WebSocket connection
          </button>
          <button className="btn" onClick={() => setPasting(true)}>
            Paste a cURL command
          </button>
        </div>
      )}
      {pasting && <CurlDialog close={() => setPasting(false)} opener={curlButton} />}
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

// Send history survives switching tabs (the tab view remounts), keyed by tab; so does a send
// or race in flight, so its result lands in its tab and Stop stays (replayCalls.ts). A race
// can run for a while: coming back to its tab shows it still running.
const sentByTab = tabSlot<{ list: Sent[]; at: number }>({ list: [], at: -1 });

function RepeaterTabView({ tab, raceSelected }: { tab: RepeaterTab; raceSelected: number[] }) {
  const app = useApp();
  // Pinned to this project: another may be open by the time a send or race ends.
  const { project } = app;
  const [raw, setRaw] = useState(tab.raw);
  const [target, setTarget] = useState(tab.target);
  const [autoEncode, setAutoEncode] = useState(storedAutoEncode);
  const [options, setOptions] = useSendOptions(tab);
  const [showOptions, setShowOptions] = useState(false);
  const optionsId = useId();
  const [sent, setSent] = useTabSlot(sentByTab, tab.key);
  const current = sent.list[sent.at];
  // The send in flight, so Stop can cancel it (a long timeout would otherwise hold the tab).
  const [call] = useTabSlot(replayCalls, tab.key);
  const busy = call != null;
  const racing = busy && call.startsWith("replay-race-");
  const [raceCount, setRaceCount] = useState(() => {
    try {
      return localStorage.getItem(RACE_COUNT) || "20";
    } catch {
      return "20";
    }
  });

  // Keep the edited request in the shared tab list so it survives tab switches. Unchanged
  // tabs return the same array, so React skips the update; a new array every time changed
  // the app state, which re-ran this effect every 300 ms and re-ran other views' effects too.
  // Passed up 300 ms after typing, and at once on unmount or when the tabs are saved on close.
  const { setRepeater, addReplayEditor } = app;
  const edits = useRef({ raw, target });
  edits.current = { raw, target };
  const commit = useCallback(() => {
    const { raw, target } = edits.current;
    setRepeater((ts) => {
      const cur = ts.find((x) => x.key === tab.key);
      if (!cur || (cur.raw === raw && cur.target === target)) return ts;
      return ts.map((x) => (x.key === tab.key ? { ...x, raw, target } : x));
    });
  }, [tab.key, setRepeater]);
  useEffect(() => {
    const t = setTimeout(commit, 300);
    return () => clearTimeout(t);
  }, [raw, target, commit]);
  useEffect(() => {
    const remove = addReplayEditor(commit);
    return () => {
      remove();
      commit();
    };
  }, [addReplayEditor, commit]);

  const send = async () => {
    const to = withScheme(guessTarget(raw, target));
    if (!to) return app.toast("Set a target (scheme://host[:port]) or a Host header", "error");
    const problem = optionsProblem(options);
    if (problem) return app.toast(problem, "error");
    setTarget(to);
    const { text: sent, encoded } = requestToSend(raw, { binary: tab.binary, autoEncode, options });
    const labels = activeLabels(options, "http");
    const key = tab.key;
    const id = beginCall(key, "replay-send");
    let entry: Sent;
    try {
      const result = await run<SendResult>(sendArgs(to, options), { stdin: textBytes(sent, tab.binary), call: id, project });
      entry = { raw, sent, encoded, labels, result, error: null };
    } catch (e: any) {
      entry = { raw, sent, encoded, labels, result: null, error: failureText(e, "http") };
    }
    // Into the tab's history even if the view was remounted meanwhile; not if the tab closed.
    if (endCall(key, id)) sentByTab.update(key, (s) => ({ list: [...s.list, entry], at: s.list.length }));
  };

  // The request as Send would send it (auto URL-encoding, CRLF body), with the tab's options.
  const copyCurl = () => {
    const problem = optionsProblem(options);
    if (problem) return app.toast(problem, "error");
    copyAsCurl(requestToSend(raw, { binary: tab.binary, autoEncode, options }).text, withScheme(guessTarget(raw, target)), tab.binary, app.toast, curlOptions(options));
  };

  // The active tab is primary; checked HTTP tabs follow it in tab order.
  const raceTabs = [tab, ...app.repeater.filter((t) => t.key !== tab.key && !t.ws && raceSelected.includes(t.key))];
  const groupLines = raceTabs.map((t) => sentRequestLine(t.key === tab.key ? raw : t.raw, autoEncode && !sendsAsTyped(options)));
  const groupMax = groupRaceMax(groupLines, options.http2);
  const groupHttp2 = groupLines.some((line) => racesHttp2(line, options.http2));
  const race = async () => {
    const members = raceTabs.map((t) => {
      const source = t.key === tab.key ? raw : t.raw;
      return {
        tab: t,
        raw: source,
        to: withScheme(guessTarget(source, t.key === tab.key ? target : t.target)),
        ...requestToSend(source, { binary: t.binary, autoEncode, options }),
      };
    });
    const n = parseGroupRaceCount(raceCount, members.map((m) => m.text), options.http2);
    if (n == null) return app.toast(`Race takes ${members.length > 1 ? 1 : RACE_MIN} to ${groupMax} copies per tab`, "error");
    const to = members[0].to;
    if (!to || members.some((m) => !m.to)) return app.toast("Set a target (scheme://host[:port]) or a Host header for every tab", "error");
    try {
      const origin = new URL(to).origin;
      const other = members.find((m) => new URL(m.to).origin !== origin);
      if (other) return app.toast(`Race tabs must have the same origin: ${origin} and ${new URL(other.to).origin}`, "error");
    } catch {
      return app.toast("Set a valid target for every tab", "error");
    }
    if (members.some((m) => replayCalls.get(m.tab.key) != null)) return app.toast("A selected tab already has a send running", "error");
    const problem = optionsProblem(options);
    if (problem) return app.toast(problem, "error");
    setTarget(to);
    try {
      localStorage.setItem(RACE_COUNT, String(n));
    } catch {
      /* storage unavailable */
    }
    const labels = activeLabels(options, "http");
    const id = beginCall(tab.key, "replay-race");
    for (const member of members.slice(1)) replayCalls.update(member.tab.key, () => id);
    let result: RaceResult | null = null;
    let error: string | null = null;
    try {
      result = await run<RaceResult>(raceGroupArgs(to, n, members.length - 1, options), {
        stdin: textBytes(members[0].text, tab.binary),
        requestFiles: members.slice(1).map((m) => textBytes(m.text, m.tab.binary)),
        call: id,
        project,
      });
    } catch (e: any) {
      error = failureText(e, "race");
      // A failed HTTP/2 connection still reports every member's recorded failure.
      if (Array.isArray(e.data?.results)) result = e.data as RaceResult;
    }
    members.forEach((member, index) => {
      if (!endCall(member.tab.key, id)) return;
      const perTab = result ? raceResultForRequest(result, index) : null;
      const entry: Sent = {
        raw: member.raw, sent: member.text, encoded: member.encoded, labels,
        result: null, error, ...(perTab ? { race: { result: perTab, open: null } } : {}),
      };
      sentByTab.update(member.tab.key, (s) => ({ list: [...s.list, entry], at: s.list.length }));
      if (member.tab.key === tab.key && perTab) {
        const first = firstOpenable(raceRows(perTab));
        if (first != null) openRaced(first, perTab);
      }
    });
  };

  // Opens one raced response in the response pane (`history show`). The race's entry is found by
  // its result (the list may have grown since), and the response only lands if that row is
  // still the one open in it.
  const openRaced = async (idx: number, result: RaceResult) => {
    const key = tab.key;
    const item = raceRows(result)[idx];
    sentByTab.update(key, (s) => ({ ...s, list: s.list.map((e) => (e.race?.result === result ? { ...e, race: { result, open: idx }, result: null, error: item.error } : e)) }));
    // A failure's row holds only its error, shown already.
    if (!openable(item)) return;
    const patch = (p: Partial<Sent>) => sentByTab.update(key, (s) => ({ ...s, list: patchOpen(s.list, result, idx, p) }));
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
    setSent((s) => ({ ...s, at }));
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
  const note = current ? sentWithNote(current.labels, activeLabels(options, "http")) : null;
  const raced = current?.race;
  const line = sentRequestLine(raw, autoEncode && !sendsAsTyped(options));
  const rows = raced ? raceRows(raced.result) : [];
  const summary = raced ? raceSummary(raced.result) : null;
  const partial = raced ? syncNote(raced.result) : null;
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
        <button className="btn primary" disabled={busy} onClick={send} title="Send (⌘/Ctrl+Enter)">
          {busy && !racing ? "Sending…" : "Send"}
        </button>
        {busy && (
          <button
            className="btn"
            onClick={() => stopCall(tab.key, cancelCli)}
            title={
              racing
                ? "Stop the race. Its requests may already have reached the server; if they went out, history has every copy as cancelled (on Windows, as sent with no response recorded)."
                : "Stop waiting for this request. It may already have reached the server; if it went out, history has it as cancelled (on Windows, as sent with no response recorded)."
            }
          >
            Stop
          </button>
        )}
        <div
          className="race-ctl"
          title={`Send each of ${raceTabs.length} tabs ${raceCount || "N"} times at once, with the active tab's options, to look for race conditions: ${plannedTechnique(line, groupHttp2)}. HTTP/2 (the option, or a request line ending in HTTP/2) uses the single-packet attack (up to ${RACE_MAX_HTTP2}).`}
        >
          <button className="btn" disabled={busy} onClick={race}>
            {racing ? "Racing…" : raceTabs.length > 1 ? `Race ${raceTabs.length} tabs` : "Race"}
          </button>
          <span className="label">×</span>
          <input className="input mono" type="number" aria-label="Race count" min={raceTabs.length > 1 ? 1 : RACE_MIN} max={groupMax} style={{ width: 64 }} value={raceCount} onChange={(e) => setRaceCount(e.target.value)} />
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
        <label
          className="check"
          title={
            sendsAsTyped(options)
              ? "Off while this tab sends as typed (Options)"
              : "Before sending, percent-encode characters that aren't valid in a URL (spaces, quotes, <>, #, non-ASCII) in the request line and in form bodies. & = ? / and existing %XX stay as typed."
          }
        >
          <input
            type="checkbox"
            checked={autoEncode && !sendsAsTyped(options)}
            disabled={sendsAsTyped(options)}
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
        <button className="btn" onClick={copyCurl} title="Copy this request as a curl command (POSIX shell)">
          Copy as cURL
        </button>
        <OptionsToggle options={options} kind="http" open={showOptions} onToggle={() => setShowOptions(!showOptions)} controls={optionsId} />
        <div className="toolbar-end">
          {note && (
            <span className="tag" title="This step was sent with other options than the tab has now">
              {note}
            </span>
          )}
          <button
            className="btn small"
            onClick={() => app.newFinding(draftFromRequest(current?.sent ?? raw, withScheme(guessTarget(raw, target)), r?.id, r?.url))}
            title="Write up a finding for this request, linked to its last send"
          >
            Create finding…
          </button>
          {!!current?.encoded && (
            <span className="tag" title={`Sent as:\n${current.sent.split("\n")[0]}`}>
              {current.encoded} char{current.encoded === 1 ? "" : "s"} URL-encoded
            </span>
          )}
          {raced && summary && (
            <span className="tag" title={[partial, raced.result.race_id && `History rows tagged race:${raced.result.race_id}`].filter(Boolean).join("\n") || undefined}>
              race ×{raced.result.race} · {techniqueLabel(raced.result.sync)}
              {partial ? " (partial)" : ""}
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
              {r.response.status} · {r.response.body.length ?? textBytes(bodyText(r.response.body), isBinary(r.response.body)).length} bytes · {r.duration_ms} ms ·{" "}
              {r.id != null ? `history #${r.id}` : "not recorded"}
            </span>
          )}
        </div>
      </div>
      {showOptions && <OptionsRow id={optionsId} options={options} set={setOptions} kind="http" binary={tab.binary} />}
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
