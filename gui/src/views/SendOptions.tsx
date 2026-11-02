// Replay's per-tab send options: a toggle with the active ones as chips for the tab's
// toolbar, and the row that edits them. The flags they map to are in replayOptions.ts.

import { useApp, type RepeaterTab } from "../store";
import { DEFAULT_OPTIONS, DEFAULT_TIMEOUT, activeLabels, withDefaults, type ReplayOptions, type TabKind } from "./replayOptions";

/** The tab's options, and a setter that keeps them in the tab (so they survive tab switches). */
export function useSendOptions(tab: RepeaterTab): [ReplayOptions, (patch: Partial<ReplayOptions>) => void] {
  const { setRepeater } = useApp();
  const set = (patch: Partial<ReplayOptions>) =>
    setRepeater((ts) => ts.map((x) => (x.key === tab.key ? { ...x, options: { ...withDefaults(x.options), ...patch } } : x)));
  return [withDefaults(tab.options), set];
}

/** "Options" plus a chip for each option that isn't the default, so a changed send isn't a surprise. */
export function OptionsToggle({ options, kind, open, onToggle }: { options: ReplayOptions; kind: TabKind; open: boolean; onToggle: () => void }) {
  return (
    <>
      <button className="btn small" onClick={onToggle} title={open ? "Hide the send options" : "Show the send options"}>
        Options {open ? "▴" : "▾"}
      </button>
      {activeLabels(options, kind).map((l) => (
        <span key={l} className="chip" title="Not the default; change it under Options">
          {l}
        </span>
      ))}
    </>
  );
}

const same = (a: ReplayOptions, b: ReplayOptions) => (Object.keys(a) as (keyof ReplayOptions)[]).every((k) => a[k] === b[k]);

export function OptionsRow({ options, set, kind }: { options: ReplayOptions; set: (patch: Partial<ReplayOptions>) => void; kind: TabKind }) {
  return (
    <div className="toolbar">
      {kind === "http" && (
        <label className="check" title="Send over HTTP/2: ALPN h2 for https, prior knowledge for http. The request line can stay HTTP/1.1.">
          <input type="checkbox" checked={options.http2} onChange={(e) => set({ http2: e.target.checked })} /> HTTP/2
        </label>
      )}
      {kind === "http" && (
        <label
          className="check"
          title={
            "Send the request exactly as it is in the editor, for request smuggling and other malformed requests: " +
            "Content-Length isn't updated, auto URL-encode is skipped, and no blank line is added after the headers. " +
            "Each line break goes out as CRLF, in the body too (a binary body keeps its bytes)."
          }
        >
          <input type="checkbox" checked={options.verbatim} onChange={(e) => set({ verbatim: e.target.checked })} /> Send as typed
        </label>
      )}
      <span className="label" title="The TLS server name (SNI) to send instead of the target's host">
        SNI
      </span>
      <input className="input mono" style={{ width: 180 }} placeholder="the target's host" spellCheck={false} value={options.sni} onChange={(e) => set({ sni: e.target.value })} />
      <span className="label" title="Seconds the request may take">
        Timeout
      </span>
      <input className="input" inputMode="decimal" style={{ width: 56 }} placeholder={String(DEFAULT_TIMEOUT)} value={options.timeout} onChange={(e) => set({ timeout: e.target.value })} />
      <span className="muted">s</span>
      <label className="check" title="Check the server's certificate and refuse an invalid one (off by default, as with most intercepting tools)">
        <input type="checkbox" checked={options.verifyTls} onChange={(e) => set({ verifyTls: e.target.checked })} /> Verify TLS
      </label>
      <label className="check" title={kind === "http" ? "Don't record the request and response in history" : "Don't record the connection and its messages"}>
        <input type="checkbox" checked={options.noStore} onChange={(e) => set({ noStore: e.target.checked })} /> Don't record
      </label>
      <span className="grow" />
      <button className="btn small" disabled={same(options, DEFAULT_OPTIONS)} onClick={() => set(DEFAULT_OPTIONS)}>
        Reset
      </button>
    </div>
  );
}
