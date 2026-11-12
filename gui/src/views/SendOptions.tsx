// Replay's per-tab send options: a toggle with the active ones as chips for the tab's
// toolbar, and the row that edits them. The flags they map to are in replayOptions.ts.

import { useApp, type RepeaterTab } from "../store";
import { DEFAULT_OPTIONS, DEFAULT_TIMEOUT, activeLabels, sendsAsTyped, withDefaults, type ReplayOptions, type TabKind } from "./replayOptions";

/** The tab's options, and a setter that keeps them in the tab (so they survive tab switches). */
export function useSendOptions(tab: RepeaterTab): [ReplayOptions, (patch: Partial<ReplayOptions>) => void] {
  const { setRepeater } = useApp();
  const set = (patch: Partial<ReplayOptions>) =>
    setRepeater((ts) => ts.map((x) => (x.key === tab.key ? { ...x, options: { ...withDefaults(x.options), ...patch } } : x)));
  return [withDefaults(tab.options), set];
}

/** "Options" plus a chip for each option that isn't the default, so a changed send isn't a surprise. */
export function OptionsToggle({ options, kind, open, onToggle, controls }: { options: ReplayOptions; kind: TabKind; open: boolean; onToggle: () => void; controls: string }) {
  return (
    <>
      <button className="btn small" onClick={onToggle} aria-expanded={open} aria-controls={controls} title={open ? "Hide the send options" : "Show the send options"}>
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

export function OptionsRow({ id, options, set, kind, binary }: { id: string; options: ReplayOptions; set: (patch: Partial<ReplayOptions>) => void; kind: TabKind; binary?: boolean }) {
  return (
    <div className="toolbar" id={id} role="group" aria-label="Send options">
      {kind === "http" && (
        <label className="check" title="Send over HTTP/2: ALPN h2 for https, prior knowledge for http. The request line can stay HTTP/1.1.">
          <input type="checkbox" checked={options.http2} onChange={(e) => set({ http2: e.target.checked })} /> HTTP/2
        </label>
      )}
      {kind === "http" && (
        <label
          className="check"
          title="Send over HTTP/3 (QUIC) to an https target that offers it, on its own UDP port or the endpoint its Alt-Svc header named (which must be in scope too). Otherwise it goes over TCP, and a note says why. A request line ending in HTTP/3 does the same."
        >
          <input type="checkbox" checked={options.http3} onChange={(e) => set({ http3: e.target.checked })} /> HTTP/3
        </label>
      )}
      {kind === "http" && (
        <label
          className="check"
          title={
            options.http2 || options.http3
              ? "HTTP/1 only: HTTP/2 and HTTP/3 rebuild the request into frames, so it can't be sent as typed. Turn them off to use it."
              : "Send the request exactly as it is in the editor, for request smuggling and other malformed requests: " +
                "Content-Length isn't updated, auto URL-encode is skipped, and no blank line is added after the headers. " +
                "The head's line breaks go out as CRLF; the body goes out as the editor holds it (see CRLF body)."
          }
        >
          <input type="checkbox" checked={sendsAsTyped(options)} disabled={options.http2 || options.http3} onChange={(e) => set({ verbatim: e.target.checked })} /> Send as typed
        </label>
      )}
      {kind === "http" && !binary && (
        <label
          className="check"
          title={
            "Send every line break in the body as CRLF, for chunked bodies typed by hand. " +
            "The editor can't hold a CR, so without this a body you typed has bare LF line breaks (one sent from Traffic keeps its own)."
          }
        >
          <input type="checkbox" checked={options.crlfBody} onChange={(e) => set({ crlfBody: e.target.checked })} /> CRLF body
        </label>
      )}
      <label className="label" htmlFor={`${id}-sni`} title="The TLS server name (SNI) to send instead of the target's host">
        SNI
      </label>
      <input id={`${id}-sni`} className="input mono" style={{ width: 180 }} placeholder="the target's host" spellCheck={false} value={options.sni} onChange={(e) => set({ sni: e.target.value })} />
      <label className="label" htmlFor={`${id}-timeout`} title="Seconds the request may take">
        Timeout
      </label>
      <input id={`${id}-timeout`} className="input" inputMode="decimal" style={{ width: 56 }} placeholder={String(DEFAULT_TIMEOUT)} value={options.timeout} onChange={(e) => set({ timeout: e.target.value })} />
      <span className="muted">s</span>
      <label className="check" title="Check the server's certificate and refuse an invalid one (off by default, as with most intercepting tools)">
        <input type="checkbox" checked={options.verifyTls} onChange={(e) => set({ verifyTls: e.target.checked })} /> Verify TLS
      </label>
      <label className="check" title={kind === "http" ? "Keep the request and response out of history: its row has only the time, target, method and path" : "Keep the connection and its messages out of history: only the handshake gets a row, with the time, target and path"}>
        <input type="checkbox" checked={options.noStore} onChange={(e) => set({ noStore: e.target.checked })} /> Don't record
      </label>
      <span className="grow" />
      <button className="btn small" disabled={same(options, DEFAULT_OPTIONS)} onClick={() => set(DEFAULT_OPTIONS)}>
        Reset
      </button>
    </div>
  );
}
