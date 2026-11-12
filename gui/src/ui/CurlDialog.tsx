// cURL in and out of the app: a dialog that opens a pasted command as a Replay tab, and
// copying a request as a command. The conversion is ui/curl.ts; nothing here sends anything.

import { useEffect, useRef, useState, type RefObject } from "react";
import { pathOf } from "../api";
import { useApp } from "../store";
import { parseCurl, toCurl, type CurlSendOptions } from "./curl";
import { keepFocusIn } from "./focus";
import { define, matches } from "./actions.ts";
import { chordOf, isMac } from "./chords.ts";

define([{ id: "dialog.curlOpen", title: "Open the pasted cURL command (New tab from cURL)", group: "Dialogs", keys: "Mod+Enter", where: "dialog", typing: true, noPalette: true }]);
const MAC = isMac();

/**
 * Copies a raw request to `target` as a cURL command, with a toast for the result. `send` is a
 * Replay tab's options, so the command sends the way the tab does.
 */
export function copyAsCurl(raw: string, target: string, binary: boolean | undefined, toast: (text: string, kind?: "info" | "error") => void, send?: CurlSendOptions) {
  let command: string;
  let warnings: string[];
  try {
    ({ command, warnings } = toCurl(raw, target, binary, send));
  } catch (e: any) {
    return toast(e.message, "error");
  }
  navigator.clipboard.writeText(command).then(
    () => toast(["Copied as cURL", ...warnings].join("\n")),
    (e) => toast(`Couldn't copy: ${e?.message ?? e}`, "error"),
  );
}

/** Paste a cURL command; it opens as a new Replay tab. Focus goes back to `opener` on close. */
export function CurlDialog({ close, opener }: { close: () => void; opener?: RefObject<HTMLElement | null> }) {
  const app = useApp();
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  // What the tab leaves out (a proxy, --resolve, --connect-to, a Unix socket: the request may
  // go elsewhere than curl's would), shown before it opens; the next open goes ahead.
  const [warnings, setWarnings] = useState<string[]>([]);
  const box = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLTextAreaElement>(null);

  // Focus starts in the command and goes back to the opener on close. (Set here rather than
  // with autoFocus alone: StrictMode runs the cleanup once on mount, which would leave focus
  // outside the open dialog.)
  useEffect(() => {
    input.current?.focus();
    return () => opener?.current?.focus();
  }, [opener]);

  const open = () => {
    try {
      const p = parseCurl(text);
      if (p.warnings.length && !warnings.length) return setWarnings(p.warnings);
      app.sendToRepeater({ raw: p.raw, target: p.target, binary: p.binary, title: pathOf(p.url).slice(0, 24) });
      close();
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div
      className="confirm-backdrop"
      onKeyDown={(e) => {
        // Kept here, so no other shortcut (Replay's Send, say) runs too.
        e.stopPropagation();
        keepFocusIn(box.current, e);
        if (e.key === "Escape") close();
        if (matches("dialog.curlOpen", chordOf(e.nativeEvent, MAC), e.target as HTMLElement, MAC)) {
          e.preventDefault();
          open();
        }
      }}
    >
      <div ref={box} className="confirm-dialog curl-dialog" role="dialog" aria-modal="true" aria-labelledby="curl-title" aria-describedby="curl-help">
        <h2 id="curl-title">New tab from cURL</h2>
        <p id="curl-help">
          Paste a curl command, for example from a browser's <i>Copy as cURL</i> (bash or cmd). It opens in a new tab; nothing is sent until
          you press Send.
        </p>
        <textarea
          ref={input}
          className="input multiline mono full"
          rows={10}
          autoFocus
          spellCheck={false}
          aria-label="cURL command"
          aria-invalid={!!error}
          aria-errormessage={error ? "curl-error" : undefined}
          placeholder={"curl 'https://example.com/api' -H 'Accept: application/json' --data-raw '{\"a\":1}'"}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setError("");
            setWarnings([]);
          }}
        />
        {error && (
          <p id="curl-error" className="curl-error" role="alert">
            {error}
          </p>
        )}
        {warnings.length > 0 && (
          <div className="curl-warnings" role="alert">
            <p>The tab won't do all the command says:</p>
            <ul>
              {warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </div>
        )}
        <div className="row gap">
          <span className="grow" />
          <button className="btn" onClick={close}>
            Cancel
          </button>
          <button className="btn primary" disabled={!text.trim()} onClick={open} title="Open in Replay (⌘/Ctrl+Enter)">
            {warnings.length ? "Open anyway" : "Open in Replay"}
          </button>
        </div>
      </div>
    </div>
  );
}
