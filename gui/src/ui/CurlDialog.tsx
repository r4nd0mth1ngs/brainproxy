// cURL in and out of the app: a dialog that opens a pasted command as a Replay tab, and
// copying a request as a command. The conversion is ui/curl.ts; nothing here sends anything.

import { useState } from "react";
import { pathOf } from "../api";
import { useApp } from "../store";
import { parseCurl, toCurl } from "./curl";

/** Copies a raw request to `target` as a cURL command, with a toast for the result. */
export function copyAsCurl(raw: string, target: string, binary: boolean | undefined, toast: (text: string, kind?: "info" | "error") => void) {
  let command: string;
  let warnings: string[];
  try {
    ({ command, warnings } = toCurl(raw, target, binary));
  } catch (e: any) {
    return toast(e.message, "error");
  }
  navigator.clipboard.writeText(command).then(
    () => toast(["Copied as cURL", ...warnings].join("\n")),
    (e) => toast(`Couldn't copy: ${e?.message ?? e}`, "error"),
  );
}

/** Paste a cURL command; it opens as a new Replay tab. */
export function CurlDialog({ close }: { close: () => void }) {
  const app = useApp();
  const [text, setText] = useState("");
  const [error, setError] = useState("");

  const open = () => {
    try {
      const p = parseCurl(text);
      app.sendToRepeater({ raw: p.raw, target: p.target, binary: p.binary, title: pathOf(p.url).slice(0, 24) });
      if (p.warnings.length) app.toast(p.warnings.join("\n"));
      close();
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div
      className="confirm-backdrop"
      onKeyDown={(e) => {
        // Kept here, so Replay's own ⌘/Ctrl+Enter (Send) doesn't fire too.
        e.stopPropagation();
        if (e.key === "Escape") close();
        if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
          e.preventDefault();
          open();
        }
      }}
    >
      <div className="confirm-dialog curl-dialog" role="dialog" aria-modal="true" aria-labelledby="curl-title">
        <h2 id="curl-title">New tab from cURL</h2>
        <p>
          Paste a curl command, for example from a browser's <i>Copy as cURL</i> (bash or cmd). It opens in a new tab; nothing is sent until
          you press Send.
        </p>
        <textarea
          className="input multiline mono full"
          rows={10}
          autoFocus
          spellCheck={false}
          placeholder={"curl 'https://example.com/api' -H 'Accept: application/json' --data-raw '{\"a\":1}'"}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setError("");
          }}
        />
        {error && <p className="curl-error">{error}</p>}
        <div className="row gap">
          <span className="grow" />
          <button className="btn" onClick={close}>
            Cancel
          </button>
          <button className="btn primary" disabled={!text.trim()} onClick={open} title="Open in Replay (⌘/Ctrl+Enter)">
            Open in Replay
          </button>
        </div>
      </div>
    </div>
  );
}
