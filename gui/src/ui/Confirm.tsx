// In-app confirmation and text-entry dialogs. Native ones render differently per OS (GTK
// repeats the title as both the window title and the heading), and on macOS the desktop
// app's WKWebView has no window.prompt at all (it returns null), so questions are asked
// inside the window instead.

import { useEffect, useState } from "react";

interface Request {
  title: string;
  message: string;
  ok: string;
  cancel: string;
  /** Set when the answer is typed: the field's starting text. */
  value?: string;
  /** null when cancelled; the typed text (or "" for a yes/no question) otherwise. */
  resolve: (answer: string | null) => void;
}

let show: ((r: Request) => void) | null = null;

/** Asks a yes/no question; true when the user picks `ok`. Needs a mounted <ConfirmHost />. */
export function confirm(title: string, message: string, ok: string, cancel: string): Promise<boolean> {
  return new Promise((resolve) =>
    show
      ? show({ title, message, ok, cancel, resolve: (a) => resolve(a != null) })
      : resolve(window.confirm(`${title}\n\n${message}`)),
  );
}

/** Asks for a line of text, starting from `value`; null if cancelled. Needs a mounted <ConfirmHost />. */
export function ask(title: string, message: string, ok: string, cancel: string, value = ""): Promise<string | null> {
  return new Promise((resolve) =>
    show ? show({ title, message, ok, cancel, value, resolve }) : resolve(window.prompt(`${title}\n\n${message}`, value)),
  );
}

export function ConfirmHost() {
  const [req, setReq] = useState<Request | null>(null);
  const [text, setText] = useState("");
  useEffect(() => {
    // A question still open when another arrives is answered "no".
    show = (r) => {
      setText(r.value ?? "");
      setReq((prev) => {
        prev?.resolve(null);
        return r;
      });
    };
    return () => {
      show = null;
    };
  }, []);
  if (!req) return null;
  const typed = req.value != null;
  const answer = (a: string | null) => {
    setReq(null);
    req.resolve(a);
  };
  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && answer(null)}>
      <form
        className="confirm-dialog"
        role={typed ? "dialog" : "alertdialog"}
        aria-modal="true"
        aria-labelledby="confirm-title"
        onSubmit={(e) => {
          e.preventDefault();
          if (!typed || text.trim()) answer(typed ? text : "");
        }}
      >
        <h2 id="confirm-title">{req.title}</h2>
        <p>{req.message}</p>
        {typed && (
          <input
            className="input"
            style={{ width: "100%", marginBottom: 18 }}
            aria-labelledby="confirm-title"
            autoFocus
            value={text}
            onFocus={(e) => e.target.select()}
            onChange={(e) => setText(e.target.value)}
          />
        )}
        <div className="row gap">
          <span className="grow" />
          {/* For a yes/no question the safe choice has focus, so Enter doesn't destroy anything;
              in a text field Enter submits what was typed. */}
          <button type="button" className="btn" autoFocus={!typed} onClick={() => answer(null)}>
            {req.cancel}
          </button>
          {typed ? (
            <button type="submit" className="btn primary" disabled={!text.trim()}>
              {req.ok}
            </button>
          ) : (
            <button type="button" className="btn danger" onClick={() => answer("")}>
              {req.ok}
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
