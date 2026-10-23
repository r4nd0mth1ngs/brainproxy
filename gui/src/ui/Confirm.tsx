// In-app confirmation dialog. Native ones render differently per OS (GTK repeats the title as
// both the window title and the heading), so questions are asked inside the window instead.

import { useEffect, useState } from "react";

interface Request {
  title: string;
  message: string;
  ok: string;
  cancel: string;
  resolve: (yes: boolean) => void;
}

let show: ((r: Request) => void) | null = null;

/** Asks a yes/no question; true when the user picks `ok`. Needs a mounted <ConfirmHost />. */
export function confirm(title: string, message: string, ok: string, cancel: string): Promise<boolean> {
  return new Promise((resolve) =>
    show ? show({ title, message, ok, cancel, resolve }) : resolve(window.confirm(`${title}\n\n${message}`)),
  );
}

export function ConfirmHost() {
  const [req, setReq] = useState<Request | null>(null);
  useEffect(() => {
    // A question still open when another arrives is answered "no".
    show = (r) =>
      setReq((prev) => {
        prev?.resolve(false);
        return r;
      });
    return () => {
      show = null;
    };
  }, []);
  if (!req) return null;
  const answer = (yes: boolean) => {
    setReq(null);
    req.resolve(yes);
  };
  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && answer(false)}>
      <div className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
        <h2 id="confirm-title">{req.title}</h2>
        <p>{req.message}</p>
        <div className="row gap">
          <span className="grow" />
          {/* The safe choice has focus, so Enter doesn't destroy anything. */}
          <button className="btn" autoFocus onClick={() => answer(false)}>
            {req.cancel}
          </button>
          <button className="btn danger" onClick={() => answer(true)}>
            {req.ok}
          </button>
        </div>
      </div>
    </div>
  );
}
