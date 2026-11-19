// Settings › TLS / CA › Install in system trust store: says what `ca install-system` changes on
// this OS, runs it once the person agrees, and shows its result with any step left to them.
// What it says and means is views/systemTrust.ts.

import { useEffect, useRef, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { useDialogFocus } from "../ui/dialogFocus";
import { currentTrustOs, failed, installed, trustPlan, type InstallResult, type TrustOutcome } from "./systemTrust";

export function SystemTrustDialog({ certPath, sha256, close }: { certPath: string; sha256: string; close: () => void }) {
  const app = useApp();
  const [plan] = useState(() => trustPlan(currentTrustOs(), certPath));
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<TrustOutcome | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  useDialogFocus(ref);
  // Install goes away with the result: focus moves to Close, so Esc and Tab still reach the dialog.
  useEffect(() => {
    if (outcome) closeButton.current?.focus();
  }, [outcome]);

  const install = async () => {
    if (!plan.args || busy) return;
    setBusy(true);
    try {
      setOutcome(installed(plan, await run<InstallResult>(plan.args), sha256));
    } catch (e: any) {
      setOutcome(failed(plan, String(e?.message ?? e)));
    } finally {
      setBusy(false);
    }
  };
  const copy = (lines: string[]) =>
    navigator.clipboard.writeText(lines.join("\n")).then(
      () => app.toast("Commands copied"),
      (e) => app.toast(`Couldn't copy: ${e?.message ?? e}`, "error"),
    );
  const manual = outcome ? outcome.manual : plan.args ? [] : plan.manual;

  return (
    <div
      className="confirm-backdrop"
      onKeyDown={(e) => {
        // Kept here, so no other shortcut runs under the dialog.
        e.stopPropagation();
        // While it runs, Windows may be waiting on its own warning: the answer is shown here.
        if (e.key === "Escape" && !busy) close();
      }}
    >
      <div ref={ref} className="confirm-dialog trust-dialog" role="dialog" aria-modal="true" aria-labelledby="trust-title" aria-describedby="trust-what">
        <h2 id="trust-title">Install the CA in {plan.store}</h2>
        {!outcome ? (
          <div id="trust-what">
            <ul className="trust-list">
              {plan.changes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
            <p>{plan.prompt}</p>
          </div>
        ) : (
          <div id="trust-what" role="status">
            <p className={outcome.ok ? "trust-ok" : "trust-error"}>
              <b>{outcome.title}.</b> {outcome.detail}
            </p>
            {outcome.mismatch && <p className="trust-error">{outcome.mismatch}</p>}
            {outcome.hint && <p>{outcome.hint}</p>}
          </div>
        )}
        {manual.length > 0 && (
          <div className="trust-commands">
            <pre className="code">{manual.join("\n")}</pre>
            <button className="btn small" onClick={() => copy(manual)}>
              Copy commands
            </button>
          </div>
        )}
        <details className="trust-undo">
          <summary>To take it out again</summary>
          <p>brainproxy has no command for this; run:</p>
          <pre className="code">{plan.undo.join("\n")}</pre>
        </details>
        <div className="row gap">
          <span className="grow" />
          {/* The safe choice has focus, so Enter doesn't change the system's trust. */}
          <button ref={closeButton} type="button" className="btn" autoFocus disabled={busy} onClick={close}>
            {outcome || !plan.args ? "Close" : "Cancel"}
          </button>
          {plan.args && !outcome && (
            <button type="button" className="btn danger" disabled={busy} onClick={install}>
              {busy ? "Installing…" : "Install"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
