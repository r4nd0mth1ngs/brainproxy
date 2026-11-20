// Settings › TLS / CA › Install in system trust store: says what `ca install-system` changes on
// this OS, runs it once the person agrees, and shows its result with any step left to them.
// What it says and means is views/systemTrust.ts.

import { useEffect, useRef, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { useDialogFocus } from "../ui/dialogFocus";
import { changedSince, currentTrustOs, failed, installed, thumbprint, trustPlan, type InstallResult, type TrustOutcome } from "./systemTrust";

export function SystemTrustDialog({ certPath, pem, sha256, close }: { certPath: string; pem: string; sha256: string; close: () => void }) {
  const app = useApp();
  const [os] = useState(currentTrustOs);
  const [sha1, setSha1] = useState<string>();
  const plan = trustPlan(os, certPath, sha1);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<TrustOutcome | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  // Closed while the install still runs: its result comes as a toast instead.
  const gone = useRef(false);
  useDialogFocus(ref);
  useEffect(() => {
    thumbprint(pem).then(setSha1, () => setSha1(undefined));
  }, [pem]);
  // Install goes away with the result: focus moves to Close, so Esc and Tab still reach the dialog.
  useEffect(() => {
    if (outcome) closeButton.current?.focus();
  }, [outcome]);
  useEffect(
    () => () => {
      gone.current = true;
    },
    [],
  );

  const install = async () => {
    if (!plan.args || busy) return;
    setBusy(true);
    let o: TrustOutcome;
    try {
      // The CLI installs the CA on disk now: not if it is another than the one shown.
      const now = await run<{ sha256: string }>(["ca", "export"]);
      const changed = changedSince(sha256, now.sha256);
      o = changed
        ? { ok: false, title: "Not installed", detail: changed, manual: [] }
        : installed(plan, await run<InstallResult>(plan.args), sha256);
    } catch (e: any) {
      o = failed(plan, String(e?.message ?? e));
    }
    setBusy(false);
    if (gone.current) app.toast(`${o.title}. ${o.detail}`, o.ok ? "info" : "error");
    else setOutcome(o);
  };
  const copy = (lines: string[]) =>
    navigator.clipboard.writeText(lines.join("\n")).then(
      () => app.toast("Commands copied"),
      (e) => app.toast(`Couldn't copy: ${e?.message ?? e}`, "error"),
    );
  // Linux runs as root only by exception, so its sudo commands are shown before trying too.
  const manual = outcome ? outcome.manual : plan.args && os !== "linux" ? [] : plan.manual;

  return (
    // Global shortcuts wait while an aria-modal dialog is open, and useDialogFocus keeps Tab in
    // here from a document listener, so key presses must reach the document.
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && close()}>
      <div ref={ref} className="confirm-dialog trust-dialog" role="dialog" aria-modal="true" aria-labelledby="trust-title" aria-describedby="trust-what">
        <h2 id="trust-title">Install the CA in {plan.store}</h2>
        {!outcome && (
          <div id="trust-what">
            <ul className="trust-list">
              {plan.changes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
            <p>{plan.prompt}</p>
          </div>
        )}
        {/* Mounted from the start, so the result is announced when it appears. */}
        <div aria-live="polite">
          {busy && <p>Installing… {os === "windows" ? "Answer Windows' warning; you can close this, and the result comes as a message." : ""}</p>}
          {outcome && (
            <div id="trust-what">
              <p className={outcome.ok && !outcome.mismatch ? "trust-ok" : "trust-error"}>
                <b>{outcome.title}.</b> {outcome.detail}
              </p>
              {outcome.mismatch && <p className="trust-error">{outcome.mismatch}</p>}
              {outcome.hint && <p>{outcome.hint}</p>}
            </div>
          )}
        </div>
        {manual.length > 0 && (
          <div className="trust-commands">
            {!outcome && plan.args && <p>Or run this in {plan.shell} yourself:</p>}
            <pre className="code">{manual.join("\n")}</pre>
            <button className="btn small" onClick={() => copy(manual)}>
              Copy commands
            </button>
          </div>
        )}
        <details className="trust-undo">
          <summary>To take it out again</summary>
          <p>
            brainproxy has no command for this; run this in {plan.shell}. It takes out this CA only{sha1 ? " (by its SHA-1 thumbprint)" : ""}; one
            installed before a Regenerate has the same name, {plan.os === "linux" ? "and the same file" : "and a thumbprint of its own"}.
          </p>
          <pre className="code">{plan.undo.join("\n")}</pre>
        </details>
        <div className="row gap">
          <span className="grow" />
          {/* The safe choice has focus, so Enter doesn't change the system's trust. Close stays
              enabled while it runs: Windows' warning may be hidden behind this window. */}
          <button ref={closeButton} type="button" className="btn" autoFocus onClick={close}>
            {outcome || busy || !plan.args ? "Close" : "Cancel"}
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
