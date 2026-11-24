// A proof-of-concept page for a request (`poc csrf`, `poc clickjacking`): its settings, the
// warnings, and the HTML as text. The page is never rendered here; "Open in browser" writes it
// to the temporary folder and opens it after a confirmation, as opening it sends requests.

import { useEffect, useRef, useState } from "react";
import { inTauri, run, textBytes } from "../api";
import { useApp } from "../store";
import { chooseSave } from "../ui/chooseSave";
import { confirm } from "../ui/Confirm";
import { useDialogFocus } from "../ui/dialogFocus";
import { saveFailure } from "../ui/savePath.ts";
import {
  DEFAULT_CLICKJACKING,
  DEFAULT_CSRF,
  defaultName,
  joinPath,
  openWarning,
  pocArgs,
  readsStdin,
  summary,
  tempName,
  type ClickjackingSettings,
  type CsrfSettings,
  type PocKind,
  type PocPage,
  type PocSource,
} from "./poc.ts";

const TITLES: Record<PocKind, string> = { csrf: "CSRF proof of concept", clickjacking: "Clickjacking proof of concept" };

export function PocDialog({ kind, source, close }: { kind: PocKind; source: PocSource; close: () => void }) {
  const app = useApp();
  // Pinned to this project: another may be open by the time a call ends.
  const { project } = app;
  const [csrf, setCsrf] = useState<CsrfSettings>(DEFAULT_CSRF);
  const [clickjacking, setClickjacking] = useState<ClickjackingSettings>(DEFAULT_CLICKJACKING);
  const [page, setPage] = useState<PocPage | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const dialog = useRef<HTMLDivElement>(null);
  useDialogFocus(dialog);

  const call = (output?: { path: string; overwrite: boolean }) =>
    run<PocPage>(pocArgs(kind, source, { csrf, clickjacking }, output), {
      project,
      stdin: readsStdin(kind, source) && "raw" in source ? textBytes(source.raw, source.binary) : undefined,
    });

  // The page again whenever a setting changes; only the latest answer shows.
  const latest = useRef(0);
  useEffect(() => {
    const me = ++latest.current;
    const t = setTimeout(() => {
      call().then(
        (p) => me === latest.current && (setPage(p), setError("")),
        (e) => me === latest.current && (setPage(null), setError(e.message)),
      );
    }, 200);
    return () => clearTimeout(t);
  }, [kind, source, csrf, clickjacking]);

  const copy = () =>
    page &&
    navigator.clipboard.writeText(page.html).then(
      () => app.toast("Page HTML copied."),
      (e) => app.toast(`Couldn't copy: ${e?.message ?? e}`, "error"),
    );

  const save = async () => {
    let chosen: { path: string; overwrite: boolean } | null = null;
    try {
      chosen = await chooseSave(defaultName(kind, source), "HTML", "html");
      if (!chosen) return;
      setBusy(true);
      await call(chosen);
      app.toast(`Page saved to ${chosen.path}.`);
      if (inTauri) {
        const { revealItemInDir } = await import("@tauri-apps/plugin-opener");
        await revealItemInDir(chosen.path).catch(() => {});
      }
    } catch (e: any) {
      app.toast(chosen ? saveFailure(e, chosen.path) : e.message, "error");
    } finally {
      setBusy(false);
    }
  };

  const openInBrowser = async () => {
    if (!(await confirm("Open the page in your browser?", openWarning(kind), "Open in browser", "Cancel"))) return;
    try {
      setBusy(true);
      const { tempDir } = await import("@tauri-apps/api/path");
      const path = joinPath(await tempDir(), tempName(kind));
      await call({ path, overwrite: false });
      const { openPath } = await import("@tauri-apps/plugin-opener");
      await openPath(path);
    } catch (e: any) {
      app.toast(e.message ?? String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && close()}>
      <div ref={dialog} className="confirm-dialog poc-dialog" role="dialog" aria-modal="true" aria-labelledby="poc-title" aria-describedby="poc-help">
        <h2 id="poc-title">{TITLES[kind]}</h2>
        <p id="poc-help">
          A page that {kind === "csrf" ? "sends this request from a visitor's browser" : "frames this URL under a decoy button"}. Nothing is sent
          from here; opening the page in a browser sends its requests straight to the target, outside brainproxy's scope checks.
        </p>
        {kind === "csrf" ? (
          <div className="row gap poc-settings">
            <label>
              Technique{" "}
              <select className="input" value={csrf.technique} onChange={(e) => setCsrf({ ...csrf, technique: e.target.value as CsrfSettings["technique"] })}>
                <option value="form">HTML form</option>
                <option value="fetch">fetch (script)</option>
              </select>
            </label>
            <label>
              <input type="checkbox" checked={csrf.autoSubmit} onChange={(e) => setCsrf({ ...csrf, autoSubmit: e.target.checked })} /> Send when the page opens
            </label>
            <label className="grow">
              Leave out{" "}
              <input
                className="input mono"
                placeholder="parameter names, such as csrf_token"
                spellCheck={false}
                value={csrf.drop}
                onChange={(e) => setCsrf({ ...csrf, drop: e.target.value })}
              />
            </label>
          </div>
        ) : (
          <div className="row gap poc-settings">
            <label>
              Frame opacity{" "}
              <input
                className="input"
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={clickjacking.opacity}
                onChange={(e) => setClickjacking({ ...clickjacking, opacity: Number(e.target.value) })}
              />
            </label>
            <label className="grow">
              Decoy text <input className="input" value={clickjacking.decoy} onChange={(e) => setClickjacking({ ...clickjacking, decoy: e.target.value })} />
            </label>
          </div>
        )}
        {error && (
          <p className="poc-error" role="alert">
            {error}
          </p>
        )}
        {page && (
          <>
            <p className="poc-summary">{summary(page)}</p>
            {page.warnings.length > 0 && (
              <div className="poc-warnings" role="status">
                <ul>
                  {page.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
        {/* The page as text: it is the target's values in HTML, so it is never rendered in the app. */}
        <textarea className="input multiline mono full" rows={14} readOnly spellCheck={false} aria-label="Page HTML" value={page?.html ?? ""} placeholder={error ? "" : "Writing the page…"} />
        <div className="row gap">
          <button className="btn" disabled={!page} onClick={copy}>
            Copy
          </button>
          <button className="btn" disabled={!page || busy} onClick={save}>
            Save…
          </button>
          {inTauri && (
            <button className="btn" disabled={!page || busy} onClick={openInBrowser} title="Writes the page to the temporary folder and opens it, after a confirmation">
              Open in browser…
            </button>
          )}
          <span className="grow" />
          <button className="btn primary" onClick={close} disabled={busy}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
