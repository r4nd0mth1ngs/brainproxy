// Proxy › Traffic › Export: the options dialog, then the save dialog, then `history export har`.
// The arguments and their checks are in trafficExport.ts.

import { useRef, useState } from "react";
import { inTauri, run } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { useDialogFocus } from "../ui/dialogFocus";
import { chooseSave } from "../ui/chooseSave.ts";
import { saveFailure } from "../ui/savePath.ts";
import { DEFAULT_EXPORT, EXPORT_LIMIT, exportArgs, exportNote, exportProblem, MIN_MASK, type ExportOptions, type ExportResult } from "./trafficExport.ts";
import type { TrafficFilter } from "./trafficFilter";

/** Asks how to export what the filter shows, then writes it. `close` is called once it has started or was cancelled. */
export function TrafficExport({ filter, shown, close }: { filter: TrafficFilter; shown: number; close: () => void }) {
  const app = useApp();
  const [o, setO] = useState<ExportOptions>(DEFAULT_EXPORT);
  const box = useRef<HTMLFormElement>(null);
  useDialogFocus(box);
  const problem = exportProblem(filter, o);
  const name = app.temp ? "engagement" : app.project.split(/[\\/]/).pop()!.replace(/\.bpdb$/, "");

  const go = async () => {
    if (problem) return;
    // One dialog at a time: this one closes before the question and the save dialog.
    close();
    if (
      o.keepSecrets &&
      !(await confirm(
        "Export with secrets?",
        "Cookies, Authorization headers, API keys, tokens and passwords go into the file as recorded, as do bodies that aren't text. Anyone with the file can use them.",
        "Keep secrets",
        "Cancel",
      ))
    )
      return;
    let chosen: { path: string; overwrite: boolean } | null;
    try {
      chosen = await chooseSave(`${name}-traffic.har`, "HAR", "har");
    } catch (e: any) {
      return app.toast(e.message, "error");
    }
    if (!chosen) return;
    const { path, overwrite } = chosen;
    try {
      const r = await run<ExportResult>(exportArgs(filter, o, path, overwrite));
      app.toast(exportNote(r));
      if (inTauri) {
        const { revealItemInDir } = await import("@tauri-apps/plugin-opener");
        await revealItemInDir(r.path).catch(() => {});
      }
    } catch (e: any) {
      app.toast(saveFailure(e, path), "error");
    }
  };

  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && close()}>
      <form
        ref={box}
        className="confirm-dialog export-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="export-title"
        aria-describedby="export-help"
        onSubmit={(e) => {
          e.preventDefault();
          go();
        }}
      >
        <h2 id="export-title">Export traffic as HAR</h2>
        <p id="export-help">
          Every request the current filter matches ({shown.toLocaleString("en-US")} shown now, more if not all are loaded), oldest first, up to{" "}
          {EXPORT_LIMIT.toLocaleString("en-US")}. Browsers, Burp, ZAP and <code>import har</code> read it. Session secrets are masked, as in reports.
        </p>
        <label className="check">
          <input type="checkbox" checked={o.keepSecrets} onChange={(e) => setO({ ...o, keepSecrets: e.target.checked })} /> Keep secrets as recorded
        </label>
        <label className="export-mask">
          <span>Also mask these values (one per line, at least {MIN_MASK} characters)</span>
          <textarea
            className="input multiline mono full"
            rows={3}
            spellCheck={false}
            disabled={o.keepSecrets}
            value={o.mask}
            onChange={(e) => setO({ ...o, mask: e.target.value })}
            aria-invalid={!!problem}
            aria-errormessage={problem ? "export-problem" : undefined}
          />
        </label>
        {problem && (
          <p id="export-problem" className="export-problem" role="alert">
            {problem}
          </p>
        )}
        <div className="row gap">
          <span className="grow" />
          <button type="button" className="btn" onClick={close}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={!!problem}>
            Export…
          </button>
        </div>
      </form>
    </div>
  );
}
