// Asks where to save a file the app writes. Apart from savePath.ts, which the tests load
// under Node: this one needs the app (Tauri or the in-window question).

import { inTauri } from "../api";
import { ask } from "./Confirm";
import { savePath } from "./savePath.ts";

/**
 * Asks where to save a file: the save dialog in the desktop app, its full path typed in the
 * browser build (the dev bridge). Null if cancelled.
 */
export async function chooseSave(defaultName: string, kind: string, ext: string): Promise<{ path: string; overwrite: boolean } | null> {
  if (inTauri) {
    const dialogs = await import("@tauri-apps/plugin-dialog");
    const p = await dialogs.save({ defaultPath: defaultName, filters: [{ name: kind, extensions: [ext] }] });
    return typeof p === "string" ? savePath(p, ext, true) : null;
  }
  const typed = (await ask(`Save the ${kind} file as`, "Its full path on this computer. A file already there is kept.", "Save", "Cancel", defaultName))?.trim();
  return typed ? savePath(typed, ext, false) : null;
}
