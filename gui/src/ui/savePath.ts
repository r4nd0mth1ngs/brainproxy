// Where a file the app writes goes, and whether the CLI may replace one already there
// (`--force`): only when the operating system's save dialog asked about that very file.

import { inTauri } from "../api";
import { ask } from "./Confirm";

/**
 * The file to write for what was chosen: `ext` is added when the name lacks it. `asked`: the
 * save dialog asked about replacing `chosen` (a path typed in the browser build was never
 * asked about). A name the app extended was not asked about either, so it isn't replaced.
 */
export function savePath(chosen: string, ext: string, asked: boolean): { path: string; overwrite: boolean } {
  const has = chosen.toLowerCase().endsWith(`.${ext.toLowerCase()}`);
  return { path: has ? chosen : `${chosen}.${ext}`, overwrite: asked && has };
}

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
