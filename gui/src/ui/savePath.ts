// Where a file the app writes goes, and whether the CLI may replace one already there
// (`--force`): only when the operating system's save dialog asked about that very file.

/**
 * The file to write for what was chosen: `ext` is added when the name lacks it. `asked`: the
 * save dialog asked about replacing `chosen` (a path typed in the browser build was never
 * asked about). A name the app extended was not asked about either, so it isn't replaced.
 */
export function savePath(chosen: string, ext: string, asked: boolean): { path: string; overwrite: boolean } {
  const has = chosen.toLowerCase().endsWith(`.${ext.toLowerCase()}`);
  return { path: has ? chosen : `${chosen}.${ext}`, overwrite: asked && has };
}
