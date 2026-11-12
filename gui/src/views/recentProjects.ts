// The Recent projects list's paths: which of them the app may open. Welcome and the command
// palette both offer them, so both go by the same check.

const WINDOWS = () => typeof navigator !== "undefined" && navigator.userAgent.includes("Windows");

/**
 * Whether `path` is a full path. The CLI resolves a relative path against wherever it was
 * started (the dev server's folder), so only a full one opens the project it names. On Windows
 * "/foo" is relative to the current drive, so only a drive letter or UNC path counts.
 */
export const isAbsolute = (path: string, windows: boolean = WINDOWS()) =>
  (windows ? /^([a-z]:[\\/]|\\\\)/i : /^\//).test(path);

/** The recent projects to offer for opening: full paths only, without the one open now. */
export const openableRecents = (recent: string[], open: string | null | undefined, windows: boolean = WINDOWS()) =>
  recent.filter((p) => p !== open && isAbsolute(p, windows));
