// Proof-of-concept pages (`poc csrf`, `poc clickjacking`): the CLI arguments the dialog runs,
// what it says about the page, and where "Open in browser" writes it. The page is the CLI's
// HTML; the app shows it as text and never renders it.

/** Where the request comes from: a recorded one, or a Replay tab's piped with `--file -`. */
export type PocSource = { historyId: number } | { raw: string; target: string; binary?: boolean };

export type PocKind = "csrf" | "clickjacking";
export type Technique = "form" | "fetch";

export interface CsrfSettings {
  technique: Technique;
  autoSubmit: boolean;
  /** Parameter names to leave out, as typed: comma- or space-separated. */
  drop: string;
}

export interface ClickjackingSettings {
  opacity: number;
  decoy: string;
}

export const DEFAULT_CSRF: CsrfSettings = { technique: "form", autoSubmit: false, drop: "" };
export const DEFAULT_CLICKJACKING: ClickjackingSettings = { opacity: 0.5, decoy: "Click me" };

export interface PocField {
  name: string;
  value: string;
  filename?: string;
}

/** `poc csrf`'s data. */
export interface CsrfPage {
  kind: "csrf";
  history_id: number | null;
  method: string;
  action: string;
  encoding: "query" | "urlencoded" | "multipart" | "json" | "text";
  technique: Technique;
  fields: PocField[];
  auto_submit: boolean;
  warnings: string[];
  html: string;
  path: string | null;
}

/** `poc clickjacking`'s data. */
export interface ClickjackingPage {
  kind: "clickjacking";
  history_id: number | null;
  url: string;
  framing: { x_frame_options: string | null; frame_ancestors: string | null; blocked: boolean | null };
  warnings: string[];
  html: string;
  path: string | null;
}

export type PocPage = CsrfPage | ClickjackingPage;

/** The names in the "leave out" box, each once. */
export function dropNames(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).filter(Boolean))];
}

function sourceArgs(source: PocSource, kind: PocKind): string[] {
  if ("historyId" in source) return ["--history-id", String(source.historyId)];
  // A clickjacking page frames a URL: the tab's request line on its target.
  if (kind === "clickjacking") return ["--url", tabUrl(source.raw, source.target)];
  return ["--file", "-", "--target", source.target];
}

/** The URL a Replay tab's request goes to: its absolute request target, or the target and the path. */
export function tabUrl(raw: string, target: string): string {
  const line = raw.split(/\r?\n/, 1)[0] ?? "";
  const path = line.trim().split(/\s+/)[1] ?? "/";
  if (/^https?:\/\//i.test(path)) return path;
  return target.replace(/\/+$/, "") + (path.startsWith("/") ? path : `/${path}`);
}

/** The opacity as the CLI takes it, kept to 0..1. */
export function opacityArg(v: number): string {
  const n = Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : DEFAULT_CLICKJACKING.opacity;
  return String(Math.round(n * 100) / 100);
}

/** The CLI arguments for a page; `output` writes it to that file too (`overwrite`: `--force`). */
export function pocArgs(
  kind: PocKind,
  source: PocSource,
  settings: { csrf: CsrfSettings; clickjacking: ClickjackingSettings },
  output?: { path: string; overwrite: boolean },
): string[] {
  const args = ["poc", kind, ...sourceArgs(source, kind)];
  if (kind === "csrf") {
    const c = settings.csrf;
    if (c.technique !== "form") args.push("--technique", c.technique);
    if (c.autoSubmit) args.push("--auto-submit");
    for (const name of dropNames(c.drop)) args.push(`--drop-param=${name}`);
  } else {
    const c = settings.clickjacking;
    args.push("--opacity", opacityArg(c.opacity));
    // `=`: a decoy text starting with "-" is still the value.
    args.push(`--decoy=${c.decoy || DEFAULT_CLICKJACKING.decoy}`);
  }
  if (output) args.push("--output", output.path, ...(output.overwrite ? ["--force"] : []));
  return args;
}

/** Whether the request goes on stdin (a Replay tab's, for a CSRF page). */
export function readsStdin(kind: PocKind, source: PocSource): boolean {
  return kind === "csrf" && !("historyId" in source);
}

/** The file name Save… suggests. */
export function defaultName(kind: PocKind, source: PocSource): string {
  const id = "historyId" in source ? `-${source.historyId}` : "";
  return `${kind}-poc${id}.html`;
}

/** A line about the page above its warnings. */
export function summary(page: PocPage): string {
  if (page.kind === "csrf") {
    const how = page.technique === "fetch" ? "a script (fetch)" : "a form";
    return `Sends ${page.method} ${page.action} from ${how}, with the visitor's cookies${page.auto_submit ? ", as soon as the page opens" : ""}.`;
  }
  const f = page.framing;
  const why = f.frame_ancestors != null ? `frame-ancestors ${f.frame_ancestors}` : f.x_frame_options != null ? `X-Frame-Options: ${f.x_frame_options}` : "";
  if (f.blocked == null) return `Frames ${page.url}. No response is recorded for it, so whether it may be framed is unknown.`;
  return f.blocked ? `Frames ${page.url}, but its response says it can't be framed (${why}).` : `Frames ${page.url}${why ? ` (${why} allows it)` : ", which sets no framing protection"}.`;
}

/** What the confirmation before "Open in browser" says. */
export function openWarning(kind: PocKind): string {
  return kind === "csrf"
    ? "Opening the page sends the request from your browser, with its cookies for the site, straight to the target: not through brainproxy and its scope checks (unless the browser uses the proxy)."
    : "Opening the page loads the URL in a frame from your browser, with its cookies for the site, straight from the target: not through brainproxy and its scope checks (unless the browser uses the proxy).";
}

/**
 * The file "Open in browser" writes in the temporary folder: a new name each time (the CLI
 * never replaces it), matching the opener permission `$TEMP/brainproxy-poc-*.html`.
 */
export function tempName(kind: PocKind, random: () => number = Math.random): string {
  const id = Math.floor(random() * 2 ** 48).toString(36).padStart(10, "0");
  return `brainproxy-poc-${kind}-${id}.html`;
}

/** `dir` and `name` joined with the folder's own separator. */
export function joinPath(dir: string, name: string): string {
  const sep = dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}
