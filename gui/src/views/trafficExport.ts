// Proxy › Traffic › Export: the rows the Traffic filter shows, as a HAR file (`history export
// har`). Traffic applies part of its filter here (the URL text, sources, checkboxes) and part
// in the CLI (a contents search or a query); the export asks the CLI for all of it at once, as
// one query in the filter language, so it covers every matching row, not only those loaded.

import type { TrafficFilter } from "./trafficFilter";

/** Rows per export, oldest first; the CLI says `truncated` when more matched. */
export const EXPORT_LIMIT = 5000;

/** The shortest value `--mask` takes, in characters (after trimming). */
export const MIN_MASK = 6;

export interface ExportOptions {
  /** Keep cookies, credentials and tokens as recorded (`--no-redact`). */
  keepSecrets: boolean;
  /** More values to mask wherever they appear (`--mask`), one per line. */
  mask: string;
}

export const DEFAULT_EXPORT: ExportOptions = { keepSecrets: false, mask: "" };

/** A value in double quotes, as the filter language reads it (\" and \\ inside). */
export const quoted = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/** `s` as literal text inside a regex. */
const regexLiteral = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The asset paths Traffic's "Hide static assets" hides; trafficFilter.ts tests the same. */
const ASSET_REGEX = "(?i)\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\\?|$)";

/**
 * Whether a query's parentheses pair up (outside quoted values). One that doesn't would join
 * the other terms differently once wrapped in ( ), so the export refuses it.
 */
export function balanced(query: string): boolean {
  let depth = 0;
  let quote = false;
  for (let i = 0; i < query.length; i++) {
    const c = query[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === '"') quote = false;
    } else if (c === '"') quote = true;
    else if (c === "(") depth++;
    else if (c === ")" && --depth < 0) return false;
  }
  return depth === 0 && !quote;
}

/**
 * The filter-language query for what `matchesFilter` checks here (the URL text, sources and
 * checkboxes), with a query typed in Traffic's Query mode ANDed in front. Empty: no query.
 */
export function exportQuery(f: TrafficFilter): string {
  const terms: string[] = [];
  if (f.query && f.text.trim()) terms.push(`(${f.text})`);
  if (!f.query && !f.contents && f.text) {
    // Traffic matches the URL or title containing the text in any case, or the method equal to it.
    const t = f.text.toLowerCase();
    terms.push(`(url:${quoted(t)} OR title:${quoted(t)} OR method~${quoted(`(?i)^${regexLiteral(t)}$`)})`);
  }
  if (f.sources.length) terms.push(`(${f.sources.map((s) => `source=${quoted(s)}`).join(" OR ")})`);
  if (f.hideErrors) terms.push("status<400");
  if (f.hideAssets) terms.push(`NOT url~${quoted(ASSET_REGEX)}`);
  if (f.hideRefused) terms.push(`NOT error~${quoted("^out of scope")}`);
  return terms.join(" AND ");
}

/** The mask values, one per line, blank lines dropped. */
export const maskValues = (mask: string) =>
  mask
    .split("\n")
    .map((v) => v.trim())
    .filter(Boolean);

/** Why the export can't run as set, or null. */
export function exportProblem(f: TrafficFilter, o: ExportOptions): string | null {
  if (f.query && f.text.trim() && !balanced(f.text)) return "The query's parentheses or quotes don't pair up; fix it to export what it shows.";
  // Kept as recorded, nothing is masked: the values are left out (see exportArgs).
  if (o.keepSecrets) return null;
  const short = maskValues(o.mask).find((v) => [...v].length < MIN_MASK);
  if (short != null) return `A value to mask has at least ${MIN_MASK} characters: ${short}`;
  return null;
}

/**
 * `history export har` for the filter, written to `path`. `overwrite` passes --force: only
 * when the save dialog itself asked about replacing that very file.
 */
export function exportArgs(f: TrafficFilter, o: ExportOptions, path: string, overwrite: boolean): string[] {
  const query = exportQuery(f);
  const contains = f.contents && !f.query && f.text.trim() ? [`--contains=${f.text}`] : [];
  return [
    "history",
    "export",
    "har",
    ...contains,
    ...(query ? [`--filter=${query}`] : []),
    `--limit=${EXPORT_LIMIT}`,
    ...(o.keepSecrets ? ["--no-redact"] : maskValues(o.mask).map((v) => `--mask=${v}`)),
    `--output=${path}`,
    ...(overwrite ? ["--force"] : []),
  ];
}

/** The file to write: the dialog's path, with .har added when it has no such extension. */
export function harPath(chosen: string): { path: string; overwrite: boolean } {
  if (/\.har$/i.test(chosen)) return { path: chosen, overwrite: true };
  // The dialog asked about `chosen`, not this name: an existing file here is refused, not replaced.
  return { path: `${chosen}.har`, overwrite: false };
}

/** What `history export` answers with --output. */
export interface ExportResult {
  entries: number;
  truncated: boolean;
  /** Places a secret was masked; null with --no-redact. */
  redacted: number | null;
  binary_bodies_left_out: number;
  path: string;
}

/** The toast after an export. */
export function exportNote(r: ExportResult): string {
  const parts = [`Exported ${r.entries} request${r.entries === 1 ? "" : "s"} to ${r.path}.`];
  if (r.truncated) parts.push(`Only the oldest ${EXPORT_LIMIT.toLocaleString("en-US")} that match: narrow the filter to export later ones.`);
  if (r.redacted == null) parts.push("Secrets are kept as recorded.");
  else if (r.redacted) parts.push(`Session secrets are masked in ${r.redacted} place${r.redacted === 1 ? "" : "s"}.`);
  if (r.binary_bodies_left_out) parts.push(`${r.binary_bodies_left_out} binary bod${r.binary_bodies_left_out === 1 ? "y was" : "ies were"} left out.`);
  return parts.join(" ");
}
