// Alert filters in Findings (`findings filter add|list|remove`): an alert, on a host or any host,
// maybe only under a path, for a parameter, or by URL or parameter regex, gets the risk and/or
// confidence a person gives it wherever a scan finds it, now and later. The CLI does the matching
// and rating; this builds its arguments and says what it did.

import type { FindingItem, Risk } from "../api.ts";
import { draftFor, matchPath } from "./suppression.ts";

/** A filter, as `findings filter list` gives it. */
export interface AlertFilterRow {
  id: number;
  time: string;
  alert_ref: string;
  /** Lowercased, without its port (see `port`); null for any host. */
  host: string | null;
  port: number | null;
  /** "" for every path. */
  path_prefix: string;
  url_regex: string | null;
  param: string | null;
  param_regex: string | null;
  /** What it gives; null keeps the scanner's. */
  risk: Risk | null;
  confidence: string | null;
  reason: string;
  by?: string;
  origin: string | null;
  /** How many findings still have its rating. */
  holds: number;
}

export interface AlertFilterList {
  count: number;
  filters: AlertFilterRow[];
}

/** The fields of the Re-rate future findings… dialog, as typed. "" for risk or confidence keeps the scanner's. */
export interface FilterDraft {
  alert: string;
  host: string;
  pathPrefix: string;
  urlRegex: string;
  param: string;
  paramRegex: string;
  risk: "" | Risk;
  confidence: "" | "high" | "medium" | "low";
  reason: string;
}

export const FILTER_LIST_ARGS = ["findings", "filter", "list"];

/**
 * A filter for one finding as a start: its alert, its host and port (the scheme's default too,
 * so a filter made on one service doesn't re-rate another's findings unasked), its URL's path
 * and its parameter, and no rating yet: the person picks it, and widens the rest from there
 * (clearing the host for every host, cutting the path back to a directory).
 */
export function filterDraftFor(f: Pick<FindingItem, "alert_ref" | "host" | "url" | "param">): FilterDraft {
  const d = draftFor(f);
  return { alert: d.alert, host: d.host, pathPrefix: d.pathPrefix, urlRegex: "", param: d.param, paramRegex: "", risk: "", confidence: "", reason: "" };
}

/** Why the draft can't be added yet (the CLI's own checks, said before it runs); null when it can. */
export function filterDraftProblem(d: FilterDraft): string | null {
  const host = d.host.trim();
  const prefix = d.pathPrefix.trim();
  if (!d.alert.trim()) return "Give the alert ref or rule id it re-rates";
  if (host && /[/\s@?#]/.test(host)) return "The host is a name such as app.test, 127.0.0.1:3000 for that port only, or empty for any host";
  if (prefix && !prefix.startsWith("/")) return "A path prefix starts with /";
  if (/[?#]/.test(prefix)) return "A path prefix is part of the path: no ? or #; match a query with the URL regex";
  for (const [what, src] of [
    ["URL regex", d.urlRegex],
    ["parameter regex", d.paramRegex],
  ] as const) {
    if (src.trim().length > 1000) return `The ${what} is at most 1000 characters`;
  }
  if (!d.risk && !d.confidence) return "Pick the risk and/or confidence it gives";
  if (!d.reason.trim()) return "Give the reason: it becomes the rating reason of each finding the filter rates";
  return null;
}

/**
 * `findings filter add` for the draft. Values go as `--flag=value`, so one that starts with "-"
 * (a reason, a regex) isn't read as a flag. An empty host, path, parameter or regex matches any.
 * A typed path goes as the CLI matches paths (`matchPath`). Regexes go as typed: the CLI checks
 * them, with its own syntax.
 */
export function filterAddArgs(d: FilterDraft): string[] {
  const args = ["findings", "filter", "add", `--alert=${d.alert.trim()}`];
  const host = d.host.trim();
  if (host) args.push(`--host=${host}`);
  const prefix = d.pathPrefix.trim();
  if (prefix) args.push(`--path-prefix=${matchPath(prefix)}`);
  if (d.urlRegex.trim()) args.push(`--url-regex=${d.urlRegex.trim()}`);
  // Trimmed: the CLI matches a parameter exactly, so a stray space would make a filter that never matches.
  const param = d.param.trim();
  if (param) args.push(`--param=${param}`);
  if (d.paramRegex.trim()) args.push(`--param-regex=${d.paramRegex.trim()}`);
  if (d.risk) args.push(`--risk=${d.risk}`);
  if (d.confidence) args.push(`--confidence=${d.confidence}`);
  args.push(`--reason=${d.reason.trim()}`);
  return args;
}

export function filterRemoveArgs(id: number, unrate: boolean): string[] {
  return ["findings", "filter", "remove", String(id), ...(unrate ? ["--unrate"] : [])];
}

/** Where a filter applies, as one line: `any host/static/ · URL ~ \.js$ · parameter id`. */
export function filterWhere(r: Pick<AlertFilterRow, "host" | "port" | "path_prefix" | "url_regex" | "param" | "param_regex">): string {
  let where: string;
  if (r.host == null) where = r.path_prefix ? `any host, ${r.path_prefix}` : "any host";
  else {
    // An IPv6 address is bracketed once a port follows it, as in a URL.
    const name = r.port != null && r.host.includes(":") && !r.host.startsWith("[") ? `[${r.host}]` : r.host;
    where = `${name}${r.port != null ? `:${r.port}` : ""}${r.path_prefix}`;
  }
  const parts = [where];
  if (r.url_regex) parts.push(`URL ~ ${r.url_regex}`);
  if (r.param) parts.push(`parameter ${r.param}`);
  if (r.param_regex) parts.push(`parameter ~ ${r.param_regex}`);
  return parts.join(" · ");
}

/** What a filter gives: "risk info, confidence low", or one of them. */
export function filterRating(r: Pick<AlertFilterRow, "risk" | "confidence">): string {
  return [r.risk && `risk ${r.risk}`, r.confidence && `confidence ${r.confidence}`].filter(Boolean).join(", ");
}

const findings = (n: number) => `${n} finding${n === 1 ? "" : "s"}`;

/**
 * What to say once a filter is added. `from`: the finding it was made from, read again after,
 * when the filter left it as it was (someone rated it, or it is triaged), so it says why.
 */
export function filterAddedNote(id: number, rated: number, from?: (Pick<FindingItem, "id" | "state"> & { rated_origin?: string | null; rated_by?: number | null }) | null): string {
  const said = rated
    ? `Alert filter ${id} added: it re-rated ${findings(rated)}.`
    : `Alert filter ${id} added. No open finding nobody rated matched it yet; it re-rates the ones scans find from now on.`;
  if (!from || from.rated_by === id) return said;
  const why =
    from.rated_by != null
      ? `filter ${from.rated_by} rated it first`
      : from.rated_origin
        ? "it has a person's rating, which a filter leaves alone"
        : from.state !== "open"
          ? `it is ${from.state.replace(/_/g, " ")}`
          : "the filter doesn't match it";
  return `${said} Finding #${from.id} keeps its rating: ${why}.`;
}

/** What to say once a filter is removed. `held`: how many findings had its rating when it was removed. */
export function filterRemovedNote(id: number, unrated: number, unrate: boolean, held: number): string {
  if (unrate) return `Alert filter ${id} removed: ${findings(unrated)} ${unrated === 1 ? "has" : "have"} the scanner's rating again.`;
  if (!held) return `Alert filter ${id} removed.`;
  return `Alert filter ${id} removed. The ${held === 1 ? "finding it rated keeps" : `${held} findings it rated keep`} its rating.`;
}

/** The filters dialog's opening line: what the filters hold, or how to make one. */
export function filtersSummary(filters: readonly Pick<AlertFilterRow, "holds">[]): string {
  if (!filters.length) return "No alert filters yet. Open a scanner's finding and choose Re-rate future findings… to make one.";
  const n = filters.reduce((s, f) => s + f.holds, 0);
  return `${findings(n)} ${n === 1 ? "has" : "have"} a rating from these filters. When several match a new finding, the oldest rates it; a suppression rule, or a rating of its whole issue, comes first.`;
}

/** Whether a finding can start a filter: a scanner's finding, since a filter leaves findings added by hand alone. */
export const canFilter = (f: Pick<FindingItem, "source" | "state">) => f.source !== "manual" && f.state !== "removed";
