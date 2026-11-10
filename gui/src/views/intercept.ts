// Proxy › Intercept and Settings › Intercept options: the intercept settings, the `intercept
// enable` call that sets them, and the filter that picks which messages are held, a query in
// the Traffic filter language (`intercept enable --filter`) that can start from a saved filter.

import type { SavedFilter } from "./trafficFilter";

export interface InterceptSettings {
  enabled: boolean;
  requests: boolean;
  responses: boolean;
  ws_to_server?: boolean;
  ws_to_client?: boolean;
  host?: string;
  path?: string;
  method?: string;
  /** A query in the filter language; left out when there is none. */
  filter?: string;
  timeout_secs: number;
  timeout_action: string;
}

/** `intercept enable` arguments for these settings. Enable replaces every setting, so the
 * filters are passed back each time or they would be cleared. */
export function interceptEnableArgs(s: InterceptSettings): string[] {
  // `--flag=value`: a value starting with `-` (a query such as `-x`) isn't read as a flag.
  const opt = (flag: string, v?: string) => (v ? [`${flag}=${v}`] : []);
  return [
    "intercept",
    "enable",
    ...(s.requests ? ["--requests"] : []),
    ...(s.responses ? ["--responses"] : []),
    ...(s.ws_to_server ? ["--ws-to-server"] : []),
    ...(s.ws_to_client ? ["--ws-to-client"] : []),
    ...opt("--host", s.host),
    ...opt("--path", s.path),
    ...opt("--method", s.method),
    ...opt("--filter", s.filter?.trim()),
    "--timeout",
    String(s.timeout_secs),
    "--timeout-action",
    s.timeout_action,
  ];
}

/** The settings with `filter` as the intercept's filter: trimmed, and none when empty. */
export function withFilter(s: InterceptSettings, filter: string): InterceptSettings {
  const { filter: _, ...rest } = s;
  const text = filter.trim();
  return text ? { ...rest, filter: text } : rest;
}

/** Whether `text` would change the filter in `s` (spaces around it don't count). */
export const filterChanged = (s: InterceptSettings, text: string) => (s.filter ?? "").trim() !== text.trim();

/**
 * The saved Traffic filters the intercept can take: those in Query mode with a query. Their
 * sources and checkboxes are Traffic's own and don't carry over; a URL or contents search isn't
 * in the filter language.
 */
export function savedQueries(list: SavedFilter[]): { name: string; text: string }[] {
  return list.filter((s) => s.filter.query && s.filter.text.trim()).map((s) => ({ name: s.name, text: s.filter.text.trim() }));
}

/** The saved query whose text is `text`, if one is. */
export const savedQueryFor = (list: { name: string; text: string }[], text: string) => list.find((s) => s.text === text.trim())?.name ?? null;

export const INTERCEPT_FILTER_HELP =
  "Hold only messages matching a query in the Traffic filter language (Query mode), e.g. method=POST NOT path:/static. " +
  "A request is matched by itself, a response by the request sent and the response, a WebSocket message by its handshake request. " +
  "Response fields (status, length, duration, title, type, resp, resp.body, body, resp.header.NAME) work only when only responses are held; " +
  "id, error, note and tag never do. Host, path and method above still apply. Runs intercept enable --filter.";
