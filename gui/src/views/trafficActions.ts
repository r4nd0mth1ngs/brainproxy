// Traffic's right-click actions on recorded requests: an active scan of them, the highlight tag,
// and what Access is handed to test them as other users.

import { isRefused } from "./trafficFilter.ts";

/** A recorded request picked in Traffic. */
export interface HistoryPick {
  id: number;
  method: string;
  url: string;
  /** It carries a GraphQL mutation (`isMutationRequest` on the recorded request), when that was checked. */
  mutation?: boolean;
}

const SAFE = ["GET", "HEAD", "OPTIONS"];

/** Methods among the picks other than GET, HEAD and OPTIONS (each once, upper case): replaying them can change data. */
export function unsafeMethods(picks: HistoryPick[]): string[] {
  return [...new Set(picks.map((p) => p.method.toUpperCase()).filter((m) => !SAFE.includes(m)))];
}

/**
 * What among the picks can change data, each once: "GraphQL mutation" for a mutation, whatever
 * its method (it travels as POST, or even GET), then the other methods `unsafeMethods` names.
 */
export function changeKinds(picks: HistoryPick[]): string[] {
  const mutation = picks.some((p) => p.mutation) ? ["GraphQL mutation"] : [];
  return [...mutation, ...unsafeMethods(picks.filter((p) => !p.mutation))];
}

/**
 * Logout-like paths, as `authz run --exclude` leaves them alone by default (`DEFAULT_EXCLUDE` in
 * crates/core/src/authz/mod.rs). Sending one ends the session it carries.
 */
export const LOGOUT = /(log|sign)[-_]?(out|off)\b/i;

/**
 * The pick's path looks like a logout. The path is taken as recorded (the URL is the origin plus
 * the request target), without the query and not normalised, as `authz run` matches it: a URL
 * parser would turn `/logout/../account` into `/account`.
 */
export function isLogout(p: HistoryPick): boolean {
  const target = p.url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?]*/i, "");
  return LOGOUT.test(target.split("?")[0]);
}

/** What a raw request carries of GraphQL, as `graphql::read` reads it. */
interface GraphqlRead {
  documents: string[];
  /**
   * An operation sent without its document (a persisted query's hash, a `doc_id`, an `id` with
   * `operationName` or `variables`), or a body this view can't decode at a GraphQL-looking
   * request: it can't be shown to be read-only.
   */
  unproven: boolean;
}

/** One operation: its `query`, or, without one, whether it names a document the server keeps. */
function readOperation(v: unknown, out: GraphqlRead) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return;
  const o = v as Record<string, unknown>;
  if (typeof o.query === "string") {
    out.documents.push(o.query);
    return;
  }
  const ext = o.extensions;
  const persisted = !!ext && typeof ext === "object" && "persistedQuery" in ext;
  const id = "id" in o && ("operationName" in o || "variables" in o);
  if (persisted || "doc_id" in o || "documentId" in o || id) out.unproven = true;
}

/** A JSON body or batch: each operation's `query`. */
function readJson(body: string, out: GraphqlRead) {
  try {
    const v: unknown = JSON.parse(body);
    if (Array.isArray(v)) v.forEach((op) => readOperation(op, out));
    else readOperation(v, out);
  } catch {
    // Not JSON: no documents in the body.
  }
}

/** URL or form parameters: `query`, or an operation named by `extensions`, `doc_id` or `id`. */
function readForm(params: string, out: GraphqlRead) {
  const op: Record<string, unknown> = {};
  for (const [k, v] of new URLSearchParams(params)) {
    if (k === "query") {
      out.documents.push(v);
      continue;
    }
    // `extensions` and `variables` travel as JSON in a parameter.
    let value: unknown = v;
    if (k === "extensions" || k === "variables") {
      try {
        value = JSON.parse(v);
      } catch {
        // Kept as text.
      }
    }
    op[k] = value;
  }
  if (Object.keys(op).length) readOperation(op, out);
}

/** The body without its chunked framing, or null when the framing is broken. */
function dechunk(body: string): string | null {
  let [out, at] = ["", 0];
  for (;;) {
    const eol = body.indexOf("\r\n", at);
    if (eol < 0) return null;
    const size = parseInt(body.slice(at, eol).split(";")[0].trim(), 16);
    if (Number.isNaN(size)) return null;
    if (size === 0) return out;
    out += body.slice(eol + 2, eol + 2 + size);
    at = eol + 2 + size + 2;
  }
}

/**
 * What a raw request carries of GraphQL, as `graphql::documents` and `is_mutation_request` read
 * it: `query` URL parameters, an `application/graphql` body, the `query` of a JSON body or batch,
 * the `operations` field of a multipart upload, or the `query` of a form body. Chunked framing is
 * removed; a Content-Encoding is not (the Rust side removes gzip, deflate and br), so such a body
 * counts as unproven at a GraphQL-looking request or when the word `mutation` appears in it. Like
 * the scanner's parser, it needs CRLF line endings and the blank line ending the head.
 */
function readGraphql(raw: string): GraphqlRead {
  const out: GraphqlRead = { documents: [], unproven: false };
  const sep = raw.indexOf("\r\n\r\n");
  if (sep < 0) return out;
  let body = raw.slice(sep + 4);
  const [line = "", ...headers] = raw.slice(0, sep).split("\r\n");
  const target = line.split(" ")[1] ?? "";
  const q = target.indexOf("?");
  if (q >= 0) readForm(target.slice(q + 1), out);
  // Every value of a header, as sent (any one saying so counts, as on the Rust side).
  const header = (name: string) =>
    headers.filter((h) => h.includes(":") && h.slice(0, h.indexOf(":")).trim().toLowerCase() === name).map((h) => h.slice(h.indexOf(":") + 1).trim());
  const typeValues = header("content-type");
  const types = typeValues.map((t) => t.toLowerCase());
  const encoded = header("content-encoding").some((v) => v.split(",").some((c) => !["", "identity"].includes(c.trim().toLowerCase())));
  const chunked = header("transfer-encoding").some((v) => /chunked/i.test(v));
  const dechunked = chunked ? dechunk(body) : body;
  if (encoded || dechunked === null) {
    // Not readable here: at a GraphQL-looking request, or naming a mutation, it may be one.
    const looks = types.some((t) => t.includes("graphql")) || /graphql/i.test(target) || out.documents.length > 0;
    out.unproven ||= looks || /\bmutation\b/.test(body);
    return out;
  }
  body = dechunked;
  if (types.some((t) => t.includes("application/graphql"))) {
    out.documents.push(body);
  } else if (types.some((t) => t.startsWith("multipart/form-data"))) {
    // A file upload (the GraphQL multipart request spec): the operation is in `operations`.
    const boundary = /;\s*boundary="?([^";]+)"?/i.exec(typeValues.find((t) => /^multipart\/form-data/i.test(t)) ?? "")?.[1];
    for (const part of boundary ? body.split(`--${boundary}`) : []) {
      const end = part.indexOf("\r\n\r\n");
      if (end >= 0 && /^content-disposition:.*\bname="operations"/im.test(part.slice(0, end))) readJson(part.slice(end + 4).replace(/\r\n$/, ""), out);
    }
  } else if (types.some((t) => t.startsWith("application/x-www-form-urlencoded"))) {
    readForm(body, out);
  } else {
    readJson(body, out);
  }
  return out;
}

/** The GraphQL documents a raw request carries, as `graphql::documents` reads them (see `readGraphql`). */
export function graphqlDocuments(raw: string): string[] {
  return readGraphql(raw).documents;
}

/**
 * Whether a GraphQL document defines a mutation, as `graphql::defines_mutation` decides: strings
 * and comments are skipped, and a definition is one when its first word at the top level says so.
 */
export function definesMutation(doc: string): boolean {
  let [i, depth, word, first] = [0, 0, "", true];
  // Ends the word being read; true when it opens a mutation.
  const endWord = () => {
    const mutation = depth === 0 && first && word === "mutation";
    if (depth === 0 && word) first = false;
    word = "";
    return mutation;
  };
  while (i < doc.length) {
    const c = doc[i];
    if (/[A-Za-z0-9_]/.test(c)) {
      word += c;
      i++;
      continue;
    }
    if (endWord()) return true;
    if (c === "#") {
      while (i < doc.length && doc[i] !== "\n") i++;
    } else if (doc.startsWith('"""', i)) {
      i += 3;
      while (i < doc.length && !doc.startsWith('"""', i)) i += doc[i] === "\\" ? 2 : 1;
      i += 2;
    } else if (c === '"') {
      i++;
      while (i < doc.length && doc[i] !== '"' && doc[i] !== "\n") i += doc[i] === "\\" ? 2 : 1;
    } else if ("{([".includes(c)) {
      depth++;
    } else if ("})]".includes(c)) {
      depth = Math.max(0, depth - 1);
      // The next definition starts.
      if (depth === 0 && c === "}") first = true;
    }
    i++;
  }
  return endWord();
}

/**
 * The raw request may carry a GraphQL mutation, which can change data whatever its method: a
 * document defines one, or an operation can't be shown to be read-only (see `readGraphql`), as
 * `graphql::is_mutation_request` decides. A request cut short (`truncated`, over the app's
 * --max-body) may no longer parse, so it is taken as one when the word appears anywhere in it:
 * the questions then ask rather than stay silent.
 */
export function isMutationRequest(raw: string, truncated = false): boolean {
  const read = readGraphql(raw);
  return read.unproven || read.documents.some(definesMutation) || (truncated && /\bmutation\b/.test(raw));
}

/** "alice", "alice and bob", "alice, bob and carol". */
function joinNames(names: string[]): string {
  return names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names.at(-1)}` : (names[0] ?? "");
}

/** Settings for a scan started from Traffic: the Scans view's defaults. */
export interface ScanDefaults {
  /** The Nuclei templates are downloaded (`checks status`). */
  nuclei: boolean;
}

/**
 * What `scan active --history-id` needs opted in to attack the picks: MUTATION for a GraphQL
 * mutation, whatever its method, and each other method besides GET, HEAD, OPTIONS and POST (which
 * it attacks by default). Empty when none needs it.
 */
export function scanOptIns(picks: HistoryPick[]): string[] {
  const mutation = picks.some((p) => p.mutation) ? ["MUTATION"] : [];
  return [...mutation, ...unsafeMethods(picks.filter((p) => !p.mutation)).filter((m) => m !== "POST")];
}

/**
 * What `authz run --history-id` needs to replay the picks: `--include-methods` with MUTATION for a
 * GraphQL mutation, whatever its method, and each method besides GET, HEAD and OPTIONS, and an
 * `--exclude` that matches no path when one looks like a logout. Empty when none needs either. A
 * mutation's method is opted in to too: read from a truncated request, a POST that only mentions
 * "mutation" is taken for one, and the CLI, which reads it whole, needs its POST then.
 */
export function authzOptIns(picks: HistoryPick[]): string[] {
  const mutation = picks.some((p) => p.mutation) ? ["MUTATION"] : [];
  const methods = [...mutation, ...unsafeMethods(picks)];
  return [...(methods.length ? [`--include-methods=${methods.join(",")}`] : []), ...(picks.some(isLogout) ? ["--exclude=^$"] : [])];
}

/**
 * `scan active` on these history entries, in the background, with the Scans view's defaults:
 * medium strength and, once the Nuclei templates are downloaded, those of high severity and up
 * plus the end-of-life checks. A pick that can change data is opted in to (`scanOptIns`) only
 * once the user said yes to `scanConfirm`; without that, the scanner refuses it and sends nothing.
 */
export function scanArgs(picks: HistoryPick[], d: ScanDefaults, confirmed = false): string[] {
  if (!picks.length) throw new Error("No request picked");
  return [
    "scan",
    "active",
    ...picks.map((p) => `--history-id=${p.id}`),
    "--strength=medium",
    ...optInArgs(picks, confirmed),
    ...(d.nuclei ? ["--checks=nuclei,brainproxy", "--check-include-tags=eol", "--check-severity=high"] : []),
    "--background",
  ];
}

/** `--include-methods` with what `scanOptIns` names, once the user said yes; nothing otherwise. */
function optInArgs(picks: HistoryPick[], confirmed: boolean): string[] {
  const optIns = confirmed ? scanOptIns(picks) : [];
  return optIns.length ? [`--include-methods=${optIns.join(",")}`] : [];
}

/**
 * The Site map's *Active scan this request*: `scan active --history-id` with the Site map's Nuclei
 * arguments, in the background. As from Traffic, a DELETE, PUT, PATCH or GraphQL mutation is
 * opted in to only once the user said yes to `scanConfirm`; the Site map asks only then
 * (`scanOptIns` not empty), as `scan active` attacks anything else by default.
 */
export function siteMapScanArgs(pick: HistoryPick, nucleiArgs: string[], confirmed = false): string[] {
  return ["scan", "active", "--history-id", String(pick.id), ...optInArgs([pick], confirmed), ...nucleiArgs, "--background"];
}

/**
 * The question asked before scanning the picks: what is attacked, that a POST or a GraphQL
 * mutation is replayed too, that a logout ends its session, and that the Nuclei templates also
 * reach other paths of the site.
 */
export function scanConfirm(picks: HistoryPick[], d: ScanDefaults): { title: string; message: string; ok: string; cancel: string } {
  const one = picks.length === 1;
  const what = one ? `${picks[0].method.toUpperCase()} ${picks[0].url}` : `${picks.length} requests`;
  const kinds = changeKinds(picks);
  const sideEffects = "that can change data or trigger side effects: one contact form can send a lot of emails.";
  const replay = !kinds.length
    ? ""
    : one
      ? ` It is replayed even though it is a ${kinds[0]}, and ${sideEffects}`
      : ` ${kinds.join(", ")} requests among them are replayed too, and ${sideEffects}`;
  const logouts = picks.filter(isLogout).length;
  const logout = !logouts
    ? ""
    : one
      ? " It looks like a logout: sending it again can end the session it was recorded with."
      : ` ${logouts === 1 ? "One of them looks" : `${logouts} of them look`} like a logout: sending ${logouts === 1 ? "it" : "them"} again can end the session ${logouts === 1 ? "it was" : "they were"} recorded with.`;
  // --include-methods also lets the templates send those methods (`check_methods`).
  const optIns = scanOptIns(picks).map((m) => (m === "MUTATION" ? "GraphQL mutation" : m));
  const templateOptIns = optIns.length ? ` Their ${optIns.join(", ")} requests are sent too.` : "";
  const nuclei = d.nuclei ? ` The downloaded Nuclei templates also run against ${one ? "its site" : "their sites"}, on paths of their own.${templateOptIns}` : "";
  return {
    title: one ? "Scan this request?" : `Scan ${picks.length} requests?`,
    message: `This sends real attack traffic to the site: ${what} ${one ? "is" : "are"} sent again with attack data, often many times.${replay}${logout}${nuclei} Every request stays inside the engagement scope.`,
    ok: "Start scan",
    cancel: "Cancel",
  };
}

/** What a row needs for the actions here: its status, and the proxy's error if any. */
export interface HistoryRow {
  status: number | null;
  error?: string | null;
}

/** Why a refused row's actions are disabled. */
export const REFUSED_HINT = "Out of scope: the proxy refused this request";

/**
 * Why a row can't be scanned, or null when it can. A scan needs the recorded response to compare
 * against, so a request that got none (a connection error, a timeout, dropped in Intercept) has
 * nothing to scan.
 */
export function scanBlocker(r: HistoryRow): string | null {
  if (isRefused(r)) return REFUSED_HINT;
  if (r.status == null) return "No response recorded to scan";
  return null;
}

/**
 * The question asked before an access-control run of requests picked in Traffic, or null when
 * none can change data or looks like a logout. Each is sent twice as its owner, then as each
 * identity and with no session: a POST or a GraphQL mutation can change data as another user, and
 * a logout can end those sessions, so later results may not be reliable.
 */
export function accessConfirm(
  picks: HistoryPick[],
  identities: string[],
  anonymous: boolean,
): { title: string; message: string; ok: string; cancel: string } | null {
  const kinds = changeKinds(picks);
  const logouts = picks.filter(isLogout);
  if (!kinds.length && !logouts.length) return null;
  const one = picks.length === 1;
  const others = [...(identities.length ? [`as ${joinNames(identities)}`] : []), ...(anonymous ? ["with no session"] : [])].join(" and ");
  const who = `twice as ${one ? "its owner" : "their owners"}${others ? `, then ${others}` : ""}`;
  const what = one ? `This ${kinds[0] ?? "request"}` : kinds.length ? `The ${kinds.join(", ")} requests` : `These ${picks.length} requests`;
  const change = kinds.length ? " That can change data or trigger side effects, now as another user." : "";
  const ends = "can end the owner's session and each identity's, so the results after it may not be reliable.";
  const logout = !logouts.length
    ? ""
    : one
      ? ` It looks like a logout: sending it ${ends}`
      : ` ${joinNames(logouts.map((p) => `#${p.id}`))} ${logouts.length === 1 ? "looks" : "look"} like a logout: sending ${logouts.length === 1 ? "it" : "them"} ${ends}`;
  return {
    title: one ? `Replay this ${kinds[0] ?? "logout"}?` : kinds.length ? "Replay requests that can change data?" : "Replay requests that look like logouts?",
    message: `${what} ${one ? "is" : "are"} sent again ${who}.${change}${logout} Every request stays inside the engagement scope.`,
    ok: "Start run",
    cancel: "Cancel",
  };
}

/** `history tag` adding or removing the highlight. */
export function highlightArgs(id: number, on: boolean): string[] {
  return ["history", "tag", String(id), on ? "--add" : "--remove", "highlight"];
}

/** A row's tags once the highlight is added or removed. */
export function withHighlight(tags: string[], on: boolean): string[] {
  return on ? [...new Set([...tags, "highlight"])] : tags.filter((t) => t !== "highlight");
}
