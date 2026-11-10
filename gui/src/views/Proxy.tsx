import { useEffect, useMemo, useRef, useState } from "react";
import { bodyText, CliError, cancelCli, historyRequest, hostOf, isBinary, MAX_BODY, pathOf, rawResponse, run, textBytes, type Body, type HistoryEntry, type HistoryItem } from "../api";
import { originOf, useApp, type Handoff } from "../store";
import { ask, confirm } from "../ui/Confirm";
import { copyAsCurl } from "../ui/CurlDialog";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Menu, useMenu } from "../ui/Menu";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import {
  appliedSaved,
  clearLocalSaved,
  DEFAULT_FILTER,
  failPage,
  FILTERS_LIST_ARGS,
  isCurrent,
  isRefused,
  loadSaved,
  modeOf,
  mergePage,
  needsSearch,
  newSearch,
  refilter,
  rerun,
  mergeLocal,
  deleteNamed,
  saveAs,
  saveChange,
  SavedMoved,
  savedFrom,
  searchArgs,
  searchFor,
  searchNote,
  visibleRows,
  withMode,
  usesEditableFields,
  type ContentSearch,
  type Cli,
  type SavedFilter,
  type SavedChange,
  type SavedState,
  type SearchMode,
  type SearchQuery,
  type TrafficFilter,
} from "./trafficFilter";
import { highlightArgs, isMutationRequest, REFUSED_HINT, scanArgs, scanBlocker, scanConfirm, withHighlight, type HistoryPick } from "./trafficActions";
import { EventStreams } from "./EventStreams";
import { ruleEditNote } from "./matchReplace.ts";
import { WebSockets } from "./WebSockets";
import { filterChanged, INTERCEPT_FILTER_HELP, interceptEnableArgs, savedQueries, savedQueryFor, withFilter, type InterceptSettings } from "./intercept";

export function ProxyView() {
  const app = useApp();
  const [sub, setSub] = useState<"history" | "intercept" | "ws" | "sse">("history");
  // Traffic opened from elsewhere (an import's requests).
  useEffect(() => {
    if (app.traffic) setSub("history");
  }, [app.traffic]);
  return (
    <div className="col fill">
      <div className="subtabs">
        <button className={sub === "intercept" ? "on" : ""} onClick={() => setSub("intercept")}>
          Intercept
        </button>
        <button className={sub === "history" ? "on" : ""} onClick={() => setSub("history")}>
          Traffic
        </button>
        <button className={sub === "ws" ? "on" : ""} onClick={() => setSub("ws")}>
          WebSockets
        </button>
        <button className={sub === "sse" ? "on" : ""} onClick={() => setSub("sse")}>
          Event streams
        </button>
      </div>
      <div className="fill" hidden={sub !== "history"}>
        <History />
      </div>
      <div className="fill" hidden={sub !== "intercept"}>
        <Intercept active={sub === "intercept"} />
      </div>
      <div className="fill" hidden={sub !== "ws"}>
        <WebSockets active={sub === "ws"} />
      </div>
      <div className="fill" hidden={sub !== "sse"}>
        <EventStreams active={sub === "sse"} />
      </div>
    </div>
  );
}

// ---------------- HTTP history ----------------

const statusClass = (s: number | null) => (s == null ? "s0" : s >= 500 ? "s5" : s >= 400 ? "s4" : s >= 300 ? "s3" : "s2");

/** Who or what recorded an entry, as the column shows it. */
const ORIGIN_LABEL: Record<string, string> = { gui: "app", cli: "CLI", mcp: "agent" };

const COLUMNS: Column<HistoryItem>[] = [
  { key: "id", label: "#", width: 56, value: (r) => r.id, align: "right" },
  { key: "host", label: "Host", width: 170, value: (r) => hostOf(r.url) },
  { key: "method", label: "Method", width: 64, value: (r) => r.method, render: (r) => <span className="method">{r.method}</span> },
  { key: "path", label: "URL", width: 340, value: (r) => pathOf(r.url) },
  {
    key: "status",
    label: "Status",
    width: 58,
    value: (r) => r.status,
    render: (r) => (r.error ? <span className="s5" title={r.error}>error</span> : <span className={statusClass(r.status)}>{r.status ?? "—"}</span>),
    align: "right",
  },
  { key: "length", label: "Length", width: 70, value: (r) => r.resp_body_length, align: "right" },
  { key: "mime", label: "MIME", width: 110, value: (r) => (r.resp_content_type ?? "").split(";")[0] },
  { key: "title", label: "Title", width: 180, value: (r) => r.title },
  { key: "source", label: "Source", width: 70, value: (r) => r.source },
  {
    key: "origin",
    label: "By",
    width: 60,
    value: (r) => r.origin ?? "unknown",
    render: (r) => <span title={r.client_addr ? `proxy client ${r.client_addr}` : undefined}>{ORIGIN_LABEL[r.origin ?? ""] ?? "unknown"}</span>,
  },
  { key: "ms", label: "Time", width: 60, value: (r) => r.duration_ms, render: (r) => (r.duration_ms == null ? "" : `${r.duration_ms} ms`), align: "right" },
  {
    key: "notes",
    label: "Notes",
    width: 160,
    value: (r) => [r.note, ...r.tags].filter(Boolean).join(" "),
    render: (r) => (
      <>
        {r.tags.map((t) => (
          <span key={t} className="tag">
            {t}
          </span>
        ))}
        {r.note && <span className="note">{r.note}</span>}
      </>
    ),
  },
];

const SOURCES = ["proxy", "send", "crawl", "crawl-browser", "fuzz", "scan", "import", "auth", "race", "ws"];

const PLACEHOLDER: Record<SearchMode, string> = {
  text: "Filter: URL, title, or method",
  contents: "Search requests and responses",
  query: 'Query, e.g. status:5xx resp.body:"stack trace"',
};

const QUERY_HELP =
  "FIELD:VALUE contains (ASCII letters in any case), = equals, != differs, ~ and !~ match a regex, < <= > >= compare numbers and times, FIELD:* is present. " +
  "Fields include method, host, path, url, query, status (also 5xx), length, duration, time, source, origin, tag, note, title, type, " +
  "req, resp, req.body, resp.body, body, req.header.NAME and resp.header.NAME. A bare word searches the URL and title. " +
  "Terms side by side must all match; AND, OR, NOT (any case) and ( ) combine them; quote values with spaces. Runs history list --filter.";

const MODE_HELP: Record<SearchMode, string> = {
  text: "The text filters the URL, title and method of the rows shown",
  contents:
    "Search inside requests and responses: headers and bodies, compressed bodies included. Case-sensitive and literal: the text must appear as stored (URL-encoded or JSON-escaped text included). Runs history list --contains.",
  query: QUERY_HELP,
};

function History() {
  const app = useApp();
  const [rows, setRows] = useState<HistoryItem[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [entry, setEntry] = useState<HistoryEntry | null>(null);
  const [filter, setFilter] = useState<TrafficFilter>(DEFAULT_FILTER);
  const [saved, setSaved] = useState<SavedFilter[]>([]);
  // The saved filters and their revision in the project, for the next save (0: none saved yet).
  const savedState = useRef<SavedState>({ rev: 0, list: [] });
  // Goes up when the project changes or the view closes: a load or save that answers later is dropped.
  const savedGen = useRef(0);
  const takeSaved = (s: SavedState, gen: number) => {
    // Another project's answer, or an older revision than one already shown (a slow answer).
    if (gen !== savedGen.current || s.rev < savedState.current.rev) return;
    savedState.current = s;
    setSaved(s.list);
  };
  // Every call names the project it was made for, so one still queued when another project
  // opens can't write there.
  const cliFor =
    (project: string): Cli =>
    (args, stdin) =>
      run(args, { stdin, project });
  const isConflict = (e: unknown) => e instanceof CliError && e.kind === "conflict";
  // Loads, saves and the move from local storage run one after another (`saveQueue`), each on
  // the state the one before left, so two quick saves don't send the same revision.
  const saveQueue = useRef<Promise<void>>(Promise.resolve());
  const enqueue = (gen: number, work: () => Promise<void>) => {
    saveQueue.current = saveQueue.current.then(() => (gen === savedGen.current ? work() : undefined));
  };
  // Saved filters live in the project. An older build kept them in this app's storage: they
  // are added to the project's (whatever an agent or the CLI saved there first), then removed.
  useEffect(() => {
    const gen = ++savedGen.current;
    const project = app.project;
    const cli = cliFor(project);
    savedState.current = { rev: 0, list: [] };
    setSaved([]);
    enqueue(gen, async () => {
      try {
        const d = await cli(FILTERS_LIST_ARGS);
        takeSaved({ rev: d.rev, list: savedFrom(d.filters) }, gen);
        const local = loadSaved(project);
        if (gen !== savedGen.current || !local.length) return;
        try {
          const merged = await saveChange(cli, savedState.current, (list) => mergeLocal(list, local), isConflict);
          clearLocalSaved(project);
          takeSaved(merged, gen);
        } catch (e: any) {
          // Still shown, and kept where they were: the next save (or open) tries the project again.
          if (gen !== savedGen.current) return;
          takeSaved({ rev: savedState.current.rev, list: mergeLocal(savedState.current.list, local) }, gen);
          app.toast(`Saved filters stay in this app until they can be saved in the project: ${e.message}`, "error");
        }
      } catch (e: any) {
        if (gen === savedGen.current) app.toast(`Saved filters: ${e.message}`, "error");
      }
    });
    return () => {
      savedGen.current++;
    };
  }, [app.project]);
  // The saved filter last chosen or saved, so two with the same state stay apart.
  const [picked, setPicked] = useState<string | null>(null);
  const lastId = useRef(0);
  const { menu, open, close } = useMenu();
  // Opened to show one source's requests: that source alone, and none of them hidden by another filter.
  useEffect(() => {
    if (app.traffic) setFilter({ ...DEFAULT_FILTER, sources: [app.traffic.source] });
  }, [app.traffic]);

  // Contents search: the CLI matches the text inside requests and responses. It runs page by
  // page up to the newest polled row, then searches only the rows each poll adds. A failed
  // page is tried again on a later poll, waiting longer after each failure.
  const search = useRef<ContentSearch | null>(null);
  const [found, setFound] = useState<ContentSearch | null>(null);
  const searching = useRef(false);
  // The CLI call running for the search, stopped when the query changes.
  const searchCall = useRef<string | null>(null);
  // The filter in force, which decides which matches count toward the cap.
  const current = useRef(filter);
  current.current = filter;
  const searchMore = async () => {
    if (searching.current) return;
    searching.current = true;
    try {
      for (;;) {
        const s = search.current;
        const upTo = lastId.current;
        if (!s || !needsSearch(s, upTo)) return;
        const call = `traffic-search-${Date.now()}-${Math.random().toString(36).slice(2)}`;
        searchCall.current = call;
        let next: ContentSearch;
        try {
          next = mergePage(s, (await run<{ items: HistoryItem[] }>(searchArgs(s), { call })).items, upTo, current.current);
        } catch (e: any) {
          // A query that doesn't parse fails the same way every time: stop until it changes.
          next = failPage(s, e.message, Date.now(), e instanceof CliError && e.kind === "invalid_input" && s.query.kind === "filter");
        } finally {
          searchCall.current = null;
        }
        // The query changed (this call was stopped) or the cap was worked out again
        // meanwhile: drop this page and carry on with the search as it is now.
        if (search.current !== s) continue;
        search.current = next;
        setFound(next);
        if (next.error) return;
      }
    } finally {
      searching.current = false;
    }
  };

  // Fetch only new rows each tick (ids only grow), then search them.
  usePoll(async () => {
    for (;;) {
      const d = await run<{ items: HistoryItem[] }>(["history", "list", "--after", String(lastId.current), "--limit", "2000"]);
      if (!d.items.length) break;
      lastId.current = d.items[d.items.length - 1].id;
      // Overlapping polls can fetch the same rows; keep each id once.
      setRows((r) => {
        const max = r.length ? r[r.length - 1].id : 0;
        return [...r, ...d.items.filter((i) => i.id > max)];
      });
      if (d.items.length < 2000) break;
    }
    await searchMore();
  }, 1500);

  // A new search shortly after the text or the single source stops changing. The old one's
  // CLI call is stopped at once: it may be reading every body in the project.
  const wanted = JSON.stringify(searchFor(filter));
  useEffect(() => {
    const want = JSON.parse(wanted) as SearchQuery | null;
    if (!want) {
      setFound(null);
      return;
    }
    const t = setTimeout(() => {
      search.current = newSearch(want);
      setFound(search.current);
      searchMore();
    }, 300);
    return () => {
      clearTimeout(t);
      search.current = null;
      if (searchCall.current) cancelCli(searchCall.current).catch(() => {});
    };
  }, [wanted]);

  // The other filters only decide which matches show and count toward the cap: work that out
  // again here, searching on only if the cap no longer applies.
  useEffect(() => {
    const s = search.current;
    if (!isCurrent(s, filter)) return;
    const next = refilter(s, filter);
    if (next === s) return;
    search.current = next;
    setFound(next);
    searchMore();
  }, [filter]);

  // A rule-changed exchange has two of each: the request before the rules and as sent, the
  // response as received and after the rules. The row's own (sent, received) show first.
  const [beforeRules, setBeforeRules] = useState(false);
  const [afterRules, setAfterRules] = useState(false);
  useEffect(() => {
    setBeforeRules(false);
    setAfterRules(false);
  }, [selected]);

  useEffect(() => {
    if (selected == null) return setEntry(null);
    let live = true;
    run<HistoryEntry>(["history", "show", String(selected), "--max-body", "2000000"])
      .then((e) => live && setEntry(e))
      .catch((e) => live && app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [selected, app.toast]);

  const refused = useMemo(() => rows.filter(isRefused).length, [rows]);
  const shown = useMemo(() => visibleRows(rows, filter, found), [rows, filter, found]);
  const contents = searchFor(filter) != null;
  const note = contents ? (isCurrent(found, filter) ? searchNote(found, lastId.current) : "Searching…") : "";

  const handoff = (id: number, f: (h: Handoff & { entry: HistoryEntry }) => void) =>
    historyRequest(id).then(
      (h) => f({ raw: h.raw, binary: h.binary, target: originOf(h.entry.url), entry: h.entry }),
      (e) => app.toast(e.message, "error"),
    );

  // Whether a pick carries a GraphQL mutation, from its recorded request, so the questions name it.
  // Unknown when the request can't be read: the questions then go by its method.
  const withMutation = (p: HistoryPick): Promise<HistoryPick> =>
    run<HistoryEntry>(["history", "show", String(p.id), MAX_BODY]).then(
      (e) => ({ ...p, mutation: isMutationRequest(bodyText(e.request), !!e.request.truncated) }),
      () => p,
    );

  // Attack traffic: asked first, then started in the background and shown in Scans › Tasks on a click.
  const scan = async (pick: HistoryPick) => {
    const [checks, picks] = await Promise.all([
      run<{ nuclei: unknown }>(["checks", "status"]).catch(() => ({ nuclei: null })),
      withMutation(pick).then((p) => [p]),
    ]);
    const defaults = { nuclei: !!checks.nuclei };
    const q = scanConfirm(picks, defaults);
    if (!(await confirm(q.title, q.message, q.ok, q.cancel))) return;
    try {
      const d = await run<{ job: number }>(scanArgs(picks, defaults, true));
      app.toast(`Active scan started (job ${d.job}). Click to follow it in Scans.`, "info", () => app.showJob(d.job));
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // A note or tag edit can change which rows a query on notes or tags matches, also for rows
  // searched already: search again from the start. (Edits made elsewhere show on the next query.)
  const rerunQuery = () => {
    const s = search.current;
    if (!s || s.query.kind !== "filter" || !usesEditableFields(s.query.text)) return;
    if (searchCall.current) cancelCli(searchCall.current).catch(() => {});
    search.current = rerun(s);
    setFound(search.current);
    searchMore();
  };

  const highlight = (r: HistoryItem, on: boolean) =>
    run(highlightArgs(r.id, on))
      .then(() => setRows((rs) => rs.map((x) => (x.id === r.id ? { ...x, tags: withHighlight(x.tags, on) } : x))))
      .then(rerunQuery)
      .catch((e) => app.toast(e.message, "error"));

  const rowMenu = (r: HistoryItem, ev: React.MouseEvent) => {
    const pick = { id: r.id, method: r.method, url: r.url };
    const refused = isRefused(r);
    const noScan = scanBlocker(r);
    const highlighted = r.tags.includes("highlight");
    open(ev, [
      { label: "Send to Replay", action: () => handoff(r.id, (h) => app.sendToRepeater({ ...h, title: pathOf(r.url).slice(0, 24) })) },
      { label: "Send to Fuzzer", action: () => handoff(r.id, app.sendToFuzzer) },
      { label: "Send request to Diff", action: () => handoff(r.id, (h) => app.sendToComparer(h.raw)) },
      { label: "Send response to Diff", action: () => handoff(r.id, (h) => app.sendToComparer(rawResponse(h.entry))) },
      { label: "Create finding…", action: () => app.newFinding({ url: r.url, method: r.method, history: [r.id] }) },
      "-",
      { label: "Scan this request…", action: () => scan(pick), disabled: !!noScan, hint: noScan ?? undefined },
      { label: "Test access control…", action: () => withMutation(pick).then((p) => app.sendToAccess([p])), disabled: refused, hint: refused ? REFUSED_HINT : undefined },
      "-",
      { label: "Copy URL", action: () => navigator.clipboard.writeText(r.url) },
      { label: "Copy as cURL", action: () => handoff(r.id, (h) => copyAsCurl(h.raw, h.target, h.binary, app.toast)) },
      {
        label: "Add note…",
        action: () => {
          const text = window.prompt("Note for #" + r.id, r.note ?? "");
          if (text == null) return;
          run(["history", "note", String(r.id), ...(text ? ["--", text] : [])])
            .then(() => setRows((rs) => rs.map((x) => (x.id === r.id ? { ...x, note: text || null } : x))))
            .then(rerunQuery)
            .catch((e) => app.toast(e.message, "error"));
        },
      },
      { label: highlighted ? "Remove highlight" : "Highlight", action: () => highlight(r, !highlighted) },
    ]);
  };

  const toggleSource = (s: string) =>
    setFilter((f) => ({ ...f, sources: f.sources.includes(s) ? f.sources.filter((x) => x !== s) : [...f.sources, s] }));

  // Saved filters are kept in the project (`history filters`), so they travel with it.
  const applied = appliedSaved(saved, filter, picked);
  const keepSaved = (change: SavedChange) => {
    const gen = savedGen.current;
    const cli = cliFor(app.project);
    enqueue(gen, async () => {
      try {
        takeSaved(await saveChange(cli, savedState.current, change, isConflict), gen);
      } catch (e: any) {
        if (gen !== savedGen.current) return;
        if (e instanceof SavedMoved) takeSaved(e.now, gen);
        app.toast(e instanceof SavedMoved ? e.message : `Saved filters: ${e.message}`, "error");
      }
    });
  };
  const saveFilter = async () => {
    const name = (await ask("Save the current filter", "Name it to apply it again later.", "Save", "Cancel", applied ?? ""))?.trim();
    if (!name) return;
    if (name !== applied && saved.some((s) => s.name === name) && !(await confirm(`Replace the filter ${name}?`, "A saved filter already has that name.", "Replace", "Cancel"))) return;
    keepSaved(saveAs(name, filter));
    setPicked(name);
  };
  const deleteFilter = async () => {
    if (!applied || !(await confirm(`Delete the filter ${applied}?`, "Only the saved filter is deleted, not any traffic.", "Delete", "Cancel"))) return;
    keepSaved(deleteNamed(applied));
  };

  return (
    <div className="col fill">
      <div className="toolbar">
        <input
          className="input"
          style={{ width: 260 }}
          placeholder={PLACEHOLDER[modeOf(filter)]}
          title={modeOf(filter) === "query" ? QUERY_HELP : undefined}
          spellCheck={false}
          value={filter.text}
          onChange={(e) => setFilter({ ...filter, text: e.target.value })}
        />
        <select
          className="input"
          aria-label="What the text searches"
          value={modeOf(filter)}
          title={MODE_HELP[modeOf(filter)]}
          onChange={(e) => setFilter(withMode(filter, e.target.value as SearchMode))}
        >
          <option value="text">URL</option>
          <option value="contents">Contents</option>
          <option value="query">Query</option>
        </select>
        <div className="seg">
          {SOURCES.map((s) => (
            <button key={s} className={filter.sources.includes(s) ? "on" : ""} onClick={() => toggleSource(s)}>
              {s}
            </button>
          ))}
        </div>
        <label className="check">
          <input type="checkbox" checked={filter.hideErrors} onChange={(e) => setFilter({ ...filter, hideErrors: e.target.checked })} /> 2xx/3xx only
        </label>
        <label className="check">
          <input type="checkbox" checked={filter.hideAssets} onChange={(e) => setFilter({ ...filter, hideAssets: e.target.checked })} /> Hide static assets
        </label>
        <label className="check" title="Requests the proxy refused because their host is outside the engagement scope (often browser background traffic)">
          <input type="checkbox" checked={filter.hideRefused} onChange={(e) => setFilter({ ...filter, hideRefused: e.target.checked })} /> Hide out-of-scope
          {filter.hideRefused && refused > 0 && <span className="muted"> ({refused})</span>}
        </label>
        <span className="sep" />
        <select
          className="input"
          aria-label="Saved filters"
          value={applied ?? ""}
          disabled={!saved.length}
          title="Saved filters for this project"
          onChange={(e) => {
            const s = saved.find((x) => x.name === e.target.value);
            if (s) {
              setPicked(s.name);
              setFilter(s.filter);
            }
          }}
        >
          <option value="">{saved.length ? "Saved filters" : "No saved filters"}</option>
          {saved.map((s) => (
            <option key={s.name} value={s.name}>
              {s.name}
            </option>
          ))}
        </select>
        <button className="btn" onClick={saveFilter} title="Name the current filter to apply it again later">
          Save…
        </button>
        <button className="btn" disabled={!applied} onClick={deleteFilter} title={applied ? `Delete the saved filter ${applied}` : "Pick a saved filter to delete it"}>
          Delete
        </button>
        <div className="toolbar-end">
          <span className={found?.error && isCurrent(found, filter) ? "s5" : "muted"} aria-live="polite">
            {note}
          </span>
          <span className="muted">
            {contents
              ? `${shown.length} match${shown.length === 1 ? "" : "es"} of ${rows.length} items`
              : shown.length === rows.length
                ? `${rows.length} items`
                : `${shown.length} of ${rows.length} items`}
          </span>
        </div>
      </div>
      <Split id="history" dir="col" initial={0.5}>
        <DataTable
          rows={shown}
          columns={COLUMNS}
          rowKey={(r) => r.id}
          selected={selected}
          onSelect={(r) => setSelected(r.id)}
          onActivate={(r) => handoff(r.id, (h) => app.sendToRepeater({ ...h, title: pathOf(r.url).slice(0, 24) }))}
          onContextMenu={rowMenu}
          rowClass={(r) => (r.tags.includes("highlight") ? "hl" : undefined)}
          initialSort={{ key: "id", desc: true }}
          empty={
            contents
              ? note || "Nothing matches."
              : rows.length
                ? "Nothing matches the filter."
                : "No traffic yet. Start the proxy and point a browser at it, or use Replay."
          }
        />
        <Split id="history-msg" dir="row">
          <HttpView
            title="Request"
            value={entry ? bodyText(beforeRules && entry.original_request ? entry.original_request : entry.request) : ""}
            binary={isBinary(beforeRules && entry?.original_request ? entry.original_request : entry?.request)}
            placeholder="Select a request"
            extra={
              entry?.original_request && (
                <div className="seg" title={ruleEditNote(entry.entry.edited_by)}>
                  <button className={beforeRules ? "on" : ""} onClick={() => setBeforeRules(true)}>
                    Before rules
                  </button>
                  <button className={beforeRules ? "" : "on"} onClick={() => setBeforeRules(false)}>
                    Sent
                  </button>
                </div>
              )
            }
          />
          <HttpView
            title="Response"
            value={entry ? (afterRules && entry.modified_response ? bodyText(entry.modified_response) : rawResponse(entry)) : ""}
            binary={isBinary(afterRules && entry?.modified_response ? entry.modified_response : entry?.response?.body)}
            placeholder={entry?.entry.error ?? ""}
            extra={
              <>
                {entry?.modified_response && (
                  <div className="seg" title={ruleEditNote(entry.response_edits)}>
                    <button className={afterRules ? "" : "on"} onClick={() => setAfterRules(false)}>
                      Received
                    </button>
                    <button className={afterRules ? "on" : ""} onClick={() => setAfterRules(true)}>
                      After rules
                    </button>
                  </div>
                )}
                {entry?.duration_ms != null && <span className="muted">{entry.duration_ms} ms</span>}
              </>
            }
          />
        </Split>
      </Split>
      <Menu menu={menu} close={close} />
    </div>
  );
}

// ---------------- Intercept ----------------

interface Held {
  id: number;
  time: string;
  direction: "request" | "response" | "ws-to-server" | "ws-to-client";
  state: string;
  method: string;
  url: string;
  status: number | null;
  length: number;
}

export { interceptEnableArgs, type InterceptSettings } from "./intercept";

/**
 * The intercept's filter: a query in the filter language, with the saved Traffic filters that
 * are queries to start from. With `onCommit` (the Intercept toolbar) Enter, leaving the box or
 * picking a saved filter applies it and Escape puts it back; without, the text is part of a
 * draft saved elsewhere.
 */
export function InterceptFilter({
  value,
  onChange,
  onCommit,
  onRevert,
  disabled,
  width = 260,
}: {
  value: string;
  onChange: (text: string) => void;
  onCommit?: (text: string) => void;
  onRevert?: () => void;
  disabled?: boolean;
  width?: number;
}) {
  const [saved, setSaved] = useState<{ name: string; text: string }[]>([]);
  // Read again when the list is opened: Traffic may have saved one since.
  const load = () =>
    run<{ filters: unknown }>(FILTERS_LIST_ARGS)
      .then((d) => setSaved(savedQueries(savedFrom(d.filters))))
      .catch(() => {});
  useEffect(() => {
    load();
  }, []);
  const picked = savedQueryFor(saved, value);
  return (
    <>
      <input
        className="input mono"
        style={{ width }}
        aria-label="Intercept filter"
        placeholder="Hold only: query, e.g. method=POST NOT path:/static"
        title={INTERCEPT_FILTER_HELP}
        spellCheck={false}
        disabled={disabled}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") onCommit?.(value);
          if (e.key === "Escape") onRevert?.();
        }}
        onBlur={() => onCommit?.(value)}
      />
      <select
        className="input"
        aria-label="Saved filters for intercept"
        value={picked ?? ""}
        disabled={disabled}
        onFocus={load}
        title="Saved Traffic filters in Query mode. Only the query is used: their sources and checkboxes are Traffic's."
        onChange={(e) => {
          const s = saved.find((x) => x.name === e.target.value);
          if (!s) return;
          onChange(s.text);
          onCommit?.(s.text);
        }}
      >
        <option value="">{saved.length ? "Saved filters" : "No saved queries"}</option>
        {saved.map((s) => (
          <option key={s.name} value={s.name}>
            {s.name}
          </option>
        ))}
      </select>
    </>
  );
}

const HELD_TITLE: Record<Held["direction"], string> = {
  request: "Request to",
  response: "Response from",
  "ws-to-server": "WebSocket message to",
  "ws-to-client": "WebSocket message from",
};

function Intercept({ active }: { active: boolean }) {
  const app = useApp();
  const [settings, refreshSettings] = usePoll<{ settings: InterceptSettings; pending: number }>(() => run(["intercept", "status"]), 2000, active);
  const [held, refreshHeld] = usePoll<{ items: Held[] }>(() => run(["intercept", "list"]), 1000, active);
  const [current, setCurrent] = useState<number | null>(null);
  // binary: the text holds one char per byte; truncated: only the first 2 MB arrived, so it can't be edited.
  const [message, setMessage] = useState<{ original: string; text: string; binary: boolean; truncated: boolean } | null>(null);
  const items = held?.items ?? [];

  // Follow the oldest held message unless the user picked one that is still held.
  useEffect(() => {
    if (current != null && items.some((i) => i.id === current)) return;
    setCurrent(items[0]?.id ?? null);
  }, [items, current]);

  useEffect(() => {
    if (current == null) return setMessage(null);
    run<{ message: Body }>(["intercept", "show", String(current), MAX_BODY])
      .then((d) => {
        const text = bodyText(d.message);
        setMessage({ original: text, text, binary: isBinary(d.message), truncated: !!d.message.truncated });
      })
      .catch(() => setMessage(null));
  }, [current]);

  const s = settings?.settings;
  // Changes run one after another, each on the settings as they are then: `enable` replaces
  // them all, so a checkbox ticked while a filter is being applied mustn't undo it (or the
  // other way round).
  const queue = useRef<Promise<unknown>>(Promise.resolve());
  const change = (make: (cur: InterceptSettings) => string[] | null) => {
    const work = async () => {
      try {
        const cur = (await run<{ settings: InterceptSettings }>(["intercept", "status"])).settings;
        const args = make(cur);
        if (args) await run(args);
        return true;
      } catch (e: any) {
        app.toast(e.message, "error");
        return false;
      } finally {
        refreshSettings();
      }
    };
    const done = queue.current.then(work);
    queue.current = done;
    return done;
  };

  // The filter as typed, until it is applied and shows in the settings (null: the saved one is shown).
  const [filterDraft, setFilterDraft] = useState<string | null>(null);
  // The text last applied, so Enter and then leaving the box don't apply (or refuse) it twice.
  const triedFilter = useRef<string | null>(null);
  // Applied, and kept in the box until the settings polled show it.
  const appliedFilter = useRef<string | null>(null);
  useEffect(() => {
    const text = appliedFilter.current;
    if (!s || text == null || filterChanged(s, text)) return;
    appliedFilter.current = null;
    setFilterDraft((d) => (d === text ? null : d));
  }, [s]);
  const applyFilter = async (text: string) => {
    if (!s?.enabled || !filterChanged(s, text)) return setFilterDraft(null);
    if (triedFilter.current === text) return;
    triedFilter.current = text;
    // Kept as typed when refused, to fix.
    const ok = await change((cur) => (cur.enabled ? interceptEnableArgs(withFilter(cur, text)) : null));
    if (ok) appliedFilter.current = text;
  };
  const toggle = (patch: (cur: InterceptSettings) => Partial<InterceptSettings>) =>
    change((cur) => {
      const next = { ...cur, ...patch(cur) };
      return next.enabled ? interceptEnableArgs(next) : ["intercept", "disable"];
    });

  const decide = async (how: "forward" | "drop") => {
    if (current == null || !message) return;
    try {
      if (how === "drop") await run(["intercept", "drop", String(current)]);
      else if (message.text !== message.original) await run(["intercept", "forward", String(current), "--file=-"], textBytes(message.text, message.binary));
      else await run(["intercept", "forward", String(current)]);
      setCurrent(null);
      refreshHeld();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const item = items.find((i) => i.id === current);
  return (
    <div className="col fill">
      <div className="toolbar">
        <button
          className={`btn ${s?.enabled ? "primary" : ""}`}
          onClick={() => s && toggle((c) => ({ enabled: !c.enabled, requests: c.enabled ? c.requests : c.requests || !(c.responses || c.ws_to_server || c.ws_to_client) }))}
        >
          Intercept is {s?.enabled ? "on" : "off"}
        </button>
        <label className="check">
          <input type="checkbox" checked={!!s?.requests} disabled={!s?.enabled} onChange={(e) => {
              const on = e.target.checked;
              toggle(() => ({ requests: on }));
            }} /> Requests
        </label>
        <label className="check">
          <input type="checkbox" checked={!!s?.responses} disabled={!s?.enabled} onChange={(e) => {
              const on = e.target.checked;
              toggle(() => ({ responses: on }));
            }} /> Responses
        </label>
        <label className="check" title="WebSocket messages from the browser (text and binary)">
          <input type="checkbox" checked={!!s?.ws_to_server} disabled={!s?.enabled} onChange={(e) => {
              const on = e.target.checked;
              toggle(() => ({ ws_to_server: on }));
            }} /> WS to server
        </label>
        <label className="check" title="WebSocket messages from the server (text and binary)">
          <input type="checkbox" checked={!!s?.ws_to_client} disabled={!s?.enabled} onChange={(e) => {
              const on = e.target.checked;
              toggle(() => ({ ws_to_client: on }));
            }} /> WS to client
        </label>
        <InterceptFilter
          value={filterDraft ?? s?.filter ?? ""}
          disabled={!s?.enabled}
          width={240}
          onChange={(text) => {
            triedFilter.current = null;
            setFilterDraft(text);
          }}
          onCommit={applyFilter}
          onRevert={() => setFilterDraft(null)}
        />
        <span className="sep" />
        <button className="btn primary" disabled={!message} onClick={() => decide("forward")}>
          Forward{message && message.text !== message.original ? " edited" : ""}
        </button>
        <button className="btn" disabled={!message} onClick={() => decide("drop")}>
          Drop
        </button>
        <button
          className="btn"
          disabled={!message || message.truncated || item?.direction !== "request"}
          onClick={() => item && message && app.sendToRepeater({ raw: message.text, binary: message.binary, target: originOf(item.url) })}
        >
          Send to Replay
        </button>
        {message?.truncated && (
          <span className="tag" title="Only the first 2 MB is shown. Forward or drop it as is, or use the CLI to edit it.">
            Over 2 MB: read-only
          </span>
        )}
        <span className="grow" />
        <span className="muted">{s ? `Unanswered messages are ${s.timeout_action === "drop" ? "dropped" : "forwarded"} after ${s.timeout_secs} s` : ""}</span>
      </div>
      <Split id="intercept" dir="col" initial={0.28}>
        <DataTable
          rows={items}
          columns={[
            { key: "id", label: "#", width: 50, value: (r: Held) => r.id, align: "right" },
            { key: "dir", label: "Direction", width: 80, value: (r: Held) => r.direction },
            { key: "method", label: "Method", width: 64, value: (r: Held) => r.method },
            { key: "url", label: "URL", width: 420, value: (r: Held) => r.url },
            { key: "status", label: "Status", width: 60, value: (r: Held) => r.status, align: "right" },
            { key: "len", label: "Length", width: 70, value: (r: Held) => r.length, align: "right" },
          ]}
          rowKey={(r) => r.id}
          selected={current}
          onSelect={(r) => setCurrent(r.id)}
          initialSort={{ key: "id", desc: false }}
          empty={s?.enabled ? "Waiting for traffic through the proxy…" : "Intercept is off. Turn it on to hold requests before they are sent."}
        />
        <HttpView
          title={item ? `${HELD_TITLE[item.direction]} ${hostOf(item.url.replace(/^ws/, "http"))}` : "Message"}
          value={message?.text ?? ""}
          binary={message?.binary}
          onChange={message && !message.truncated ? (text) => setMessage({ ...message, text }) : undefined}
          placeholder="Nothing held"
        />
      </Split>
    </div>
  );
}
