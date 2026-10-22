import { useEffect, useMemo, useState } from "react";
import { bodyText, historyRequest, isBinary, MAX_BODY, pathOf, rawResponse, run, type HistoryEntry, type HistoryItem, type Risk } from "../api";
import { originOf, useApp } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Menu, useMenu, type MenuItem } from "../ui/Menu";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";
import { feedHasActive } from "./feed";
import type { ChecksStatus } from "./Updates";

export function TargetView({ active }: { active: boolean }) {
  const [sub, setSub] = useState<"map" | "scope">("map");
  return (
    <div className="col fill">
      <div className="subtabs">
        <button className={sub === "map" ? "on" : ""} onClick={() => setSub("map")}>
          Site map
        </button>
        <button className={sub === "scope" ? "on" : ""} onClick={() => setSub("scope")}>
          Scope
        </button>
      </div>
      <div className="fill" hidden={sub !== "map"}>
        <SiteMap active={active && sub === "map"} />
      </div>
      <div className="fill" hidden={sub !== "scope"}>
        <Scope active={active && sub === "scope"} />
      </div>
    </div>
  );
}

// ---------------- Site map ----------------

const RISK_OF: Risk[] = ["info", "low", "medium", "high"];

/** One row per origin + path, with the highest open finding risk on that path. */
const TREE_SQL = `SELECT h.scheme, h.host, h.port, h.path, group_concat(DISTINCT h.method) AS methods,
  group_concat(DISTINCT h.status) AS statuses, count(*) AS n, max(h.id) AS last, f.risk, f.issues
FROM history h
LEFT JOIN (SELECT x.scheme s, x.host hh, x.port pp, x.path p, max(f.risk_level) risk, count(DISTINCT f.id) issues
  FROM findings f JOIN history x ON x.id = f.history_id WHERE f.state <> 'false_positive' GROUP BY 1, 2, 3, 4) f
  ON f.s = h.scheme AND f.hh = h.host AND f.pp = h.port AND f.p = h.path
WHERE (?1 OR h.source NOT IN ('scan', 'fuzz'))
  AND (NOT ?2 OR h.error IS NULL OR h.error NOT LIKE 'out of scope%')
GROUP BY h.scheme, h.host, h.port, h.path`;

const ROWS_SQL = `SELECT id, time, source, method, url, status, resp_content_type, resp_body_length, title, duration_ms, error, note, tags
FROM history WHERE scheme = ?1 AND host = ?2 AND port = ?3 AND (?4 = '' OR path = ?4 OR substr(path, 1, length(?4) + 1) = ?4 || '/')
  AND (?5 OR source NOT IN ('scan', 'fuzz'))
  AND (NOT ?6 OR error IS NULL OR error NOT LIKE 'out of scope%')
ORDER BY id DESC`;

type TreeRow = [string, string, number, string, string, string | null, number, number, number | null, number | null];

interface Node {
  key: string;
  origin: string; // scheme://host:port
  scheme: string;
  host: string;
  port: number;
  path: string; // "" for the origin itself, else "/a/b"
  name: string;
  methods: Set<string>;
  statuses: Set<string>;
  count: number;
  last: number;
  risk: number; // -1 when no findings
  issues: number;
  children: Map<string, Node>;
}

function origin(scheme: string, host: string, port: number): string {
  const def = (scheme === "http" && port === 80) || (scheme === "https" && port === 443);
  return `${scheme}://${host}${def ? "" : `:${port}`}`;
}

/** Folds the per-path rows into origin → path segment nodes, rolling counts and risk up. */
function buildTree(rows: TreeRow[]): Node[] {
  const roots = new Map<string, Node>();
  const make = (o: string, r: TreeRow, path: string, name: string): Node => ({
    key: `${o}${path}`,
    origin: o,
    scheme: r[0],
    host: r[1],
    port: r[2],
    path,
    name,
    methods: new Set(),
    statuses: new Set(),
    count: 0,
    last: 0,
    risk: -1,
    issues: 0,
    children: new Map(),
  });
  for (const r of rows) {
    const o = origin(r[0], r[1], r[2]);
    let node = roots.get(o) ?? make(o, r, "", o);
    roots.set(o, node);
    const chain = [node];
    let path = "";
    for (const seg of r[3].split("/").filter(Boolean)) {
      path += "/" + seg;
      const next = node.children.get(seg) ?? make(o, r, path, seg);
      node.children.set(seg, next);
      node = next;
      chain.push(node);
    }
    for (const m of r[4].split(",")) node.methods.add(m);
    for (const s of (r[5] ?? "").split(",").filter(Boolean)) node.statuses.add(s);
    for (const n of chain) {
      n.count += r[6];
      n.last = Math.max(n.last, r[7]);
      n.risk = Math.max(n.risk, r[8] ?? -1);
      n.issues += r[9] ?? 0;
    }
  }
  return [...roots.values()].sort((a, b) => a.key.localeCompare(b.key));
}

const statusClass = (s: string) => (s[0] === "5" ? "s5" : s[0] === "4" ? "s4" : s[0] === "3" ? "s3" : "s2");

/** SQL condition selecting a node's history rows, for `scan active --where`. */
function whereFor(n: Node): string {
  const q = (s: string) => `'${s.replace(/'/g, "''")}'`;
  const branch = n.path ? ` AND (path = ${q(n.path)} OR substr(path, 1, ${n.path.length + 1}) = ${q(n.path + "/")})` : "";
  return `scheme = ${q(n.scheme)} AND host = ${q(n.host)} AND port = ${n.port}${branch} AND source NOT IN ('scan', 'fuzz')`;
}

const COLUMNS: Column<HistoryItem>[] = [
  { key: "id", label: "#", width: 56, value: (r) => r.id, align: "right" },
  { key: "method", label: "Method", width: 64, value: (r) => r.method, render: (r) => <span className="method">{r.method}</span> },
  { key: "path", label: "URL", width: 320, value: (r) => pathOf(r.url) },
  {
    key: "status",
    label: "Status",
    width: 58,
    value: (r) => r.status,
    render: (r) => (r.error ? <span className="s5" title={r.error}>error</span> : <span className={statusClass(String(r.status ?? ""))}>{r.status ?? "—"}</span>),
    align: "right",
  },
  { key: "length", label: "Length", width: 70, value: (r) => r.resp_body_length, align: "right" },
  { key: "mime", label: "MIME", width: 110, value: (r) => (r.resp_content_type ?? "").split(";")[0] },
  { key: "title", label: "Title", width: 160, value: (r) => r.title },
  { key: "source", label: "Source", width: 70, value: (r) => r.source },
];

function SiteMap({ active }: { active: boolean }) {
  const app = useApp();
  const [withAttacks, setWithAttacks] = useState(false);
  // Hosts the engagement refused (browser background calls, stray links) aren't part of the target.
  const [inScope, setInScope] = useState(true);
  const [data] = usePoll<{ rows: TreeRow[] }>(
    () => run(["query", TREE_SQL, "-p", withAttacks ? "1" : "0", "-p", inScope ? "1" : "0", "--limit", "100000"]),
    4000,
    active,
  );
  const [toggled, setToggled] = useState(new Set<string>());
  const [node, setNode] = useState<Node | null>(null);
  const [rows, setRows] = useState<HistoryItem[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [entry, setEntry] = useState<HistoryEntry | null>(null);
  const { menu, open, close } = useMenu();

  const tree = useMemo(() => buildTree(data?.rows ?? []), [data]);

  // The node's requests; refreshed with the tree so new traffic shows up.
  useEffect(() => {
    if (!node) return setRows([]);
    let live = true;
    run<{ rows: (Omit<HistoryItem, "tags"> & { tags: string | null })[] }>([
      "query",
      ROWS_SQL,
      "--shape",
      "objects",
      "--limit",
      "5000",
      `--param=${node.scheme}`,
      `--param=${node.host}`,
      `--param=${node.port}`,
      `--param=${node.path}`,
      `--param=${withAttacks ? "1" : "0"}`,
      `--param=${inScope ? "1" : "0"}`,
    ])
      .then((d) => live && setRows(d.rows.map((r) => ({ ...r, tags: JSON.parse(r.tags ?? "[]") }))))
      .catch((e) => live && app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [node, data, withAttacks, inScope, app.toast]);

  useEffect(() => {
    if (selected == null) return setEntry(null);
    let live = true;
    run<HistoryEntry>(["history", "show", String(selected), MAX_BODY])
      .then((e) => live && setEntry(e))
      .catch((e) => live && app.toast(e.message, "error"));
    return () => {
      live = false;
    };
  }, [selected, app.toast]);

  const toRepeater = (id: number) =>
    historyRequest(id)
      .then(({ raw, binary, entry: e }) => app.sendToRepeater({ raw, binary, target: originOf(e.url), title: pathOf(e.url).slice(0, 24) }))
      .catch((e) => app.toast(e.message, "error"));

  // Installed checks join active scans started from here: brainproxy's feed, and the Nuclei
  // templates of high severity and up.
  const [nucleiArgs, setNucleiArgs] = useState<string[]>([]);
  useEffect(() => {
    run<ChecksStatus>(["checks", "status"])
      .then((d) => {
        const sources = [feedHasActive(d.brainproxy?.installed) ? "brainproxy" : "", d.nuclei ? "nuclei" : ""].filter(Boolean);
        setNucleiArgs(sources.length ? ["--checks", sources.join(","), ...(d.nuclei ? ["--check-severity", "high"] : [])] : []);
      })
      .catch(() => {});
  }, []);

  const launch = (args: string[], what: string) =>
    run<{ job: number }>([...args, "--background"])
      .then((d) => app.toast(`${what} started (job ${d.job}); see Scans`))
      .catch((e) => app.toast(e.message, "error"));

  const actions = (url: string, lastId: number, scan: string[], prefix?: string): MenuItem[] => [
    { label: "Send to Replay", action: () => toRepeater(lastId) },
    { label: "Crawl from here", action: () => launch(["crawl", url, ...(prefix ? [`--path-prefix=${prefix}`] : [])], "Crawl") },
    { label: prefix != null ? "Active scan this branch" : "Active scan this request", action: () => launch(["scan", "active", ...scan, ...nucleiArgs], "Active scan") },
    { label: "Copy URL", action: () => navigator.clipboard.writeText(url) },
  ];

  const nodeMenu = (n: Node, ev: React.MouseEvent) => {
    ev.preventDefault();
    setNode(n);
    open(ev, actions(n.origin + (n.path || "/"), n.last, [`--where=${whereFor(n)}`], n.path || "/"));
  };

  const isOpen = (n: Node, depth: number) => (depth === 0 ? !toggled.has(n.key) : toggled.has(n.key));
  const toggle = (k: string) =>
    setToggled((t) => {
      const s = new Set(t);
      s.has(k) ? s.delete(k) : s.add(k);
      return s;
    });

  const renderNode = (n: Node, depth: number): React.ReactNode => {
    const kids = [...n.children.values()].sort((a, b) => Number(b.children.size > 0) - Number(a.children.size > 0) || a.name.localeCompare(b.name));
    const expanded = isOpen(n, depth);
    return (
      <div key={n.key}>
        <button
          className={`tree-group st-node ${node?.key === n.key ? "on" : ""}`}
          style={{ paddingLeft: 10 + depth * 14 }}
          onClick={() => {
            setNode(n);
            setSelected(null);
          }}
          onDoubleClick={() => kids.length && toggle(n.key)}
          onContextMenu={(e) => nodeMenu(n, e)}
          title={n.origin + n.path}
        >
          <span
            className="caret"
            onClick={(e) => {
              e.stopPropagation();
              toggle(n.key);
            }}
          >
            {kids.length ? (expanded ? "▾" : "▸") : ""}
          </span>
          <span className={`dot-risk ${n.risk >= 0 ? `risk-${RISK_OF[n.risk]}` : "st-none"}`} title={n.risk >= 0 ? `${n.issues} issue(s), highest ${RISK_OF[n.risk]}` : "No issues"} />
          <span className={`grow ellipsis ${depth === 0 ? "" : "st-seg"}`}>{n.name}</span>
          {[...n.methods].map((m) => (
            <span key={m} className="st-badge method">
              {m}
            </span>
          ))}
          {[...n.statuses].slice(0, 3).map((s) => (
            <span key={s} className={`st-badge ${statusClass(s)}`}>
              {s}
            </span>
          ))}
          <span className="muted">{n.count}</span>
        </button>
        {expanded && kids.map((k) => renderNode(k, depth + 1))}
      </div>
    );
  };

  return (
    <div className="col fill">
      <div className="toolbar">
        <label className="check">
          <input type="checkbox" checked={withAttacks} onChange={(e) => setWithAttacks(e.target.checked)} /> Include scanner and fuzzer requests
        </label>
        <label className="check" title="Hide hosts and requests the proxy refused because they're outside the engagement scope">
          <input type="checkbox" checked={inScope} onChange={(e) => setInScope(e.target.checked)} /> In scope only
        </label>
        <span className="grow" />
        <span className="muted">
          {tree.length} host{tree.length === 1 ? "" : "s"} · right-click a node to crawl or scan it
        </span>
      </div>
      <Split id="sitemap" dir="row" initial={0.32}>
        <div className="tree">
          {tree.length === 0 && <div className="empty">No traffic yet. Crawl a target from Scans, or browse through the proxy.</div>}
          {tree.map((n) => renderNode(n, 0))}
        </div>
        {node ? (
          <Split id="sitemap-detail" dir="col" initial={0.4}>
            <DataTable
              rows={rows}
              columns={COLUMNS}
              rowKey={(r) => r.id}
              selected={selected}
              onSelect={(r) => setSelected(r.id)}
              onActivate={(r) => toRepeater(r.id)}
              onContextMenu={(r, e) => open(e, actions(r.url, r.id, ["--history-id", String(r.id)]))}
              initialSort={{ key: "id", desc: true }}
              empty="No requests under this node."
            />
            <Split id="sitemap-msg" dir="row">
              <HttpView title="Request" value={entry ? bodyText(entry.request) : ""} binary={isBinary(entry?.request)} placeholder="Select a request" />
              <HttpView title="Response" value={entry ? rawResponse(entry) : ""} binary={isBinary(entry?.response?.body)} placeholder={entry?.entry.error ?? ""} />
            </Split>
          </Split>
        ) : (
          <div className="blank">Select a host or path to see its requests.</div>
        )}
      </Split>
      <Menu menu={menu} close={close} />
    </div>
  );
}

// ---------------- Scope ----------------

interface Engagement {
  engagement: { name?: string | null; include: string[]; exclude: string[] } | null;
  system: { include: string[]; exclude: string[] } | null;
  system_file: string | null;
  enforced: boolean;
  rule: string;
}

interface ProxyScope {
  include: string[];
  exclude: string[];
  record_out_of_scope: boolean;
}

interface CheckResult {
  engagement: { port: number; allowed: boolean; reason?: string; addresses?: string[] }[] | string;
  proxy: boolean | string;
}

/** Fired after `engagement start` so the header chips reload. */
export const ENGAGEMENT_CHANGED = "engagement-changed";

const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function Scope({ active }: { active: boolean }) {
  const app = useApp();
  const [eng, refreshEng] = usePoll<Engagement>(() => run(["engagement", "show"]), 10000, active);
  const [scope, setScope] = useState<ProxyScope | null>(null);
  const [edit, setEdit] = useState({ include: "", exclude: "", record: false });
  const [form, setForm] = useState({ name: "", targets: "", exclude: "", sure: false });
  const [host, setHost] = useState("");
  const [check, setCheck] = useState<CheckResult | null>(null);

  const loadScope = () =>
    run<ProxyScope>(["scope", "show"])
      .then((s) => {
        setScope(s);
        setEdit({ include: s.include.join("\n"), exclude: s.exclude.join("\n"), record: s.record_out_of_scope });
      })
      .catch((e) => app.toast(e.message, "error"));
  useEffect(() => {
    if (active) loadScope();
  }, [active]);

  const scopeCmd = async (args: string[]) => {
    try {
      await run(["scope", ...args]);
      await loadScope();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const save = () =>
    scopeCmd([
      "set",
      ...lines(edit.include).map((p) => `--include=${p}`),
      ...lines(edit.exclude).map((p) => `--exclude=${p}`),
      ...(edit.record ? ["--record-out-of-scope"] : []),
    ]);

  const start = async () => {
    const targets = lines(form.targets);
    if (!targets.length || !form.sure) return;
    try {
      await run([
        "engagement",
        "start",
        ...targets.map((t) => `--target=${t}`),
        ...lines(form.exclude).map((t) => `--exclude=${t}`),
        ...(form.name.trim() ? [`--name=${form.name.trim()}`] : []),
      ]);
      app.toast("Engagement started");
      refreshEng();
      window.dispatchEvent(new Event(ENGAGEMENT_CHANGED));
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const runCheck = async () => {
    const h = host.trim();
    if (!h) return;
    const [e, p] = await Promise.all([
      run<{ results: { port: number; allowed: boolean; reason?: string }[] }>(["engagement", "check", "--", h]).then((d) => d.results, (x) => String(x.message)),
      run<{ in_scope: boolean }>(["scope", "check", "--", h.replace(/:\d+$/, "")]).then((d) => d.in_scope, (x) => String(x.message)),
    ]);
    setCheck({ engagement: e, proxy: p });
  };

  const e = eng?.engagement;
  return (
    <div className="detail tg-scope">
      <h3>Engagement scope</h3>
      {eng == null ? null : e ? (
        <>
          <p className="muted small">Write-once: every request brainproxy sends must match it. It can never be changed for this project.</p>
          <dl className="facts">
            {e.name && (
              <>
                <dt>Name</dt>
                <dd>{e.name}</dd>
              </>
            )}
            <dt>Targets</dt>
            <dd className="mono">{e.include.join(", ")}</dd>
            {e.exclude.length > 0 && (
              <>
                <dt>Excluded</dt>
                <dd className="mono">{e.exclude.join(", ")}</dd>
              </>
            )}
            {eng.system_file && (
              <>
                <dt>System scope</dt>
                <dd className="mono">{eng.system_file}</dd>
              </>
            )}
          </dl>
        </>
      ) : (
        <div className="tg-form">
          <p className="error">No engagement yet: nothing can be sent until the targets are set.</p>
          <label className="label">Name (optional)</label>
          <input className="input" value={form.name} onChange={(ev) => setForm({ ...form, name: ev.target.value })} placeholder="ACME external test" />
          <label className="label">Targets, one per line</label>
          <textarea className="input code tg-area" value={form.targets} onChange={(ev) => setForm({ ...form, targets: ev.target.value })} placeholder={"app.example.com\n*.example.com\n10.0.0.0/24:8443"} />
          <label className="label">Never contact (optional)</label>
          <textarea className="input code tg-area" value={form.exclude} onChange={(ev) => setForm({ ...form, exclude: ev.target.value })} placeholder="admin.example.com" />
          <p className="muted small">Forms: example.com, *.example.com, 10.0.0.5, 10.0.0.0/24, [2001:db8::1], each optionally with :port.</p>
          <label className="check">
            <input type="checkbox" checked={form.sure} onChange={(ev) => setForm({ ...form, sure: ev.target.checked })} /> I understand the engagement can never be changed or removed afterwards
          </label>
          <div>
            <button className="btn primary" disabled={!form.sure || !lines(form.targets).length} onClick={start}>
              Start engagement
            </button>
          </div>
        </div>
      )}

      <h3>Check a host</h3>
      <form
        className="row gap"
        onSubmit={(ev) => {
          ev.preventDefault();
          runCheck();
        }}
      >
        <input className="input" style={{ width: 280 }} placeholder="host[:port]" value={host} onChange={(ev) => setHost(ev.target.value)} />
        <button className="btn">Check</button>
      </form>
      {check && (
        <dl className="facts tg-check">
          <dt>Engagement</dt>
          <dd>
            {typeof check.engagement === "string" ? (
              <span className="s5">{check.engagement}</span>
            ) : (
              check.engagement.map((r) => (
                <div key={r.port}>
                  <span className={r.allowed ? "s2" : "s5"}>{r.allowed ? "allowed" : "blocked"}</span> port {r.port}
                  {r.reason && <span className="muted"> · {r.reason}</span>}
                </div>
              ))
            )}
          </dd>
          <dt>Proxy recording</dt>
          <dd>{typeof check.proxy === "string" ? <span className="s5">{check.proxy}</span> : check.proxy ? <span className="s2">in scope</span> : <span className="muted">out of scope</span>}</dd>
        </dl>
      )}

      <h3>Proxy recording scope</h3>
      <p className="muted small">
        Which hosts the proxy intercepts, modifies, and records. Patterns are case-insensitive regexes on host names; empty means everything.
      </p>
      {scope && (
        <div className="tg-form">
          <label className="label">Include, one per line</label>
          <textarea className="input code tg-area" value={edit.include} onChange={(ev) => setEdit({ ...edit, include: ev.target.value })} placeholder="(everything)" />
          <label className="label">Exclude, one per line</label>
          <textarea className="input code tg-area" value={edit.exclude} onChange={(ev) => setEdit({ ...edit, exclude: ev.target.value })} />
          <label className="check">
            <input type="checkbox" checked={edit.record} onChange={(ev) => setEdit({ ...edit, record: ev.target.checked })} /> Also record out-of-scope traffic (never intercepted or modified)
          </label>
          <div className="row gap">
            <button className="btn primary" onClick={save}>
              Save scope
            </button>
            <button className="btn" onClick={() => scopeCmd(["clear"])}>
              Clear
            </button>
            <button className="btn" onClick={loadScope}>
              Revert
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
