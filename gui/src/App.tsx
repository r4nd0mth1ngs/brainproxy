import { useCallback, useEffect, useRef, useState } from "react";
import { inTauri, run, setProject } from "./api";
import { AppProvider, autoProxy, useApp, type Tab, type TempInfo } from "./store";
import { ProxyView } from "./views/Proxy";
import { RepeaterView } from "./views/Repeater";
import { FindingsView } from "./views/Findings";
import { DecoderView } from "./views/Decoder";
import { OobView } from "./views/Oob";
import { SettingsView } from "./views/Settings";
import { FuzzerView } from "./views/Fuzzer";
import { ComparerView } from "./views/Comparer";
import { DashboardView } from "./views/Dashboard";
import { ENGAGEMENT_CHANGED, TargetView } from "./views/Target";
import { ScannerView } from "./views/Scanner";
import { Logo } from "./ui/Logo";
import { Icon } from "./ui/Icons";
import { SideBrand } from "./ui/Brand";
import { Boundary } from "./ui/Boundary";
import { Menu, useMenu } from "./ui/Menu";
import { ConfirmHost, confirm } from "./ui/Confirm";
import { Welcome, chooseProjectFile, remember } from "./views/Welcome";
import { usePoll } from "./ui/usePoll";
import { version } from "../package.json";

const DISCARD_TITLE = "Discard this temporary engagement?";
const DISCARD = "Its traffic, findings and settings are deleted for good. Use Save as… first to keep them.";

export function App() {
  const [project, setProj] = useState<string | null>(null);
  const [temp, setTemp] = useState<TempInfo | null>(null);
  /** Shown on the welcome screen, e.g. when a temporary project couldn't be wiped. */
  const [notice, setNotice] = useState("");
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("theme") ?? "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);

  const open = useCallback(async (path: string) => {
    setProject(path);
    const info = await run<{ temp: boolean; ram_backed?: boolean }>(["project", "init"]);
    // A temporary project is gone once closed, so it never goes in Recent.
    if (!info.temp) remember(path);
    setTemp(info.temp ? { ramBacked: !!info.ram_backed } : null);
    setNotice("");
    setProj(path);
  }, []);

  // Leaving the project unmounts the shell, which stops a proxy it started. `discard` also
  // stops the proxy, OOB listener and jobs of a temporary project before wiping it.
  const close = useCallback(async () => {
    if (temp && !(await confirm(DISCARD_TITLE, DISCARD, "Discard", "Keep open"))) return;
    setProj(null);
    setTemp(null);
    if (temp) await run(["project", "discard"]).catch((e) => setNotice(`The temporary engagement wasn't wiped: ${e.message}`));
  }, [temp]);

  // Copies the temporary project to a file, then carries on in that file.
  const saveAs = useCallback(async () => {
    const eng = await run<{ engagement: { name: string | null } | null }>(["engagement", "show"]).catch(() => null);
    const dest = await chooseProjectFile(eng?.engagement?.name ?? "");
    if (!dest) return;
    await run(["project", "save", `--output=${dest}`]);
    setProj(null);
    setTemp(null);
    // The saved file has everything; if this fails the leftover is swept once the app exits.
    await run(["project", "discard"]).catch(() => {});
    // The shell is gone by now, so a failure is shown on the welcome screen.
    await open(dest).catch((e) => setNotice(`Saved to ${dest}, but it didn't open: ${e.message}`));
  }, [open]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  return (
    <>
      {project ? (
        <AppProvider project={project} temp={temp} saveAs={saveAs}>
          <Shell onClose={close} toggleTheme={toggleTheme} />
        </AppProvider>
      ) : (
        <Welcome open={open} notice={notice} />
      )}
      <ConfirmHost />
    </>
  );
}

/** Sidebar: tools grouped by what you're doing. */
const NAV: { group: string; items: { id: Tab; label: string; icon: string }[] }[] = [
  {
    group: "Recon",
    items: [
      { id: "dashboard", label: "Overview", icon: "overview" },
      { id: "target", label: "Site map", icon: "sitemap" },
    ],
  },
  { group: "Capture", items: [{ id: "proxy", label: "Proxy", icon: "proxy" }] },
  {
    group: "Attack",
    items: [
      { id: "repeater", label: "Replay", icon: "replay" },
      { id: "fuzzer", label: "Fuzzer", icon: "fuzzer" },
      { id: "scanner", label: "Scans", icon: "scans" },
    ],
  },
  {
    group: "Results",
    items: [
      { id: "findings", label: "Findings", icon: "findings" },
      { id: "oob", label: "Callbacks", icon: "callbacks" },
    ],
  },
  {
    group: "Tools",
    items: [
      { id: "decoder", label: "Codec", icon: "codec" },
      { id: "comparer", label: "Diff", icon: "diff" },
    ],
  },
];

/** Ports tried in order when the app starts the proxy (another project may hold 8080). */
const PROXY_PORTS = [8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089];

interface ProxyStatus {
  running: boolean;
  proxy: { listen?: string; pid?: number } | null;
  pending_intercepts: number;
  intercept_enabled: boolean;
}

function Shell({ onClose, toggleTheme }: { onClose: () => void; toggleTheme: () => void }) {
  const app = useApp();
  const [scope, setScope] = useState<string[] | null>(null);
  const [engName, setEngName] = useState("");
  const [status, refreshStatus] = usePoll<ProxyStatus>(() => run(["proxy", "status"]), 2000);

  useEffect(() => {
    const load = () =>
      run(["engagement", "show"])
        .then((d) => {
          setScope(d.engagement?.include ?? []);
          setEngName(d.engagement?.name ?? "");
        })
        .catch(() => setScope([]));
    load();
    window.addEventListener(ENGAGEMENT_CHANGED, load);
    return () => window.removeEventListener(ENGAGEMENT_CHANGED, load);
  }, []);

  const [browsers, setBrowsers] = useState<{ id: string; name: string; kind: string }[]>([]);
  useEffect(() => {
    run<{ browsers: { id: string; name: string; kind: string }[] }>(["browser", "list"]).then((d) => setBrowsers(d.browsers), () => {});
  }, []);
  const browserMenu = useMenu();

  // Starts the proxy if needed, then a browser in this project's profile.
  const openBrowser = async (id: string) => {
    try {
      if (!status?.running) {
        await run(["proxy", "start"]);
        refreshStatus();
      }
      const d = await run<{ browser: { name: string }; note: string | null }>(["browser", "open", `--browser=${id}`]);
      app.toast(d.note ? `${d.browser.name} opened. ${d.note}` : `${d.browser.name} opened through the proxy. Browse the target; requests appear in Proxy › Traffic.`, "info");
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // The proxy starts with the project (unless turned off in Settings); one the app started
  // stops again when the project closes or the window does, so none are left behind.
  const startedHere = useRef(false);
  // `app` changes with every toast or tab switch; only a project change may restart the proxy.
  const toastRef = useRef(app.toast);
  toastRef.current = app.toast;
  useEffect(() => {
    if (!autoProxy()) return;
    let cancelled = false;
    (async () => {
      const s = await run<ProxyStatus>(["proxy", "status"]).catch(() => null);
      if (cancelled || !s || s.running) return;
      for (const port of PROXY_PORTS) {
        try {
          await run(["proxy", "start", `--listen=127.0.0.1:${port}`]);
          startedHere.current = true;
          refreshStatus();
          return;
        } catch (e: any) {
          if (!/cannot listen/i.test(e.message)) return toastRef.current(`The proxy didn't start: ${e.message}`, "error");
        }
      }
      toastRef.current(`The proxy didn't start: ports ${PROXY_PORTS.join(", ")} are all in use. Start it from the Proxy pill.`, "error");
    })();
    return () => {
      cancelled = true;
      if (startedHere.current) {
        startedHere.current = false;
        run(["proxy", "stop"]).catch(() => {});
      }
    };
  }, [app.project, refreshStatus]);

  const tempRef = useRef(app.temp);
  tempRef.current = app.temp;
  useEffect(() => {
    if (!inTauri) return;
    // Registering is async: a shell unmounted before it finishes (StrictMode's double mount, a
    // quick project switch) removes its listener once it arrives, so only one ever asks.
    let disposed = false;
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) =>
        getCurrentWindow().onCloseRequested(async (event) => {
          if (tempRef.current) {
            // Held open while the question is in the window; closed explicitly on "discard".
            event.preventDefault();
            if (!(await confirm(DISCARD_TITLE, DISCARD, "Discard and quit", "Keep open"))) return;
            // Stops its proxy too. If it fails, the next launch's sweep wipes it.
            await run(["project", "discard"]).catch(() => {});
            await getCurrentWindow().destroy();
          } else if (startedHere.current) {
            await run(["proxy", "stop"]).catch(() => {});
          }
        }),
      )
      .then((u) => (disposed ? u() : (unlisten = u)));
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const save = () => app.saveAs().catch((e) => app.toast(`Not saved: ${e.message}`, "error"));
  const tempTitle = app.temp
    ? `Temporary engagement, kept ${app.temp.ramBacked ? "in memory (RAM)" : "in the temp folder on disk"} and wiped when it closes. Click to save it as a project file.`
    : "";

  const proxyToggle = async () => {
    try {
      if (status?.running) await run(["proxy", "stop"]);
      else await run(["proxy", "start"]);
      refreshStatus();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const listen = status?.proxy?.listen ?? "127.0.0.1:8080";
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem("sidebar") === "collapsed";
    } catch {
      return false;
    }
  });
  const toggleSidebar = () =>
    setCollapsed((c) => {
      try {
        localStorage.setItem("sidebar", c ? "open" : "collapsed");
      } catch {
        /* storage unavailable */
      }
      return !c;
    });

  const navItem = (t: { id: Tab; label: string; icon: string }) => (
    <button key={t.id} className={`nav-item ${app.tab === t.id ? "on" : ""}`} onClick={() => app.setTab(t.id)} title={collapsed ? t.label : undefined}>
      <Icon name={t.icon} />
      <span className="nav-label">{t.label}</span>
      {t.id === "repeater" && app.repeater.length > 0 && <span className="count">{app.repeater.length}</span>}
    </button>
  );

  return (
    <div className={`app ${collapsed ? "nav-collapsed" : ""}`}>
      <header className="top">
        <div className="top-left">
          <div className="brand" onClick={onClose} title="Switch project">
            <Logo size={22} />
            <span className="brand-name">brainproxy</span>
          </div>
          <span className="project" title={app.project}>
            {app.temp ? engName || "Temporary engagement" : app.project.split("/").pop()}
          </span>
          {app.temp && (
            <button className="chip temp" onClick={save} title={tempTitle}>
              {app.temp.ramBacked ? "temp · in memory" : "temp · on disk"}
            </button>
          )}
          <div className="scope">
            {scope == null ? null : scope.length === 0 ? (
              <span className="chip warn" title="Nothing can be sent until engagement start sets the targets">
                no engagement scope
              </span>
            ) : (
              scope.map((s) => (
                <span key={s} className="chip" title="Engagement scope (write-once)">
                  {s}
                </span>
              ))
            )}
          </div>
        </div>
        <div className="top-right">
          {status?.intercept_enabled && (
            <button className="pill hold" onClick={() => app.setTab("proxy")}>
              Intercept on{status.pending_intercepts ? ` · ${status.pending_intercepts} held` : ""}
            </button>
          )}
          {browsers.length > 0 && (
            <button
              className="pill"
              onClick={(e) => {
                const r = e.currentTarget.getBoundingClientRect();
                browserMenu.open({ clientX: r.left, clientY: r.bottom + 4 }, browsers.map((b) => ({ label: `${b.name}${b.kind === "firefox" ? " (import the CA once)" : ""}`, action: () => openBrowser(b.id) })));
              }}
              title="Open a browser that goes through the proxy, in its own profile for this project"
            >
              <Icon name="globe" size={14} />
              Open browser
            </button>
          )}
          <button className={`pill ${status?.running ? "live" : ""}`} onClick={proxyToggle} title={status?.running ? "Stop the proxy" : "Start the proxy"}>
            <span className="dot" />
            {status?.running ? `Proxy ${listen}` : "Proxy off"}
          </button>
          <button className="icon-btn" onClick={toggleTheme} title="Toggle light/dark">
            <Icon name="theme" />
          </button>
        </div>
      </header>
      <div className="body">
        <aside className="sidebar">
          <nav className="nav-groups">
            {NAV.map((g) => (
              <div key={g.group} className="nav-group">
                <div className="nav-heading">{g.group}</div>
                {g.items.map(navItem)}
              </div>
            ))}
          </nav>
          <div className="nav-foot">
            {navItem({ id: "settings", label: "Settings", icon: "settings" })}
            {app.temp && (
              <button className="nav-item" onClick={save} title={collapsed ? "Save as…" : tempTitle}>
                <Icon name="save" />
                <span className="nav-label">Save as…</span>
              </button>
            )}
            <button className="nav-item" onClick={onClose} title={collapsed ? "Switch project" : undefined}>
              <Icon name="switch" />
              <span className="nav-label">Switch project</span>
            </button>
            <SideBrand collapsed={collapsed} />
            <button className="nav-item" onClick={toggleSidebar} title={collapsed ? "Expand" : "Collapse"}>
              <Icon name={collapsed ? "expand" : "collapse"} />
              <span className="nav-label">Collapse</span>
            </button>
            <div className="nav-version" title={`brainproxy ${version}`}>
              v{version}
            </div>
          </div>
        </aside>
      <main className="view">
        {/* Views stay mounted so their state survives tab switches. */}
        <div hidden={app.tab !== "dashboard"} className="view-slot">
          <Boundary><DashboardView active={app.tab === "dashboard"} /></Boundary>
        </div>
        <div hidden={app.tab !== "target"} className="view-slot">
          <Boundary><TargetView active={app.tab === "target"} /></Boundary>
        </div>
        <div hidden={app.tab !== "proxy"} className="view-slot">
          <Boundary><ProxyView /></Boundary>
        </div>
        <div hidden={app.tab !== "repeater"} className="view-slot">
          <Boundary><RepeaterView /></Boundary>
        </div>
        <div hidden={app.tab !== "fuzzer"} className="view-slot">
          <Boundary><FuzzerView /></Boundary>
        </div>
        <div hidden={app.tab !== "scanner"} className="view-slot">
          <Boundary><ScannerView active={app.tab === "scanner"} /></Boundary>
        </div>
        <div hidden={app.tab !== "findings"} className="view-slot">
          <Boundary><FindingsView active={app.tab === "findings"} /></Boundary>
        </div>
        <div hidden={app.tab !== "oob"} className="view-slot">
          <Boundary><OobView active={app.tab === "oob"} /></Boundary>
        </div>
        <div hidden={app.tab !== "decoder"} className="view-slot">
          <Boundary><DecoderView /></Boundary>
        </div>
        <div hidden={app.tab !== "comparer"} className="view-slot">
          <Boundary><ComparerView /></Boundary>
        </div>
        <div hidden={app.tab !== "settings"} className="view-slot">
          <Boundary><SettingsView /></Boundary>
        </div>
      </main>
      </div>
      <Menu menu={browserMenu.menu} close={browserMenu.close} />
      <div className="toasts">
        {app.toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            {t.text}
          </div>
        ))}
      </div>
    </div>
  );
}
