import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { cancelCli, inTauri, run, setProject, tempProjects } from "./api";
import { AppProvider, autoProxy, useApp, type TempInfo } from "./store";
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
import { AccessView } from "./views/Access";
import { PROXY_PORTS, proxyListen, savedProxyPort, startPorts, startProxy, stopOwned, stopProxy } from "./views/proxyPort";
import { hostOf, isWildcard } from "./views/proxyMode";
import { narrowedNotice, SHOW_SCOPE, type RecordingChange, reroutedNotice } from "./views/recording";
import { Logo } from "./ui/Logo";
import { Icon } from "./ui/Icons";
import { SideBrand } from "./ui/Brand";
import { Boundary } from "./ui/Boundary";
import { Menu, useMenu } from "./ui/Menu";
import { ConfirmHost, confirm } from "./ui/Confirm";
import { FILTERS, Welcome, recent, remember, saveTempAs } from "./views/Welcome";
import { NAV, SETTINGS_NAV, type NavItem } from "./nav";
import { bindingOf, initBindings, type Action } from "./ui/actions.ts";
import { formatChord, isMac } from "./ui/chords.ts";
import { useActions, useOverrides, useShortcuts, withKey } from "./ui/useActions.ts";
import { Palette } from "./ui/Palette";
import { baseName } from "./views/deleteProject";
import { closeQuestion, stopAllCalls } from "./views/replayCalls";
import { onCloseRequested } from "./quit";
import { usePoll } from "./ui/usePoll";
import { leaveProject, leaver } from "./views/leave";
import { EngageHost, useEngage } from "./ui/Engage";
import { version } from "../package.json";

/** Mod is ⌘ here, Ctrl on Linux and Windows. */
const MAC = isMac();
initBindings(MAC);

const DISCARD_TITLE = "Discard this temporary engagement?";
const DISCARD = "Its traffic, findings and settings are deleted for good. Use Save as… first to keep them.";

/** Asks before leaving the project while Replay sends are running (leaving stops them); true to go on. */
async function stopSends(ok: string): Promise<boolean> {
  const q = closeQuestion();
  return !q || confirm(q.title, q.message, ok, "Keep open");
}

export function App() {
  const [project, setProj] = useState<string | null>(null);
  const [temp, setTemp] = useState<TempInfo | null>(null);
  /** Shown on the welcome screen, e.g. when a temporary project couldn't be deleted. */
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

  // `temp` is set for a temporary engagement (made by the shell); those never go in Recent.
  // `opened` is toasted in the project once it is open (from Save as…, whose shell is gone).
  const [opened, setOpened] = useState("");
  const open = useCallback(async (path: string, tempInfo: TempInfo | null = null, notice = "") => {
    setProject(path);
    await run(["project", "init"]);
    if (!tempInfo) remember(path);
    setTemp(tempInfo);
    setNotice("");
    setOpened(notice);
    setProj(path);
  }, []);

  // Leaving the project unmounts the shell, which stops a proxy it started. The shell's
  // discard also stops the proxy, OOB listener and jobs of a temporary one before deleting it;
  // if that fails it is kept, and offered again on the next launch. The shell has already asked
  // (and checked it is still on this project), so this closes straight away.
  const close = useCallback(async () => {

    const leaving = project;
    setProj(null);
    setTemp(null);
    if (temp && leaving)
      await tempProjects.discard(leaving).catch((e) => setNotice(`The temporary engagement wasn't deleted: ${e}`));
  }, [temp, project]);

  // Copies the temporary project to a file, then carries on in that file.
  const saveAs = useCallback(async () => {
    const leaving = project;
    if (!leaving) return;
    // The saved copy opens as a new project, so this one's sends stop.
    if (!(await stopSends("Stop and save"))) return;
    const eng = await run<{ engagement: { name: string | null } | null }>(["engagement", "show"]).catch(() => null);
    const saved = await saveTempAs(leaving, eng?.engagement?.name ?? "");
    if (!saved) return;
    const { dest, notice } = saved;
    setProj(null);
    setTemp(null);
    // The saved file has everything; if this fails it is offered again on the next launch.
    await tempProjects.discard(leaving).catch(() => {});
    // The shell is gone by now, so a failure is shown on the welcome screen.
    await open(dest, null, notice).catch((e) => setNotice(`Saved to ${dest}, but it didn't open: ${e.message}`));
  }, [open, project]);

  // Another project, from the palette's Recent or Open project…: the shell has closed this one.
  const openOther = useCallback((path: string) => open(path).catch((e) => setNotice(`${path} didn't open: ${e.message}`)), [open]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  return (
    <>
      {project ? (
        // Keyed by project: per-project state (Replay's sends and results among it) never carries over.
        <AppProvider key={project} project={project} temp={temp} saveAs={saveAs} notice={opened}>
          <Shell onClose={close} onOpen={openOther} toggleTheme={toggleTheme} />
        </AppProvider>
      ) : (
        <Welcome open={open} notice={notice} />
      )}
      <ConfirmHost />
    </>
  );
}

interface ProxyStatus {
  running: boolean;
  proxy: { listen?: string; pid?: number } | null;
  pending_intercepts: number;
  intercept_enabled: boolean;
  /** An agent's changes that narrowed what the proxy records, not changed by a person since. */
  recording_narrowed_by_agent?: RecordingChange[];
  routing_changed_by_agent?: RecordingChange[];
}

function Shell({ onClose, onOpen, toggleTheme }: { onClose: () => Promise<void>; onOpen: (path: string) => Promise<void>; toggleTheme: () => void }) {
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
      // During a port move the polled status is stale; startProxy waits for the move.
      if (!status?.running || app.proxy.moving) {
        await startProxy(run, app.proxy);
        refreshStatus();
      }
      const d = await run<{ browser: { name: string }; note: string | null }>(["browser", "open", `--browser=${id}`]);
      app.toast(d.note ? `${d.browser.name} opened. ${d.note}` : `${d.browser.name} opened through the proxy. Browse the target; requests appear in Proxy › Traffic.`, "info");
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // The proxy starts with the project (unless turned off in Settings). A proxy the app started
  // (here, from the pill, Open browser, Settings or Record a login) stops again when the project
  // closes or the window does, whatever that setting, so none are left behind holding the port;
  // one a shell or an agent started is left alone.
  const proxyCtl = app.proxy;
  // Pinned to this project: another may be open by the time it runs.
  const project = app.project;
  const inProject = (args: string[]) => run(args, { project });
  const stopOnClose = () => stopOwned(inProject, proxyCtl).catch(() => {});
  // `app` changes with every toast or tab switch; only a project change may restart the proxy.
  const toastRef = useRef(app.toast);
  toastRef.current = app.toast;
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!autoProxy()) return;
      const s = (await inProject(["proxy", "status"]).catch(() => null)) as ProxyStatus | null;
      if (cancelled || !s || s.running) return;
      const chosen = savedProxyPort();
      for (const port of startPorts(chosen)) {
        if (cancelled) return;
        try {
          // Pinned: the setup is read and the proxy started in this project, even if another opens meanwhile.
          const listen = await startProxy(inProject, proxyCtl, port);
          // The project closed while it started.
          if (cancelled) return stopOwned(inProject, proxyCtl).catch(() => {});
          refreshStatus();
          // Chosen for this project in Settings › Proxy, but easy to forget when opening it again.
          if (listen && isWildcard(hostOf(listen)))
            toastRef.current(
              "The proxy started on every network interface, as chosen for this project in Settings › Proxy: other machines can use it, with this project's auth profiles and platform auth.",
              "error",
            );
          return;
        } catch (e: any) {
          if (chosen || !/cannot listen/i.test(e.message)) return toastRef.current(`The proxy didn't start: ${e.message}`, "error");
        }
      }
      toastRef.current(`The proxy didn't start: none of ports ${PROXY_PORTS[0]}-${PROXY_PORTS.at(-1)} could be opened. Choose a port in Settings › Proxy.`, "error");
    })();
    return () => {
      cancelled = true;
      stopOnClose();
    };
  }, [app.project, refreshStatus]);

  const tempRef = useRef(app.temp ? app.project : null);
  tempRef.current = app.temp ? app.project : null;
  // Stable for the project's lifetime, so the close handler below can keep it.
  const { flushReplayTabs } = app;
  useEffect(() => {
    if (!inTauri) return;
    // Registering is async: a shell unmounted before it finishes (StrictMode's double mount, a
    // quick project switch) removes its listener once it arrives, so only one ever asks.
    let disposed = false;
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) =>
        getCurrentWindow().onCloseRequested(async (event) => {
          const tempProject = tempRef.current;
          return onCloseRequested({
            temp: tempProject != null,
            sending: () => closeQuestion() != null,
            preventDefault: () => event.preventDefault(),
            askSends: () => stopSends("Stop and quit"),
            askDiscard: () => confirm(DISCARD_TITLE, DISCARD, "Discard and quit", "Keep open"),
            stopSends: () => stopAllCalls(cancelCli),
            // Discarding stops its proxy too. If it fails, it is kept and offered on the next launch.
            // Otherwise Replay's last edits are saved, which would otherwise happen a moment later.
            leave: () =>
              tempProject ? tempProjects.discard(tempProject).catch(() => {}) : Promise.all([flushReplayTabs().catch(() => {}), stopOnClose()]).then(() => {}),
            destroy: () => getCurrentWindow().destroy(),
          });
        }),
      )
      .then((u) => (disposed ? u() : (unlisten = u)));
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  useEngage(app.toast);

  const save = () => app.saveAs().catch((e) => app.toast(`Not saved: ${e.message}`, "error"));
  // Switching project: Replay's tabs are saved before it closes (so reopening it shows them),
  // and if they can't be, it stays open unless the user chooses to close it anyway; a temporary
  // one is asked about instead. Clicks while that runs join it, and it closes nothing once this
  // shell or its project is gone.
  const leaving = useMemo(leaver, []);
  useEffect(() => leaving.attach(), [leaving, app.project]);
  // `then` runs once this project has closed (another opening, say).
  const leave = (then?: () => Promise<void>) =>
    leaving.run((stale) =>
      leaveProject({
        temp: !!app.temp,
        // Closing stops Replay's sends still running (the provider's cleanup).
        sends: () => stopSends("Stop and close"),
        flush: app.flushReplayTabs,
        ask: (e) =>
          confirm(
            "Close without saving Replay's tabs?",
            `They couldn't be saved to the project: ${e.message}. Changes since the last save are lost if it closes.`,
            "Close anyway",
            "Keep open",
          ),
        discard: () => confirm(DISCARD_TITLE, DISCARD, "Discard", "Keep open"),
        close: then ? () => onClose().then(then) : onClose,
        stale,
      }),
    );
  const tempTitle = app.temp
    ? `Temporary engagement, kept ${app.temp.ramBacked ? "in memory (RAM)" : "in the temp folder on disk"} and deleted when you discard it. Click to save it as a project file.`
    : "";

  const proxyToggle = async () => {
    if (app.proxy.moving) return app.toast("The proxy is restarting on another port. Try again in a moment.");
    try {
      if (status?.running) await stopProxy(run, app.proxy);
      else await startProxy(run, app.proxy);
      refreshStatus();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const listen = status?.proxy?.listen ?? proxyListen();
  // On 0.0.0.0 or [::]: other machines can use it, so it is shown however it was started.
  const exposed = !!status?.running && isWildcard(hostOf(listen));
  const narrowed = narrowedNotice(status?.recording_narrowed_by_agent);
  const rerouted = reroutedNotice(status?.routing_changed_by_agent);
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

  const [palette, setPalette] = useState(false);
  useShortcuts(app.tab, MAC);
  // Opens another project once this one has closed (asking what closing asks first).
  const switchTo = (path: string) => {
    if (path === app.project) return app.toast("That project is open already.");
    leave(() => onOpen(path));
  };
  const openProject = async () => {
    const dialog = await import("@tauri-apps/plugin-dialog");
    const p = await dialog.open({ filters: FILTERS, multiple: false });
    if (typeof p === "string") switchTo(p);
  };
  // Recent changes only when a project opens, so read once for this one.
  const recents = useMemo(() => recent().filter((p) => p !== app.project), [app.project]);
  // Mod+digit and Mod+, mean nothing in a text field, so they go to a view from one too.
  const goTo = (t: NavItem): Action => ({ id: `go.${t.id}`, title: t.label, group: "Go to", keys: t.keys, typing: true, run: () => app.setTab(t.id) });
  useActions([
    { id: "app.palette", title: "Open the command palette", group: "App", keys: "Mod+K", typing: true, noPalette: true, run: () => setPalette(true) },
    ...NAV.flatMap((g) => g.items).map(goTo),
    goTo(SETTINGS_NAV),
    {
      id: "proxy.toggle",
      title: status?.running ? "Stop the proxy" : "Start the proxy",
      group: "Proxy",
      keywords: "proxy on off listen",
      disabled: app.proxy.moving ? "The proxy is restarting on another port" : false,
      run: proxyToggle,
    },
    ...browsers.map((b) => ({ id: `browser.open.${b.id}`, title: `Open ${b.name} through the proxy`, group: "Proxy", keywords: "browser launch", run: () => openBrowser(b.id) })),
    { id: "scan.guided", title: "Start a guided scan", group: "Scans", keywords: "wizard overview", run: () => app.openWizard(true) },
    { id: "app.theme", title: "Switch between light and dark", group: "App", keywords: "theme dark light mode", run: toggleTheme },
    { id: "app.sidebar", title: collapsed ? "Expand the sidebar" : "Collapse the sidebar", group: "App", keys: "Mod+B", keywords: "sidebar navigation", run: toggleSidebar },
    { id: "project.switch", title: "Switch project", group: "Project", keywords: "close welcome", run: () => leave() },
    { id: "project.open", title: "Open a project file…", group: "Project", keywords: "bpdb browse", hidden: !inTauri, run: openProject },
    { id: "project.saveAs", title: "Save the temporary engagement as…", group: "Project", keywords: "save file", hidden: !app.temp, run: save },
    ...recents.map((p) => ({ id: `project.recent.${p}`, title: `Open ${baseName(p)}`, group: "Recent projects", keywords: p, unbindable: true, run: () => switchTo(p) })),
  ]);

  const overrides = useOverrides();
  const navItem = (t: NavItem) => {
    const chord = bindingOf({ id: `go.${t.id}`, title: t.label, group: "Go to", keys: t.keys }, overrides);
    const key = chord ? formatChord(chord, MAC) : "";
    return (
    <button key={t.id} className={`nav-item ${app.tab === t.id ? "on" : ""}`} onClick={() => app.setTab(t.id)} title={collapsed ? withKey(t.label, key) : key || undefined}>
      <Icon name={t.icon} />
      <span className="nav-label">{t.label}</span>
      {t.id === "repeater" && app.repeater.length > 0 && <span className="count">{app.repeater.length}</span>}
    </button>
    );
  };

  return (
    <div className={`app ${collapsed ? "nav-collapsed" : ""}`}>
      <header className="top">
        <div className="top-left">
          <div className="brand" onClick={() => leave()} title="Switch project">
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
          {narrowed && (
            <button
              className="pill hold"
              onClick={() => {
                app.setTab("target");
                window.dispatchEvent(new Event(SHOW_SCOPE));
              }}
              title={`${narrowed}\nTraffic left out keeps only its request line (or a tunnel's row). Target › Scope lists the changes. Changing a setting yourself clears that setting's flag (the scope's or the pass-through list's), and Keep as it is there clears every flag shown.`}
            >
              Recording narrowed by an agent
            </button>
          )}
          {rerouted && (
            <button
              className="pill hold"
              onClick={() => {
                app.setTab("target");
                window.dispatchEvent(new Event(SHOW_SCOPE));
              }}
              title={`${rerouted}\nTraffic to those hosts goes where the agent set. Target › Scope lists the changes. Changing a setting yourself clears its flag, and Keep as it is there clears them all.`}
            >
              Routing changed by an agent
            </button>
          )}
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
          <button
            className={`pill ${status?.running ? "live" : ""} ${exposed ? "exposed" : ""}`}
            onClick={proxyToggle}
            title={
              exposed
                ? "Listening on every network interface: anyone who can reach this computer can use the proxy (Settings › Proxy). Click to stop it."
                : status?.running
                  ? "Stop the proxy"
                  : "Start the proxy"
            }
          >
            <span className="dot" />
            {status?.running ? `Proxy ${listen}${exposed ? " · open to the network" : ""}` : "Proxy off"}
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
            {navItem(SETTINGS_NAV)}
            {app.temp && (
              <button className="nav-item" onClick={save} title={collapsed ? "Save as…" : tempTitle}>
                <Icon name="save" />
                <span className="nav-label">Save as…</span>
              </button>
            )}
            <button className="nav-item" onClick={() => leave()} title={collapsed ? "Switch project" : undefined}>
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
        <div hidden={app.tab !== "access"} className="view-slot">
          <Boundary><AccessView active={app.tab === "access"} /></Boundary>
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
      {palette && <Palette view={app.tab} mac={MAC} close={() => setPalette(false)} />}
      <EngageHost />
      <div className="toasts">
        {app.toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}${t.onClick ? " clickable" : ""}`} onClick={t.onClick}>
            {t.text}
          </div>
        ))}
      </div>
    </div>
  );
}
