// The port the app's proxy listens on (Settings › Proxy): the saved choice, the address it makes,
// and starting or moving the proxy with it. `cli` is api.ts's `run`.

import { proxyOptions } from "./accessMatrix.ts";

type Cli = (args: string[]) => Promise<unknown>;

export const PROXY_PORT = "proxy-port";

/** The `proxy start` default, and the first port tried in automatic mode. */
export const DEFAULT_PROXY_PORT = 8080;

/** Ports tried in order in automatic mode (another project may hold 8080). */
export const PROXY_PORTS = [8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089];

/** The ports to try when a project opens: a chosen one is used as is. */
export function startPorts(chosen: number | null): number[] {
  return chosen ? [chosen] : PROXY_PORTS;
}

/** What's wrong with a typed port, or null if it's fine. Empty is fine: it means automatic. */
export function portProblem(text: string): string | null {
  const t = text.trim();
  if (!t) return null;
  const port = /^[0-9]+$/.test(t) ? Number(t) : 0;
  return port >= 1 && port <= 65535 ? null : "Enter a port from 1 to 65535";
}

/** A note for ports the system may not let an ordinary user open. */
export function lowPortNote(port: number): string | null {
  return port < 1024 ? "Ports below 1024 may need elevated privileges." : null;
}

/** The chosen port; null for automatic, also when the stored value is invalid or storage is unavailable. */
export function savedProxyPort(): number | null {
  try {
    const text = localStorage.getItem(PROXY_PORT)?.trim();
    return text && !portProblem(text) ? Number(text) : null;
  } catch {
    return null;
  }
}

/** Stores the chosen port (null: automatic); false when it couldn't be stored. */
export function saveProxyPort(port: number | null): boolean {
  try {
    if (port == null) localStorage.removeItem(PROXY_PORT);
    else localStorage.setItem(PROXY_PORT, String(port));
    return true;
  } catch {
    return false;
  }
}

/** The address the app starts the proxy on. */
export function proxyListen(port = savedProxyPort()): string {
  return `127.0.0.1:${port ?? DEFAULT_PROXY_PORT}`;
}

/** The port of `host:port` (the last colon, for `[::1]:8080`); null if it isn't a usable one. */
export function portOf(listen: string): number | null {
  const text = listen.slice(listen.lastIndexOf(":") + 1);
  return text && !portProblem(text) ? Number(text) : null;
}

/** `listen` with another port, on the same host. */
export function withPort(listen: string, port: number): string {
  return `${listen.slice(0, listen.lastIndexOf(":"))}:${port}`;
}

/** A failed bind's message, without its error kind and with where to fix it; other messages unchanged. */
export function withPortHint(message: string): string {
  return /cannot listen/i.test(message) ? `${message.replace(/^conflict: /, "")}. Choose another port in Settings › Proxy.` : message;
}

/** The app's hold on its project's proxy, shared by every view that starts it (store.tsx keeps one per project). */
export interface ProxyControl {
  /** The pid of the proxy the app started; only that one is stopped when the project closes. */
  owned: number | null;
  /** Set while a move restarts the proxy on another port; other starts in the app wait for it. Never rejects. */
  moving: Promise<void> | null;
}

export function proxyControl(): ProxyControl {
  return { owned: null, moving: null };
}

interface Status {
  running: boolean;
  proxy: { listen: string; pid?: number } | null;
  other_pid_namespace?: boolean;
}

const pidOf = (started: unknown) => (started as { pid?: number } | null)?.pid ?? null;

/**
 * Starts the proxy on `port` (the saved one by default) and records it as the app's. During a
 * move it waits for that first, and starts nothing if the proxy is up after it: false then.
 */
export async function startProxy(cli: Cli, ctl: ProxyControl, port = savedProxyPort()): Promise<boolean> {
  if (ctl.moving) {
    await ctl.moving;
    if (((await cli(["proxy", "status"])) as Status).running) return false;
  }
  try {
    ctl.owned = pidOf(await cli(["proxy", "start", `--listen=${proxyListen(port)}`]));
  } catch (e: any) {
    e.message = withPortHint(e.message);
    throw e;
  }
  return true;
}

/** Stops the proxy, whoever started it; it is no longer the app's. */
export async function stopProxy(cli: Cli, ctl: ProxyControl): Promise<void> {
  await cli(["proxy", "stop"]);
  ctl.owned = null;
}

/**
 * Stops the proxy the app started, if it is still the one running: not one a shell or an agent
 * started since, one in another container, or a record that can't be verified.
 */
export async function stopOwned(cli: Cli, ctl: ProxyControl): Promise<void> {
  await ctl.moving;
  const pid = ctl.owned;
  ctl.owned = null;
  if (pid == null) return;
  const s = (await cli(["proxy", "status"])) as Status;
  if (s.running && s.proxy?.pid === pid && !s.other_pid_namespace) await cli(["proxy", "stop"]);
}

/** Where the proxy is now, from a fresh `proxy status`: the end of a failed move's message. */
async function whereNow(cli: Cli, was: string): Promise<string> {
  const s = (await cli(["proxy", "status"]).catch(() => null)) as Status | null;
  if (!s) return "Check in the top bar whether the proxy is running.";
  if (!s.running || !s.proxy) return "The proxy is off.";
  return s.proxy.listen === was ? `The proxy is back on ${was}.` : `The proxy is on ${s.proxy.listen}.`;
}

/**
 * A failed `proxy restart`, from its message. Once it has stopped the proxy, the CLI adds whether
 * it started it again where it was (and its pid): `stopped`, `pid`, and `message` without that
 * part, since the app says where the proxy is from a fresh status.
 */
export function restartFailure(message: string): { message: string; stopped: boolean; pid: number | null } {
  const m = /; the proxy (?:was started again on \S+ \(pid (\d+)\)$|couldn't be started again on [\s\S]*$)/.exec(message);
  if (!m) return { message, stopped: false, pid: null };
  return { message: message.slice(0, m.index), stopped: true, pid: m[1] ? Number(m[1]) : null };
}

type Running = { listen: string; pid?: number; args?: string[] };

/**
 * Restarts a running proxy on `port`, with the same host and options; returns the new address. It
 * is one `proxy restart`, so a start from a shell or an agent can't get in between. If the proxy
 * doesn't come up there, the CLI starts it again where it was, and the error says where it is now.
 * Starts from elsewhere in the app wait until it is done. The proxy stays the app's if it was.
 */
export async function moveProxy(cli: Cli, ctl: ProxyControl, running: Running, port: number): Promise<string> {
  const work = move(cli, ctl, running, port);
  const moving = work.then(
    () => {},
    () => {},
  );
  ctl.moving = moving;
  try {
    return await work;
  } finally {
    if (ctl.moving === moving) ctl.moving = null;
  }
}

async function move(cli: Cli, ctl: ProxyControl, running: Running, port: number): Promise<string> {
  const ours = ctl.owned != null && ctl.owned === running.pid;
  const target = withPort(running.listen, port);
  try {
    const pid = pidOf(await cli(["proxy", "restart", `--listen=${target}`, ...proxyOptions(running.args ?? [])]));
    if (ours) ctl.owned = pid;
  } catch (e: any) {
    const failed = restartFailure(e.message);
    // Refused before anything stopped: the proxy runs as it did.
    if (!failed.stopped) throw e;
    if (ours) ctl.owned = failed.pid;
    throw new Error(`${withPortHint(failed.message)} ${await whereNow(cli, running.listen)}`);
  }
  return target;
}
