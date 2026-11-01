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

/** Starts the proxy on the saved port. */
export async function startProxy(cli: Cli): Promise<void> {
  try {
    await cli(["proxy", "start", `--listen=${proxyListen()}`]);
  } catch (e: any) {
    e.message = withPortHint(e.message);
    throw e;
  }
}

/**
 * Restarts a running proxy on `port`, with the same host and options; returns the new address. If
 * it doesn't come up there, the proxy is started again where it was and the error says how that went.
 */
export async function moveProxy(cli: Cli, running: { listen: string; args?: string[] }, port: number): Promise<string> {
  const target = withPort(running.listen, port);
  const options = proxyOptions(running.args ?? []);
  await cli(["proxy", "stop"]);
  try {
    await cli(["proxy", "start", `--listen=${target}`, ...options]);
  } catch (e: any) {
    const back = await cli(["proxy", "start", `--listen=${running.listen}`, ...options]).then(
      () => `The proxy is back on ${running.listen}.`,
      () => "The proxy is off.",
    );
    throw new Error(`${withPortHint(e.message)} ${back}`);
  }
  return target;
}
