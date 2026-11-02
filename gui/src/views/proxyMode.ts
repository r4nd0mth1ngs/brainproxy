// How the app's proxy listens (Settings › Proxy), besides its port: on this machine only or on
// every network interface, invisible mode, and a redirect that sends everything to one origin.
// Kept per project, as one value under its path, so a save is all or nothing: on every interface
// other machines' requests pick up that project's auth profiles and platform auth, so the choice
// is never carried to another project, and the redirect has to be in that engagement's scope.

import { proxyOptions } from "./accessMatrix.ts";

/** Followed by the project's path. */
export const PROXY_SETUP = "proxy-setup:";

export const LOCAL_HOST = "127.0.0.1";
export const ALL_HOST = "0.0.0.0";

export interface ProxySetup {
  /** Listen on every network interface (0.0.0.0), not only on this machine (127.0.0.1). */
  allInterfaces: boolean;
  /** Also serve clients that don't know they're proxied (`--invisible`). */
  invisible: boolean;
  /** The origin every request from the listener goes to (`--redirect`, implies invisible); null for none. */
  redirect: string | null;
}

export const DEFAULT_SETUP: ProxySetup = { allInterfaces: false, invisible: false, redirect: null };

/** What's wrong with a typed redirect URL, or null if it's fine. Empty is fine: it means none. */
export function redirectProblem(text: string): string | null {
  const t = text.trim();
  if (!t) return null;
  if (!/^https?:\/\//i.test(t)) return "Start with http:// or https://";
  let url: URL;
  try {
    url = new URL(t);
  } catch {
    return "Enter a URL like https://app.example.test:8443";
  }
  if (!url.hostname) return "Enter a host";
  if (url.username || url.password) return "Leave out the user name and password";
  if (url.port === "0") return "Enter a port from 1 to 65535";
  if (url.pathname !== "/" || url.search || url.hash || /[?#]/.test(t)) {
    return "Enter only the scheme, host and port: each request keeps its own path";
  }
  return null;
}

/** A valid redirect URL as an origin (`scheme://host[:port]`, default port left out); null if empty or invalid. */
export function redirectOrigin(text: string): string | null {
  if (!text.trim() || redirectProblem(text)) return null;
  const url = new URL(text.trim());
  return `${url.protocol}//${url.host}`;
}

/** `engagement check` for a redirect origin. */
export function scopeCheckArgs(origin: string): string[] {
  return ["engagement", "check", "--", origin];
}

interface ScopeCheck {
  results: { port: number; allowed: boolean; reason?: string }[];
}

/** Why `engagement check` refused the origin, or null if it is in scope. */
export function scopeProblem(check: ScopeCheck): string | null {
  const refused = check.results.find((r) => !r.allowed);
  if (!check.results.length) return "It couldn't be checked against the engagement scope.";
  return refused ? `It isn't in this engagement's scope${refused.reason ? `: ${refused.reason}` : "."}` : null;
}

/** The saved setup for `project`; defaults for anything unset, invalid or unreadable, and without a project. */
export function savedProxySetup(project?: string): ProxySetup {
  if (!project) return DEFAULT_SETUP;
  let saved: any;
  try {
    saved = JSON.parse(localStorage.getItem(PROXY_SETUP + project) ?? "null");
  } catch {
    return DEFAULT_SETUP;
  }
  if (!saved || typeof saved !== "object") return DEFAULT_SETUP;
  return {
    allInterfaces: saved.network === "all",
    invisible: saved.invisible === true,
    redirect: typeof saved.redirect === "string" ? redirectOrigin(saved.redirect) : null,
  };
}

/** Stores the setup for `project`, in one write; false when it couldn't be stored. */
export function saveProxySetup(setup: ProxySetup, project: string): boolean {
  const redirect = setup.redirect ? redirectOrigin(setup.redirect) : null;
  const value = {
    ...(setup.allInterfaces ? { network: "all" } : {}),
    ...(setup.invisible ? { invisible: true } : {}),
    ...(redirect ? { redirect } : {}),
  };
  try {
    if (Object.keys(value).length) localStorage.setItem(PROXY_SETUP + project, JSON.stringify(value));
    else localStorage.removeItem(PROXY_SETUP + project);
    return true;
  } catch {
    return false;
  }
}

/**
 * Carries a project's setup over to its new path (Save as…), replacing whatever that path had;
 * false when it couldn't be.
 */
export function moveProxySetup(from: string, to: string): boolean {
  try {
    const value = localStorage.getItem(PROXY_SETUP + from);
    if (value != null) localStorage.setItem(PROXY_SETUP + to, value);
    else localStorage.removeItem(PROXY_SETUP + to);
    localStorage.removeItem(PROXY_SETUP + from);
    return true;
  } catch {
    // Never leave the new path with what it had before.
    forgetProxySetup(to);
    return false;
  }
}

/** Forgets the setup kept for a path: a deleted project's, or one left over where a new project is made. */
export function forgetProxySetup(project: string) {
  try {
    localStorage.removeItem(PROXY_SETUP + project);
  } catch {
    /* storage unavailable */
  }
}

/** A scope check's refusal, for the origin it was made for. */
export interface Refusal {
  origin: string;
  why: string;
}

/** What's wrong with the typed redirect: invalid, or refused by the scope check made for this very origin. */
export function redirectError(text: string, refused: Refusal | null): string | null {
  const origin = redirectOrigin(text);
  return redirectProblem(text) ?? (refused && origin === refused.origin ? refused.why : null);
}

/**
 * The origin Save has to check against the engagement scope: a valid one other than the saved
 * one. Also one refused before: the check fails when the name doesn't resolve, which may have
 * changed, and a host override may have been added since.
 */
export function redirectToCheck(text: string, saved: string | null): string | null {
  const origin = redirectOrigin(text);
  return origin && origin !== saved ? origin : null;
}

/** The host the proxy listens on. */
export function setupHost(setup: ProxySetup): string {
  return setup.allInterfaces ? ALL_HOST : LOCAL_HOST;
}

/** The `proxy start` options for invisible mode and the redirect. */
export function setupOptions(setup: ProxySetup): string[] {
  if (setup.redirect) return [`--redirect=${setup.redirect}`];
  return setup.invisible ? ["--invisible"] : [];
}

const MODE_OPTIONS = ["--invisible", "--redirect"];

/** `options` from `proxyOptions` with the setup's invisible mode and redirect in place of theirs. */
export function withSetup(options: string[], setup: ProxySetup): string[] {
  return [...options.filter((o) => !MODE_OPTIONS.includes(o.split("=", 1)[0])), ...setupOptions(setup)];
}

/** The host of `host:port`. */
export function hostOf(listen: string): string {
  return listen.slice(0, Math.max(listen.lastIndexOf(":"), 0));
}

export const isLoopback = (host: string) => /^127\.\d+\.\d+\.\d+$/.test(host) || host === "[::1]" || host.toLowerCase() === "localhost";
export const isWildcard = (host: string) => host === ALL_HOST || host === "[::]";

/** Where a restart with `setup` listens: a running address that already fits it is kept (`[::1]`, `[::]`). */
export function targetHost(setup: ProxySetup, listen: string): string {
  const host = hostOf(listen);
  return (setup.allInterfaces ? isWildcard(host) : isLoopback(host)) ? host : setupHost(setup);
}

/**
 * For a proxy on a wildcard address (`0.0.0.0`, `[::]`): what other devices connect to, since the
 * address itself isn't one. Null otherwise.
 */
export function networkNote(listen: string): string | null {
  if (!isWildcard(hostOf(listen))) return null;
  const port = listen.slice(listen.lastIndexOf(":") + 1);
  return `Other devices use this computer's address on their network (its LAN IP, such as 192.168.1.20) on port ${port}: http://LAN-IP:${port}.`;
}

type Running = { listen: string; args?: string[] };

/** The setup a running proxy has, from its address and its `proxy run` arguments. */
export function runningSetup(running: Running): ProxySetup {
  const options = proxyOptions(running.args ?? []);
  const value = options.find((o) => o.startsWith("--redirect="))?.slice(11) ?? null;
  return {
    allInterfaces: isWildcard(hostOf(running.listen)),
    invisible: options.includes("--invisible") || value != null,
    redirect: value == null ? null : (redirectOrigin(value) ?? value),
  };
}

/**
 * What a running proxy would change to with the saved port (null: automatic, any port fits) and
 * setup, in words; empty when it already runs that way.
 */
export function setupChanges(running: Running, port: number | null, setup: ProxySetup): string[] {
  const now = runningSetup(running);
  const host = hostOf(running.listen);
  const portNow = Number(running.listen.slice(running.listen.lastIndexOf(":") + 1));
  const out: string[] = [];
  if (port != null && portNow !== port) out.push(`port ${port}`);
  if (setup.allInterfaces ? !isWildcard(host) : !isLoopback(host)) out.push(setup.allInterfaces ? "every network interface" : "this computer only");
  const invisible = setup.invisible || setup.redirect != null;
  if (invisible !== now.invisible) out.push(invisible ? "invisible mode" : "invisible mode off");
  if (setup.redirect !== now.redirect) out.push(setup.redirect ? `everything sent to ${setup.redirect}` : "no redirect");
  return out;
}
