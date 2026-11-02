import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_SETUP,
  PROXY_INVISIBLE,
  PROXY_NETWORK,
  PROXY_REDIRECT,
  forgetRedirect,
  hostOf,
  isLoopback,
  isWildcard,
  moveRedirect,
  networkNote,
  redirectError,
  redirectOrigin,
  redirectProblem,
  runningSetup,
  saveProxySetup,
  savedProxySetup,
  scopeCheckArgs,
  scopeProblem,
  setupChanges,
  setupHost,
  setupOptions,
  targetHost,
  withSetup,
} from "./proxyMode.ts";
import { proxyOptions } from "./accessMatrix.ts";

// localStorage: a small stub on globalThis, put back after each test.
const realStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");

function stubStorage(initial: Record<string, string> = {}, overrides: object = {}) {
  const items = new Map(Object.entries(initial));
  const stub = {
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => void items.set(key, value),
    removeItem: (key: string) => void items.delete(key),
    ...overrides,
  };
  Object.defineProperty(globalThis, "localStorage", { value: stub, configurable: true, writable: true });
  return items;
}

afterEach(() => {
  delete (globalThis as any).localStorage;
  if (realStorage) Object.defineProperty(globalThis, "localStorage", realStorage);
});

const PROJECT = "/work/acme.bpdb";

test("redirectProblem accepts empty (none) and http(s) origins", () => {
  for (const text of ["", "  ", "https://app.acme.test", "http://app.acme.test:8080", " https://app.acme.test/ ", "HTTPS://App.Acme.Test:8443", "http://10.0.0.5:81", "https://[::1]:8443"]) {
    assert.equal(redirectProblem(text), null, JSON.stringify(text));
  }
});

test("redirectProblem rejects everything else, saying why", () => {
  const cases: [string, RegExp][] = [
    ["app.acme.test", /http:\/\/ or https:\/\//],
    ["ftp://app.acme.test", /http:\/\/ or https:\/\//],
    ["https://", /URL like/],
    ["https://app.acme.test:99999", /URL like/],
    ["https://app acme.test", /URL like/],
    ["https://app.acme.test:0", /port from 1 to 65535/],
    ["https://me:pw@app.acme.test", /user name and password/],
    ["https://app.acme.test/api", /scheme, host and port/],
    ["https://app.acme.test/?a=1", /scheme, host and port/],
    ["https://app.acme.test/#x", /scheme, host and port/],
    ["https://app.acme.test?", /scheme, host and port/],
  ];
  for (const [text, why] of cases) assert.match(redirectProblem(text) ?? "", why, text);
});

test("redirectOrigin: scheme://host[:port], the default port left out", () => {
  assert.equal(redirectOrigin("HTTPS://App.Acme.Test:443/"), "https://app.acme.test");
  assert.equal(redirectOrigin(" http://app.acme.test:8080 "), "http://app.acme.test:8080");
  assert.equal(redirectOrigin("http://app.acme.test:443"), "http://app.acme.test:443");
  assert.equal(redirectOrigin("https://[::1]:8443"), "https://[::1]:8443");
  for (const text of ["", "app.acme.test", "https://app.acme.test/api"]) assert.equal(redirectOrigin(text), null, text);
});

test("the scope check: engagement check on the origin, and its answer", () => {
  assert.deepEqual(scopeCheckArgs("https://app.acme.test"), ["engagement", "check", "--", "https://app.acme.test"]);
  assert.equal(scopeProblem({ results: [{ port: 443, allowed: true }] }), null);
  assert.equal(
    scopeProblem({ results: [{ port: 443, allowed: false, reason: "evil.test is outside the engagement scope" }] }),
    "It isn't in this engagement's scope: evil.test is outside the engagement scope",
  );
  assert.equal(scopeProblem({ results: [{ port: 443, allowed: false }] }), "It isn't in this engagement's scope.");
  assert.match(scopeProblem({ results: [] })!, /couldn't be checked/);
});

test("the setup round-trips: network and invisible for every project, the redirect per project", () => {
  const items = stubStorage();
  assert.deepEqual(savedProxySetup(PROJECT), DEFAULT_SETUP);
  const setup = { allInterfaces: true, invisible: true, redirect: "https://app.acme.test" };
  assert.equal(saveProxySetup(setup, PROJECT), true);
  assert.equal(items.get(PROXY_NETWORK), "all");
  assert.equal(items.get(PROXY_INVISIBLE), "on");
  assert.equal(items.get(PROXY_REDIRECT + PROJECT), "https://app.acme.test");
  assert.deepEqual(savedProxySetup(PROJECT), setup);
  assert.deepEqual(savedProxySetup("/work/other.bpdb"), { ...setup, redirect: null });
  assert.deepEqual(savedProxySetup(), { ...setup, redirect: null });

  assert.equal(saveProxySetup(DEFAULT_SETUP, PROJECT), true);
  assert.equal(items.size, 0);
  assert.deepEqual(savedProxySetup(PROJECT), DEFAULT_SETUP);
});

test("a corrupt saved setup falls back to the defaults", () => {
  stubStorage({ [PROXY_NETWORK]: "yes", [PROXY_INVISIBLE]: "true", [PROXY_REDIRECT + PROJECT]: "ftp://x" });
  assert.deepEqual(savedProxySetup(PROJECT), DEFAULT_SETUP);
});

test("storage that throws, or none: the defaults, and saving says it failed", () => {
  const fail = () => {
    throw new Error("denied");
  };
  stubStorage({}, { getItem: fail, setItem: fail, removeItem: fail });
  assert.deepEqual(savedProxySetup(PROJECT), DEFAULT_SETUP);
  assert.equal(saveProxySetup(DEFAULT_SETUP, PROJECT), false);
  delete (globalThis as any).localStorage;
  assert.deepEqual(savedProxySetup(PROJECT), DEFAULT_SETUP);
  assert.equal(saveProxySetup(DEFAULT_SETUP, PROJECT), false);
});

test("the address and options the setup starts the proxy with", () => {
  assert.equal(setupHost(DEFAULT_SETUP), "127.0.0.1");
  assert.equal(setupHost({ ...DEFAULT_SETUP, allInterfaces: true }), "0.0.0.0");
  assert.deepEqual(setupOptions(DEFAULT_SETUP), []);
  assert.deepEqual(setupOptions({ ...DEFAULT_SETUP, invisible: true }), ["--invisible"]);
  // The redirect implies invisible mode.
  assert.deepEqual(setupOptions({ ...DEFAULT_SETUP, redirect: "https://app.acme.test" }), ["--redirect=https://app.acme.test"]);
  assert.deepEqual(setupOptions({ ...DEFAULT_SETUP, invisible: true, redirect: "https://app.acme.test" }), ["--redirect=https://app.acme.test"]);
});

test("withSetup replaces invisible mode and the redirect, and keeps the other options", () => {
  const options = ["--timeout=30", "--invisible", "--redirect=http://old.test", "--auth=alice"];
  assert.deepEqual(withSetup(options, DEFAULT_SETUP), ["--timeout=30", "--auth=alice"]);
  assert.deepEqual(withSetup(options, { ...DEFAULT_SETUP, redirect: "https://app.acme.test" }), ["--timeout=30", "--auth=alice", "--redirect=https://app.acme.test"]);
  assert.deepEqual(withSetup(["--verify-tls"], { ...DEFAULT_SETUP, invisible: true }), ["--verify-tls", "--invisible"]);
});

test("targetHost keeps a running address that already fits", () => {
  const local = DEFAULT_SETUP;
  const all = { ...DEFAULT_SETUP, allInterfaces: true };
  assert.equal(hostOf("[::1]:8080"), "[::1]");
  for (const host of ["127.0.0.1", "127.0.0.2", "[::1]", "localhost"]) assert.equal(targetHost(local, `${host}:8080`), host);
  for (const host of ["0.0.0.0", "[::]", "192.168.1.5"]) assert.equal(targetHost(local, `${host}:8080`), "127.0.0.1");
  for (const host of ["0.0.0.0", "[::]"]) assert.equal(targetHost(all, `${host}:8080`), host);
  for (const host of ["127.0.0.1", "[::1]", "192.168.1.5"]) assert.equal(targetHost(all, `${host}:8080`), "0.0.0.0");
});

test("runningSetup reads the address and the proxy run arguments", () => {
  assert.deepEqual(runningSetup({ listen: "127.0.0.1:8080" }), DEFAULT_SETUP);
  assert.deepEqual(runningSetup({ listen: "0.0.0.0:80", args: ["proxy", "run", "--listen", "0.0.0.0:80", "--invisible"] }), {
    allInterfaces: true,
    invisible: true,
    redirect: null,
  });
  // As typed in a shell: normalised to the origin.
  assert.deepEqual(runningSetup({ listen: "127.0.0.1:8443", args: ["proxy", "run", "--redirect", "HTTPS://App.Acme.Test/"] }), {
    allInterfaces: false,
    invisible: true,
    redirect: "https://app.acme.test",
  });
});

test("setupChanges: nothing when the proxy already runs that way", () => {
  assert.deepEqual(setupChanges({ listen: "127.0.0.1:8080" }, null, DEFAULT_SETUP), []);
  assert.deepEqual(setupChanges({ listen: "127.0.0.1:8081" }, null, DEFAULT_SETUP), []);
  assert.deepEqual(setupChanges({ listen: "[::1]:8080" }, 8080, DEFAULT_SETUP), []);
  const running = { listen: "0.0.0.0:80", args: ["proxy", "run", "--listen", "0.0.0.0:80", "--redirect", "https://app.acme.test:443"] };
  assert.deepEqual(setupChanges(running, 80, { allInterfaces: true, invisible: false, redirect: "https://app.acme.test" }), []);
});

test("setupChanges says what a restart would change", () => {
  assert.deepEqual(setupChanges({ listen: "127.0.0.1:8080" }, 9090, DEFAULT_SETUP), ["port 9090"]);
  assert.deepEqual(setupChanges({ listen: "127.0.0.1:8080" }, null, { allInterfaces: true, invisible: true, redirect: null }), [
    "every network interface",
    "invisible mode",
  ]);
  assert.deepEqual(setupChanges({ listen: "127.0.0.1:8080" }, 443, { ...DEFAULT_SETUP, redirect: "https://app.acme.test" }), [
    "port 443",
    "invisible mode",
    "everything sent to https://app.acme.test",
  ]);
  const shell = { listen: "0.0.0.0:8080", args: ["proxy", "run", "--redirect", "https://old.test"] };
  assert.deepEqual(setupChanges(shell, null, DEFAULT_SETUP), ["this computer only", "invisible mode off", "no redirect"]);
  assert.deepEqual(setupChanges(shell, null, { allInterfaces: true, invisible: true, redirect: null }), ["no redirect"]);
});

// Edge cases: the origin that is checked against the scope is the one the proxy starts with, and
// nothing typed or stored can add another host, credentials or an option.

test("an accepted redirect becomes one origin: what is scope-checked is what the proxy gets", () => {
  for (const text of [
    "https://app.acme.test",
    " HTTPS://App.Acme.Test:443/ ",
    "https://app.\tacme.test",
    "https://app.acme.test:443\n",
    "https://bücher.test",
    "http://0x7f.1:8080",
    "https://%61pp.acme.test",
    "https:///app.acme.test",
    "https://app.acme.test:",
    "https://app.acme.test:65535",
    "http://[::1]",
  ]) {
    const origin = redirectOrigin(text);
    assert.ok(origin, JSON.stringify(text));
    // No whitespace, credentials, path, query or fragment left.
    assert.match(origin, /^https?:\/\/[^\s/?#@]+$/, JSON.stringify(text));
    // Normalising again changes nothing, so the stored and started values match the checked one.
    assert.equal(redirectProblem(origin), null, origin);
    assert.equal(redirectOrigin(origin), origin, origin);
    assert.deepEqual(scopeCheckArgs(origin), ["engagement", "check", "--", origin]);
    // One argv element, never split into an option and a value.
    assert.deepEqual(setupOptions({ ...DEFAULT_SETUP, redirect: origin }), [`--redirect=${origin}`]);
  }
  assert.equal(redirectOrigin("https://bücher.test"), "https://xn--bcher-kva.test");
  assert.equal(redirectOrigin("http://0x7f.1:8080"), "http://127.0.0.1:8080");
});

test("a redirect that would name another host, carry credentials or add an option is refused", () => {
  for (const text of [
    "https://evil.test\\@app.acme.test",
    "https://app.acme.test%2f@evil.test",
    "https://evil.test@app.acme.test",
    "https://user@app.acme.test",
    "https://:pw@app.acme.test",
    "https://app.acme.test\n--listen=0.0.0.0:80",
    "https://app.acme.test --invisible",
    "https://app.acme.test/;x",
    "https://app.acme.test:65536",
    "https:app.acme.test",
    "https:/app.acme.test",
    "javascript://app.acme.test",
    "--redirect=https://app.acme.test",
    "//app.acme.test",
  ]) {
    assert.notEqual(redirectProblem(text), null, JSON.stringify(text));
    assert.equal(redirectOrigin(text), null, JSON.stringify(text));
  }
});

test("scopeProblem: one refused port refuses it; an answer it can't read is never in scope", () => {
  assert.match(scopeProblem({ results: [{ port: 443, allowed: true }, { port: 80, allowed: false, reason: "port 80 is outside" }] })!, /port 80 is outside/);
  assert.match(scopeProblem({ results: [{ port: 443 } as any] })!, /isn't in this engagement's scope/);
  // Settings shows a thrown error as "couldn't be checked" and saves nothing.
  for (const check of [{}, { results: null }, { results: "yes" }, null]) {
    let verdict: string | null;
    try {
      verdict = scopeProblem(check as any);
    } catch {
      verdict = "threw";
    }
    assert.notEqual(verdict, null, JSON.stringify(check));
  }
});

test("a saved redirect that isn't a plain origin is ignored, an untidy one normalised", () => {
  for (const stored of ["https://me:pw@app.acme.test", "https://app.acme.test/api", "ftp://app.acme.test", "https://app.acme.test --listen=0.0.0.0:80", "--invisible", ""]) {
    stubStorage({ [PROXY_REDIRECT + PROJECT]: stored });
    assert.equal(savedProxySetup(PROJECT).redirect, null, stored);
  }
  stubStorage({ [PROXY_REDIRECT + PROJECT]: "HTTPS://App.Acme.Test:443/" });
  assert.equal(savedProxySetup(PROJECT).redirect, "https://app.acme.test");
});

test("without a project no redirect is read, not even one stored under an empty path", () => {
  stubStorage({ [PROXY_REDIRECT]: "https://app.acme.test", [PROXY_REDIRECT + "undefined"]: "https://app.acme.test" });
  assert.equal(savedProxySetup().redirect, null);
  assert.equal(savedProxySetup("").redirect, null);
});

test("saveProxySetup stores the redirect as an origin, and never an invalid one", () => {
  const items = stubStorage({ [PROXY_REDIRECT + PROJECT]: "https://old.test" });
  assert.equal(saveProxySetup({ ...DEFAULT_SETUP, redirect: "HTTPS://App.Acme.Test:443/" }, PROJECT), true);
  assert.equal(items.get(PROXY_REDIRECT + PROJECT), "https://app.acme.test");
  for (const redirect of ["https://me:pw@app.acme.test", "https://app.acme.test/api", "ftp://app.acme.test"]) {
    assert.equal(saveProxySetup({ ...DEFAULT_SETUP, redirect }, PROJECT), true);
    assert.equal(items.has(PROXY_REDIRECT + PROJECT), false, redirect);
  }
  // Another project's redirect is left alone.
  items.set(PROXY_REDIRECT + "/work/other.bpdb", "https://other.test");
  saveProxySetup(DEFAULT_SETUP, PROJECT);
  assert.equal(items.get(PROXY_REDIRECT + "/work/other.bpdb"), "https://other.test");
});

test("withSetup on a shell's split --redirect leaves no stray value behind", () => {
  const running = ["proxy", "run", "--listen", "0.0.0.0:80", "--redirect", "https://old.test", "--timeout", "30", "--invisible"];
  assert.deepEqual(withSetup(proxyOptions(running), DEFAULT_SETUP), ["--timeout=30"]);
  assert.deepEqual(withSetup(proxyOptions(running), { ...DEFAULT_SETUP, invisible: true }), ["--timeout=30", "--invisible"]);
  // Options that only start with the same letters are kept.
  assert.deepEqual(withSetup(["--invisible-x", "--redirects=1"], DEFAULT_SETUP), ["--invisible-x", "--redirects=1"]);
});

test("isLoopback and isWildcard: exact hosts only", () => {
  for (const host of ["127.0.0.1", "127.1.2.3", "[::1]", "localhost", "LocalHost"]) assert.equal(isLoopback(host), true, host);
  for (const host of ["", "0.0.0.0", "[::]", "127.0.0.1.evil.test", "x127.0.0.1", "localhost.evil.test", "192.168.1.5", "::1"]) assert.equal(isLoopback(host), false, host);
  for (const host of ["0.0.0.0", "[::]"]) assert.equal(isWildcard(host), true, host);
  for (const host of ["", "127.0.0.1", "[::1]", "0.0.0.0.evil.test", "::"]) assert.equal(isWildcard(host), false, host);
  assert.equal(hostOf("8080"), "");
  assert.equal(hostOf("[::]:8080"), "[::]");
});

test("setupChanges: a proxy on a single network address isn't 'this computer only' or 'every interface'", () => {
  const lan = { listen: "192.168.1.5:8080" };
  assert.deepEqual(setupChanges(lan, null, DEFAULT_SETUP), ["this computer only"]);
  assert.deepEqual(setupChanges(lan, null, { ...DEFAULT_SETUP, allInterfaces: true }), ["every network interface"]);
  assert.deepEqual(setupChanges({ listen: "[::]:8080" }, null, { ...DEFAULT_SETUP, allInterfaces: true }), []);
  assert.deepEqual(setupChanges({ listen: "[::]:8080" }, null, DEFAULT_SETUP), ["this computer only"]);
});

test("setupChanges: the redirect differs from the running one", () => {
  const invisible = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--invisible"] };
  assert.deepEqual(setupChanges(invisible, null, { ...DEFAULT_SETUP, redirect: "https://app.acme.test" }), ["everything sent to https://app.acme.test"]);
  const other = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--redirect=https://old.test"] };
  assert.deepEqual(setupChanges(other, null, { ...DEFAULT_SETUP, redirect: "https://app.acme.test" }), ["everything sent to https://app.acme.test"]);
  // A shell's redirect with a path is shown as typed, and differs from the saved origin.
  const path = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--redirect", "https://app.acme.test/api"] };
  assert.equal(runningSetup(path).redirect, "https://app.acme.test/api");
  assert.deepEqual(setupChanges(path, null, { ...DEFAULT_SETUP, redirect: "https://app.acme.test" }), ["everything sent to https://app.acme.test"]);
});

test("redirectError: a refusal counts only for the origin it was made for", () => {
  const refused = { origin: "https://evil.test", why: "It isn't in this engagement's scope." };
  assert.equal(redirectError("https://evil.test", refused), refused.why);
  // The same origin typed differently.
  assert.equal(redirectError(" HTTPS://Evil.Test:443/ ", refused), refused.why);
  // Edited while the check ran: the refusal isn't the new text's.
  assert.equal(redirectError("https://app.acme.test", refused), null);
  assert.equal(redirectError("", refused), null);
  assert.equal(redirectError("https://evil.test", null), null);
  // An invalid URL says why, whatever was refused before.
  assert.match(redirectError("https://evil.test/api", refused)!, /scheme, host and port/);
});

test("Save as… carries the redirect to the new path; a discarded project's is forgotten", () => {
  const items = stubStorage({ [PROXY_REDIRECT + PROJECT]: "https://app.acme.test", [PROXY_NETWORK]: "all" });
  const dest = "/work/saved.bpdb";
  assert.equal(moveRedirect(PROJECT, dest), true);
  assert.equal(items.has(PROXY_REDIRECT + PROJECT), false);
  assert.equal(savedProxySetup(dest).redirect, "https://app.acme.test");
  // Nothing to carry: nothing is written.
  assert.equal(moveRedirect("/work/none.bpdb", "/work/none2.bpdb"), true);
  assert.equal(items.has(PROXY_REDIRECT + "/work/none2.bpdb"), false);

  forgetRedirect(dest);
  assert.equal(items.has(PROXY_REDIRECT + dest), false);
  // Only that project's key.
  assert.equal(items.get(PROXY_NETWORK), "all");
});

test("moveRedirect and forgetRedirect with storage that throws", () => {
  const fail = () => {
    throw new Error("denied");
  };
  stubStorage({}, { getItem: fail, setItem: fail, removeItem: fail });
  assert.equal(moveRedirect(PROJECT, "/work/saved.bpdb"), false);
  assert.doesNotThrow(() => forgetRedirect(PROJECT));
});

test("networkNote: what other devices connect to, for a wildcard address only", () => {
  assert.match(networkNote("0.0.0.0:8080")!, /this computer's address on their network.*port 8080: http:\/\/LAN-IP:8080/);
  assert.match(networkNote("[::]:80")!, /port 80:/);
  for (const listen of ["127.0.0.1:8080", "[::1]:8080", "192.168.1.5:8080"]) assert.equal(networkNote(listen), null, listen);
});
