import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_SETUP,
  PROXY_INVISIBLE,
  PROXY_NETWORK,
  PROXY_REDIRECT,
  hostOf,
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
