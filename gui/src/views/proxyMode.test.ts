import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_SETUP,
  hostOf,
  isLoopback,
  isWildcard,
  networkNote,
  redirectError,
  redirectOrigin,
  redirectProblem,
  redirectToCheck,
  runningSetup,
  saveProxySetup,
  savedProxySetup,
  scopeCheckArgs,
  scopeProblem,
  setupChanges,
  setupArgs,
  setupFrom,
  setupHost,
  setupOptions,
  targetHost,
  withSetup,
} from "./proxyMode.ts";
import { proxyOptions } from "./accessMatrix.ts";

/** A fake CLI: answers each call with `reply(args)`, and records the calls. */
function fakeCli(reply: (args: string[]) => unknown = () => ({})) {
  const calls: string[][] = [];
  return { calls, cli: async (args: string[]) => (calls.push(args), reply(args)) };
}

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

test("the setup is read from the project file and saved there in one call (proxy setup)", async () => {
  const shown = { network: "all", invisible: true, redirect: "https://app.acme.test", host: "0.0.0.0", start_options: [] };
  const read = fakeCli(() => shown);
  assert.deepEqual(await savedProxySetup(read.cli), { allInterfaces: true, invisible: true, redirect: "https://app.acme.test" });
  assert.deepEqual(read.calls, [["proxy", "setup", "show"]]);

  // `set` replaces the whole setup; what it prints back is what was saved.
  const saved = fakeCli(() => ({ network: "local", invisible: true, redirect: null }));
  assert.deepEqual(await saveProxySetup(saved.cli, { ...DEFAULT_SETUP, invisible: true }), { ...DEFAULT_SETUP, invisible: true });
  assert.deepEqual(saved.calls, [["proxy", "setup", "set", "--network=local", "--invisible"]]);
});

test("setupArgs: every field, every time, so a save leaves nothing of the earlier setup", () => {
  assert.deepEqual(setupArgs(DEFAULT_SETUP), ["proxy", "setup", "set", "--network=local"]);
  assert.deepEqual(setupArgs({ allInterfaces: true, invisible: true, redirect: null }), ["proxy", "setup", "set", "--network=all", "--invisible"]);
  // The redirect implies invisible mode.
  assert.deepEqual(setupArgs({ allInterfaces: false, invisible: true, redirect: "https://app.acme.test" }), [
    "proxy",
    "setup",
    "set",
    "--network=local",
    "--redirect=https://app.acme.test",
  ]);
});

test("a setup that can't be read or saved rejects, with the CLI's message", async () => {
  const failing = async () => {
    throw new Error("not_found: no such project");
  };
  await assert.rejects(savedProxySetup(failing), { message: "not_found: no such project" });
  await assert.rejects(saveProxySetup(failing, DEFAULT_SETUP), { message: "not_found: no such project" });
});

test("setupFrom: the defaults for anything missing or invalid", () => {
  for (const value of [null, undefined, "all", [], 42, {}, { network: "ALL", invisible: "true", redirect: "ftp://x" }, { network: true, invisible: 1, redirect: 5 }]) {
    assert.deepEqual(setupFrom(value), DEFAULT_SETUP, JSON.stringify(value));
  }
  assert.deepEqual(setupFrom({ network: "all" }), { ...DEFAULT_SETUP, allInterfaces: true });
  // A redirect means invisible mode, however it was saved.
  assert.deepEqual(setupFrom({ redirect: "https://app.acme.test" }), { ...DEFAULT_SETUP, invisible: true, redirect: "https://app.acme.test" });
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
  for (const redirect of ["https://me:pw@app.acme.test", "https://app.acme.test/api", "ftp://app.acme.test", "https://app.acme.test --listen=0.0.0.0:80", "--invisible", ""]) {
    assert.equal(setupFrom({ redirect }).redirect, null, redirect);
  }
  assert.equal(setupFrom({ redirect: "HTTPS://App.Acme.Test:443/" }).redirect, "https://app.acme.test");
});

test("setupArgs sends the redirect as an origin, and never an invalid one", () => {
  assert.deepEqual(setupArgs({ ...DEFAULT_SETUP, redirect: "HTTPS://App.Acme.Test:443/" }).at(-1), "--redirect=https://app.acme.test");
  for (const redirect of ["https://me:pw@app.acme.test", "https://app.acme.test/api", "ftp://app.acme.test", "https://x.test --network=all"]) {
    assert.deepEqual(setupArgs({ ...DEFAULT_SETUP, redirect }), ["proxy", "setup", "set", "--network=local"], redirect);
  }
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

test("redirectToCheck: Save checks a refused origin again, since the refusal may not hold any more", () => {
  // engagement check refuses a name that doesn't resolve; DNS may recover, or a host override be added.
  const refused = { origin: "https://app.acme.test", why: "It isn't in this engagement's scope: app.acme.test doesn't resolve" };
  assert.equal(redirectError("https://app.acme.test", refused), refused.why);
  assert.equal(redirectToCheck("https://app.acme.test", null), "https://app.acme.test");
  assert.equal(redirectToCheck(" HTTPS://App.Acme.Test:443/ ", "https://old.test"), "https://app.acme.test");
  // The saved origin was checked when it was saved; none, or an invalid one, has nothing to check.
  assert.equal(redirectToCheck("https://app.acme.test", "https://app.acme.test"), null);
  assert.equal(redirectToCheck("", null), null);
  assert.equal(redirectToCheck("https://app.acme.test/api", null), null);
});

test("networkNote: what other devices connect to, for a wildcard address only", () => {
  assert.match(networkNote("0.0.0.0:8080")!, /this computer's address on their network.*port 8080: http:\/\/LAN-IP:8080/);
  assert.match(networkNote("[::]:80")!, /port 80:/);
  for (const listen of ["127.0.0.1:8080", "[::1]:8080", "192.168.1.5:8080"]) assert.equal(networkNote(listen), null, listen);
});
