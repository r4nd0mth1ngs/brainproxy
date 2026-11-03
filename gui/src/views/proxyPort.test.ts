import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_PROXY_PORT,
  PROXY_PORT,
  PROXY_PORTS,
  lowPortNote,
  moveProxy,
  portOf,
  portProblem,
  proxyControl,
  proxyListen,
  restartFailure,
  saveProxyPort,
  savedProxyPort,
  startPorts,
  startLive,
  startProxy,
  stopOwned,
  stopProxy,
  withPort,
  withPortHint,
} from "./proxyPort.ts";

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

const BIND_FAILURE = "conflict: cannot listen on 127.0.0.1:9090: the port is already in use";
const HINTED = "cannot listen on 127.0.0.1:9090: the port is already in use. Choose another port in Settings › Proxy.";

/** A `cli` that records its calls; `answer` returns the data, or throws to make a call fail. */
function fakeCli(answer: (args: string[], call: number) => unknown = () => {}) {
  const calls: string[][] = [];
  const cli = async (args: string[]) => {
    calls.push(args);
    return answer(args, calls.length);
  };
  return { calls, cli };
}

const isStart = (args: string[]) => args[1] === "start";

test("portProblem accepts empty (automatic) and ports from 1 to 65535", () => {
  for (const text of ["", "  ", "1", "80", "8080", " 9090 ", "65535", "08080"]) {
    assert.equal(portProblem(text), null, JSON.stringify(text));
  }
});

test("portProblem rejects everything else", () => {
  for (const text of ["0", "65536", "-1", "80a", "1e3", "8080.5", "0x50", "99999999999999999999", "80 80"]) {
    assert.equal(portProblem(text), "Enter a port from 1 to 65535", JSON.stringify(text));
  }
});

test("lowPortNote: only below 1024", () => {
  assert.match(lowPortNote(1023)!, /below 1024/);
  assert.equal(lowPortNote(1024), null);
});

test("the saved port round-trips, and null removes it", () => {
  const items = stubStorage();
  assert.equal(saveProxyPort(9090), true);
  assert.equal(items.get(PROXY_PORT), "9090");
  assert.equal(savedProxyPort(), 9090);
  assert.equal(proxyListen(), "127.0.0.1:9090");
  assert.equal(saveProxyPort(null), true);
  assert.equal(items.has(PROXY_PORT), false);
  assert.equal(savedProxyPort(), null);
});

test("an unset or corrupt saved port is automatic", () => {
  const fallback = `127.0.0.1:${DEFAULT_PROXY_PORT}`;
  assert.equal(fallback, "127.0.0.1:8080");
  stubStorage();
  assert.equal(savedProxyPort(), null);
  assert.equal(proxyListen(), fallback);
  for (const stored of ["abc", "0", "70000"]) {
    stubStorage({ [PROXY_PORT]: stored });
    assert.equal(savedProxyPort(), null, stored);
    assert.equal(proxyListen(), fallback, stored);
  }
});

test("proxyListen takes an explicit port over the saved one", () => {
  stubStorage({ [PROXY_PORT]: "9090" });
  assert.equal(proxyListen(1234), "127.0.0.1:1234");
  assert.equal(proxyListen(null), "127.0.0.1:8080");
});

test("storage that throws: no saved port, and saving says it failed", () => {
  const fail = () => {
    throw new Error("denied");
  };
  stubStorage({}, { getItem: fail, setItem: fail, removeItem: fail });
  assert.equal(savedProxyPort(), null);
  assert.equal(saveProxyPort(9090), false);
  assert.equal(saveProxyPort(null), false);
});

test("no localStorage at all: no saved port", () => {
  delete (globalThis as any).localStorage;
  assert.equal(savedProxyPort(), null);
  assert.equal(saveProxyPort(9090), false);
  assert.equal(proxyListen(), "127.0.0.1:8080");
});

test("startPorts: a chosen port has no fallback, automatic mode does", () => {
  assert.deepEqual(startPorts(9090), [9090]);
  assert.deepEqual(startPorts(null), PROXY_PORTS);
  assert.equal(PROXY_PORTS[0], DEFAULT_PROXY_PORT);
});

test("portOf and withPort keep the host", () => {
  for (const host of ["127.0.0.1", "0.0.0.0", "[::1]"]) {
    assert.equal(portOf(`${host}:8080`), 8080, host);
    assert.equal(withPort(`${host}:8080`, 9090), `${host}:9090`);
  }
  for (const listen of ["localhost", ":0", ""]) assert.equal(portOf(listen), null, JSON.stringify(listen));
});

test("withPortHint: only failed binds get the hint", () => {
  assert.equal(withPortHint(BIND_FAILURE), HINTED);
  for (const message of ["conflict: proxy already running on 127.0.0.1:8080 (1)", "not found: no proxy", ""]) {
    assert.equal(withPortHint(message), message);
  }
});

test("startProxy uses the saved port, or the default", async () => {
  stubStorage({ [PROXY_PORT]: "9090" });
  let fake = fakeCli();
  await startProxy(fake.cli, proxyControl());
  assert.deepEqual(fake.calls, [["proxy", "start", "--listen=127.0.0.1:9090"]]);

  stubStorage();
  fake = fakeCli();
  await startProxy(fake.cli, proxyControl());
  assert.deepEqual(fake.calls, [["proxy", "start", "--listen=127.0.0.1:8080"]]);
});

test("startProxy: a failed bind still rejects, now with the hint; other errors are unchanged", async () => {
  stubStorage();
  const failing = (message: string) =>
    fakeCli(() => {
      throw new Error(message);
    }).cli;
  await assert.rejects(startProxy(failing(BIND_FAILURE), proxyControl()), { message: HINTED });
  await assert.rejects(startProxy(failing("conflict: proxy already running"), proxyControl()), { message: "conflict: proxy already running" });
});

// `proxy restart` fails to bind 9090 after stopping the proxy, and adds whether it started it
// again where it was (as `pid`) or couldn't (null), as the CLI does.
const restartFailed = (pid: number | null) =>
  pid == null
    ? `${BIND_FAILURE}; the proxy couldn't be started again on 127.0.0.1:8080: conflict: cannot listen on 127.0.0.1:8080: the port is already in use. It is off now`
    : `${BIND_FAILURE}; the proxy was started again on 127.0.0.1:8080 (pid ${pid})`;

test("restartFailure: what the CLI says after stopping the proxy, and the pid it started again", () => {
  assert.deepEqual(restartFailure(restartFailed(9)), { message: BIND_FAILURE, stopped: true, pid: 9 });
  assert.deepEqual(restartFailure(restartFailed(null)), { message: BIND_FAILURE, stopped: true, pid: null });
  for (const message of ["not found: no proxy running for this project; start one with `brainproxy proxy start`", BIND_FAILURE, ""]) {
    assert.deepEqual(restartFailure(message), { message, stopped: false, pid: null });
  }
});

test("moveProxy restarts the proxy on the new port in one call, and returns the address", async () => {
  const { calls, cli } = fakeCli();
  const target = await moveProxy(cli, proxyControl(), { listen: "127.0.0.1:8080" }, 9090);
  assert.equal(target, "127.0.0.1:9090");
  assert.deepEqual(calls, [["proxy", "restart", "--listen=127.0.0.1:9090"]]);
});

test("moveProxy keeps the host", async () => {
  for (const host of ["0.0.0.0", "[::1]"]) {
    const { calls, cli } = fakeCli();
    assert.equal(await moveProxy(cli, proxyControl(), { listen: `${host}:8080` }, 9090), `${host}:9090`);
    assert.deepEqual(calls[0], ["proxy", "restart", `--listen=${host}:9090`]);
  }
});

test("moveProxy keeps the options the proxy runs with, but not --listen, --log or --wait", async () => {
  const running = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--listen", "127.0.0.1:8080", "--timeout", "30", "--verify-tls", "--log", "x.log"] };
  let fake = fakeCli();
  await moveProxy(fake.cli, proxyControl(), running, 9090);
  assert.deepEqual(fake.calls[0], ["proxy", "restart", "--listen=127.0.0.1:9090", "--timeout=30", "--verify-tls"]);

  fake = fakeCli();
  await moveProxy(fake.cli, proxyControl(), { listen: "127.0.0.1:8080", args: ["proxy", "run", "--listen=127.0.0.1:8080", "--timeout=30", "--wait=5", "--log=x.log", "--auth=alice"] }, 9090);
  assert.deepEqual(fake.calls[0], ["proxy", "restart", "--listen=127.0.0.1:9090", "--timeout=30", "--auth=alice"]);
});

test("moveProxy: a restart refused before stopping anything rejects as it is, and the proxy stays the app's", async () => {
  for (const message of ["not found: no proxy running for this project", "conflict: the proxy is being restarted (pid 5)"]) {
    const ctl = proxyControl();
    ctl.owned = 7;
    const { calls, cli } = fakeCli(() => {
      throw new Error(message);
    });
    await assert.rejects(moveProxy(cli, ctl, { listen: "127.0.0.1:8080", pid: 7 }, 9090), { message });
    assert.deepEqual(calls, [["proxy", "restart", "--listen=127.0.0.1:9090"]]);
    assert.equal(ctl.owned, 7);
  }
});

const movable = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--listen", "127.0.0.1:8080", "--timeout", "30"] };

test("moveProxy: when the new port fails the CLI puts the proxy back, and a fresh status says where it is", async () => {
  const { calls, cli } = fakeCli((args) => {
    if (args[1] === "restart") throw new Error(restartFailed(9));
    if (args[1] === "status") return { running: true, proxy: { listen: "127.0.0.1:8080", pid: 9 } };
  });
  await assert.rejects(moveProxy(cli, proxyControl(), movable, 9090), { message: `${HINTED} The proxy is back on 127.0.0.1:8080.` });
  assert.deepEqual(calls, [
    ["proxy", "restart", "--listen=127.0.0.1:9090", "--timeout=30"],
    ["proxy", "status"],
  ]);
});

test("moveProxy: when going back fails too, the error says where the proxy is now", async () => {
  const cases: [object | null, string][] = [
    [{ running: false, proxy: null }, "The proxy is off."],
    // Started since by a shell or an agent.
    [{ running: true, proxy: { listen: "127.0.0.1:9090" } }, "The proxy is on 127.0.0.1:9090."],
    [{ running: true, proxy: { listen: "127.0.0.1:8080" } }, "The proxy is back on 127.0.0.1:8080."],
    [null, "Check in the top bar whether the proxy is running."],
  ];
  for (const [status, where] of cases) {
    const { calls, cli } = fakeCli((args) => {
      if (args[1] === "restart") throw new Error(restartFailed(null));
      if (args[1] === "status") {
        if (!status) throw new Error("status failed");
        return status;
      }
    });
    await assert.rejects(moveProxy(cli, proxyControl(), movable, 9090), { message: `${HINTED} ${where}` });
    assert.equal(calls.length, 2);
  }
});

test("during a move, other starts wait for it and start nothing if the proxy is up", async () => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  const { calls, cli } = fakeCli(async (args) => {
    if (args[1] === "restart") await held;
    if (args[1] === "status") return { running: true, proxy: { listen: "127.0.0.1:9090" } };
    return {};
  });
  const ctl = proxyControl();
  const moved = moveProxy(cli, ctl, movable, 9090);
  assert.ok(ctl.moving);
  const started = startProxy(cli, ctl);
  await Promise.resolve();
  assert.deepEqual(calls, [["proxy", "restart", "--listen=127.0.0.1:9090", "--timeout=30"]]);
  release();
  assert.equal(await moved, "127.0.0.1:9090");
  assert.equal(await started, false);
  assert.deepEqual(calls.slice(1), [["proxy", "status"]]);
  assert.equal(ctl.moving, null);
});

test("closing during a move stops the app's proxy where the move put it", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = proxyCli(() => ({ running: true, proxy: { listen: "127.0.0.1:9090", pid: 8 } }), [8]);
  const moved = moveProxy(cli, ctl, { ...movable, pid: 7 }, 9090);
  await stopOwned(cli, ctl);
  await moved;
  assert.deepEqual(calls.slice(-2), [
    ["proxy", "status"],
    ["proxy", "stop"],
  ]);
});

test("during a move that leaves the proxy off, a start waits and then starts it", async () => {
  stubStorage();
  const { calls, cli } = fakeCli((args) => {
    if (args[1] === "restart") throw new Error(restartFailed(null));
    if (args[1] === "status") return { running: false, proxy: null };
    return {};
  });
  const ctl = proxyControl();
  const moved = moveProxy(cli, ctl, movable, 9090);
  assert.equal(await startProxy(cli, ctl), true);
  await assert.rejects(moved);
  assert.deepEqual(calls.at(-1), ["proxy", "start", "--listen=127.0.0.1:8080"]);
  assert.equal(ctl.moving, null);
});

// Ownership: only a proxy the app started is stopped when the project closes.

/**
 * `proxy status` answers with `status`; `proxy start` and `proxy restart` with the next pid of
 * `pids`. `fail` makes a start fail to bind, and a restart too, after it started the old proxy
 * again as the next pid.
 */
function proxyCli(status: () => object, pids: number[] = [], fail: (args: string[]) => boolean = () => false) {
  return fakeCli((args) => {
    if (fail(args)) throw new Error(args[1] === "restart" ? restartFailed(pids.shift()!) : BIND_FAILURE);
    if (args[1] === "status") return status();
    if (isStart(args) || args[1] === "restart") return { pid: pids.shift(), listen: args[2].slice(9) };
    return {};
  });
}

const runningAs = (pid: number, extra: object = {}) => ({ running: true, proxy: { listen: "127.0.0.1:8080", pid }, ...extra });

test("startProxy records the pid it started; stopProxy forgets it", async () => {
  stubStorage();
  const ctl = proxyControl();
  const { cli } = proxyCli(() => ({ running: false, proxy: null }), [41]);
  await startProxy(cli, ctl);
  assert.equal(ctl.owned, 41);
  await stopProxy(cli, ctl);
  assert.equal(ctl.owned, null);
});

test("startProxy takes an explicit port, and a failed start records nothing", async () => {
  stubStorage({ [PROXY_PORT]: "9090" });
  const ctl = proxyControl();
  const { calls, cli } = proxyCli(() => ({}), [], () => true);
  await assert.rejects(startProxy(cli, ctl, 8083), { message: HINTED });
  assert.deepEqual(calls, [["proxy", "start", "--listen=127.0.0.1:8083"]]);
  assert.equal(ctl.owned, null);
});

test("stopOwned: nothing the app started, nothing stopped (an unverifiable record, an agent's proxy)", async () => {
  const { calls, cli } = proxyCli(() => runningAs(7));
  await stopOwned(cli, proxyControl());
  assert.deepEqual(calls, []);
});

test("stopOwned stops the app's proxy while it is still the one running", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = proxyCli(() => runningAs(7));
  await stopOwned(cli, ctl);
  assert.deepEqual(calls, [
    ["proxy", "status"],
    ["proxy", "stop"],
  ]);
  assert.equal(ctl.owned, null);
});

test("stopOwned leaves a proxy someone else started since, one in another container, or none", async () => {
  for (const status of [runningAs(8), runningAs(7, { other_pid_namespace: true }), { running: false, proxy: null }]) {
    const ctl = proxyControl();
    ctl.owned = 7;
    const { calls, cli } = proxyCli(() => status);
    await stopOwned(cli, ctl);
    assert.deepEqual(calls, [["proxy", "status"]], JSON.stringify(status));
    assert.equal(ctl.owned, null);
  }
});

test("moveProxy: the app's proxy stays the app's, at its new pid", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { cli } = proxyCli(() => ({}), [8]);
  await moveProxy(cli, ctl, { listen: "127.0.0.1:8080", pid: 7 }, 9090);
  assert.equal(ctl.owned, 8);
});

test("moveProxy: also when it goes back to the old port", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { cli } = proxyCli(() => runningAs(9), [9], (args) => args.includes("--listen=127.0.0.1:9090"));
  await assert.rejects(moveProxy(cli, ctl, { listen: "127.0.0.1:8080", pid: 7 }, 9090));
  assert.equal(ctl.owned, 9);
});

test("moveProxy: a proxy that couldn't go back is no longer the app's", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { cli } = fakeCli((args) => {
    if (args[1] === "restart") throw new Error(restartFailed(null));
    return runningAs(8);
  });
  await assert.rejects(moveProxy(cli, ctl, { listen: "127.0.0.1:8080", pid: 7 }, 9090), { message: `${HINTED} The proxy is back on 127.0.0.1:8080.` });
  assert.equal(ctl.owned, null);
});

test("moveProxy: a proxy the app didn't start doesn't become the app's", async () => {
  const ctl = proxyControl();
  const { cli } = proxyCli(() => ({}), [8]);
  await moveProxy(cli, ctl, { listen: "127.0.0.1:8080", pid: 7 }, 9090);
  assert.equal(ctl.owned, null);
});

test("restartFailure: other hosts, other errors, and a proxy someone else started", () => {
  const ipv6 = "conflict: cannot listen on [::1]:9090: the port is already in use";
  assert.deepEqual(restartFailure(`${ipv6}; the proxy was started again on [::1]:8080 (pid 12)`), { message: ipv6, stopped: true, pid: 12 });
  const timeout = "conflict: timed out after 10s";
  assert.deepEqual(restartFailure(`${timeout}; the proxy was started again on 127.0.0.1:8080 (pid 9)`), { message: timeout, stopped: true, pid: 9 });
  // Not going back, a pid in the reason or in where it is now isn't the app's.
  const taken = `${BIND_FAILURE}; the proxy couldn't be started again on 127.0.0.1:8080: conflict: proxy already running on 127.0.0.1:7000 (pid 12). A proxy is running on 127.0.0.1:7000 (pid 12) now`;
  assert.deepEqual(restartFailure(taken), { message: BIND_FAILURE, stopped: true, pid: null });
  // Only the CLI's own ending counts.
  for (const message of [
    "conflict: the proxy was stopped or replaced while restarting it; see `brainproxy proxy status`",
    "conflict: can't restart the proxy: the options it runs with (scan active) can't be read",
    `${BIND_FAILURE}; the proxy was started again on 127.0.0.1:8080 (pid 9) or so`,
  ]) {
    assert.deepEqual(restartFailure(message), { message, stopped: false, pid: null });
  }
});

test("moveProxy: a failed restart of a proxy the app didn't start leaves the app owning nothing new", async () => {
  for (const pid of [9, null]) {
    const ctl = proxyControl();
    ctl.owned = 3; // An earlier proxy of the app's, not the one moved.
    const { cli } = fakeCli((args) => {
      if (args[1] === "restart") throw new Error(restartFailed(pid));
      return runningAs(9);
    });
    await assert.rejects(moveProxy(cli, ctl, { listen: "127.0.0.1:8080", pid: 7 }, 9090));
    assert.equal(ctl.owned, 3);
    assert.equal(ctl.moving, null);
  }
});

test("moveProxy: a restart the CLI refused keeps its message and asks nothing more", async () => {
  const message = "conflict: can't restart the proxy: the options it runs with (x) can't be read";
  const { calls, cli } = fakeCli(() => {
    throw new Error(message);
  });
  const ctl = proxyControl();
  await assert.rejects(moveProxy(cli, ctl, movable, 9090), { message });
  assert.equal(calls.length, 1);
  assert.equal(ctl.moving, null);
});

test("closing during a move that went back stops the app's proxy at the pid it went back to", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = proxyCli(() => runningAs(9), [9], (args) => args[1] === "restart");
  const moved = moveProxy(cli, ctl, { ...movable, pid: 7 }, 9090);
  await stopOwned(cli, ctl);
  await assert.rejects(moved, { message: `${HINTED} The proxy is back on 127.0.0.1:8080.` });
  assert.deepEqual(calls.slice(-2), [
    ["proxy", "status"],
    ["proxy", "stop"],
  ]);
  assert.equal(ctl.owned, null);
});

test("during a move that went back, a start waits and starts nothing", async () => {
  stubStorage();
  const { calls, cli } = proxyCli(() => runningAs(9), [9], (args) => args[1] === "restart");
  const ctl = proxyControl();
  const moved = moveProxy(cli, ctl, movable, 9090);
  assert.equal(await startProxy(cli, ctl), false);
  await assert.rejects(moved);
  assert.ok(!calls.some(isStart), JSON.stringify(calls));
});

// Access's live testing: the same restart, on the same address, with live testing added.

const LIVE = ["--authz=anonymous,bob", "--authz-rate=5"];
const liveRunning = { listen: "127.0.0.1:8081", pid: 7, args: ["proxy", "run", "--listen", "127.0.0.1:8081", "--timeout", "12", "--authz=alice"] };

test("startLive restarts a running proxy where it is in one call, with its options and live testing", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = proxyCli(() => ({ running: true, proxy: liveRunning }), [8]);
  const d = await startLive(cli, ctl, LIVE);
  assert.deepEqual(calls, [
    ["proxy", "status"],
    ["proxy", "restart", "--listen=127.0.0.1:8081", "--timeout=12", ...LIVE],
  ]);
  assert.equal(d.listen, "127.0.0.1:8081");
  assert.equal(ctl.owned, 8);
  assert.equal(ctl.moving, null);
});

test("startLive starts a proxy that isn't running on the app's port, and it is the app's", async () => {
  stubStorage({ [PROXY_PORT]: "9090" });
  const ctl = proxyControl();
  const { calls, cli } = proxyCli(() => ({ running: false, proxy: null }), [8]);
  const d = await startLive(cli, ctl, LIVE);
  assert.deepEqual(calls, [
    ["proxy", "status"],
    ["proxy", "start", "--listen=127.0.0.1:9090", ...LIVE],
  ]);
  assert.equal(d.listen, "127.0.0.1:9090");
  assert.equal(ctl.owned, 8);
});

test("startLive: a proxy the app didn't start doesn't become the app's", async () => {
  const ctl = proxyControl();
  const { cli } = proxyCli(() => ({ running: true, proxy: liveRunning }), [8]);
  await startLive(cli, ctl, LIVE);
  assert.equal(ctl.owned, null);
});

test("startLive: when the live proxy doesn't come up, the CLI puts the old one back and a fresh status says where", async () => {
  const failure = "invalid input: login failed: no session";
  for (const [pid, owned, status, where] of [
    [9, 9, { running: true, proxy: { listen: "127.0.0.1:8081", pid: 9 } }, "The proxy is back on 127.0.0.1:8081."],
    [null, null, { running: false, proxy: null }, "The proxy is off."],
  ] as const) {
    const ctl = proxyControl();
    ctl.owned = 7;
    let statuses = 0;
    const { calls, cli } = fakeCli((args) => {
      if (args[1] === "restart") {
        throw new Error(
          pid == null
            ? `${failure}; the proxy couldn't be started again on 127.0.0.1:8081: conflict: cannot listen. It is off now`
            : `${failure}; the proxy was started again on 127.0.0.1:8081 (pid ${pid})`,
        );
      }
      return statuses++ ? status : { running: true, proxy: liveRunning };
    });
    await assert.rejects(startLive(cli, ctl, LIVE), { message: `${failure} ${where}` });
    assert.deepEqual(calls.map((c) => c[1]), ["status", "restart", "status"]);
    assert.equal(ctl.owned, owned);
    assert.equal(ctl.moving, null);
  }
});

test("startLive: a restart refused before stopping anything rejects as it is, and the proxy stays the app's", async () => {
  const message = "conflict: the proxy is being restarted (`brainproxy proxy restart`, pid 5); try again once that has finished";
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = fakeCli((args) => {
    if (args[1] === "restart") throw new Error(message);
    return { running: true, proxy: liveRunning };
  });
  await assert.rejects(startLive(cli, ctl, LIVE), { message });
  assert.equal(calls.length, 2);
  assert.equal(ctl.owned, 7);
});

test("during a live restart, other starts in the app wait for it", async () => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  const { calls, cli } = fakeCli(async (args) => {
    if (args[1] === "restart") await held;
    if (args[1] === "status") return { running: true, proxy: liveRunning };
    return { pid: 8 };
  });
  const ctl = proxyControl();
  const live = startLive(cli, ctl, LIVE);
  while (!ctl.moving) await Promise.resolve();
  const started = startProxy(cli, ctl);
  await Promise.resolve();
  assert.equal(calls.filter(isStart).length, 0);
  release();
  await live;
  assert.equal(await started, false);
  assert.equal(calls.filter(isStart).length, 0);
  assert.equal(ctl.moving, null);
});
