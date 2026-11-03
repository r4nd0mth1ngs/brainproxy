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

/** The CLI's error for `message` as api.ts's `run` throws it, with its kind and `data`. */
const cliError = (message: string, data?: object) =>
  Object.assign(new Error(message), { kind: message.slice(0, message.indexOf(":")).replace(/ /g, "_"), data });

const SHOW = ["proxy", "setup", "show"];

/** A `fakeCli` answer: the project's saved setup for `proxy setup show`, `rest` for the others. */
const withSaved = (setup: object, rest: (args: string[], call: number) => unknown = () => {}) => (args: string[], call: number) =>
  args[1] === "setup" ? setup : rest(args, call);

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
  assert.deepEqual(fake.calls, [SHOW, ["proxy", "start", "--listen=127.0.0.1:9090"]]);

  stubStorage();
  fake = fakeCli();
  await startProxy(fake.cli, proxyControl());
  assert.deepEqual(fake.calls, [SHOW, ["proxy", "start", "--listen=127.0.0.1:8080"]]);
});

test("startProxy: a failed bind still rejects, now with the hint; other errors are unchanged", async () => {
  stubStorage();
  const failing = (message: string) =>
    fakeCli(
      withSaved({}, () => {
        throw new Error(message);
      }),
    ).cli;
  await assert.rejects(startProxy(failing(BIND_FAILURE), proxyControl()), { message: HINTED });
  await assert.rejects(startProxy(failing("conflict: proxy already running"), proxyControl()), { message: "conflict: proxy already running" });
});

// `proxy restart` fails to bind 9090 after stopping the proxy, and says whether it started it
// again where it was (as `pid`) or couldn't (null), in its message and its data, as the CLI does.
const restartFailed = (pid: number | null) =>
  cliError(
    pid == null
      ? `${BIND_FAILURE}; the proxy couldn't be started again on 127.0.0.1:8080: conflict: cannot listen on 127.0.0.1:8080: the port is already in use. It is off now`
      : `${BIND_FAILURE}; the proxy was started again on 127.0.0.1:8080 (pid ${pid})`,
    { stopped: true, failure: BIND_FAILURE, restarted: pid == null ? null : { pid, listen: "127.0.0.1:8080" } },
  );

test("restartFailure: what the CLI's data says after stopping the proxy, and the pid it started again", () => {
  assert.deepEqual(restartFailure(restartFailed(9)), { message: BIND_FAILURE, stopped: true, pid: 9 });
  assert.deepEqual(restartFailure(restartFailed(null)), { message: BIND_FAILURE, stopped: true, pid: null });
  for (const message of ["not found: no proxy running for this project; start one with `brainproxy proxy start`", BIND_FAILURE, ""]) {
    assert.deepEqual(restartFailure(cliError(message, { stopped: false })), { message, stopped: false, pid: null });
    assert.deepEqual(restartFailure(new Error(message)), { message, stopped: false, pid: null });
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
    if (args[1] === "restart") throw restartFailed(9);
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
      if (args[1] === "restart") throw restartFailed(null);
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
  assert.equal(await started, null);
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
  assert.deepEqual(calls.at(-1), ["proxy", "stop", "--pid=8"]);
});

test("during a move that leaves the proxy off, a start waits and then starts it", async () => {
  stubStorage();
  const { calls, cli } = fakeCli((args) => {
    if (args[1] === "restart") throw restartFailed(null);
    if (args[1] === "status") return { running: false, proxy: null };
    return {};
  });
  const ctl = proxyControl();
  const moved = moveProxy(cli, ctl, movable, 9090);
  assert.equal(await startProxy(cli, ctl), "127.0.0.1:8080");
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
    if (args[1] === "setup") return {};
    if (fail(args)) throw args[1] === "restart" ? restartFailed(pids.shift()!) : cliError(BIND_FAILURE);
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
  assert.deepEqual(calls, [SHOW, ["proxy", "start", "--listen=127.0.0.1:8083"]]);
  assert.equal(ctl.owned, null);
});

test("stopOwned: nothing the app started, nothing stopped (an unverifiable record, an agent's proxy)", async () => {
  const { calls, cli } = proxyCli(() => runningAs(7));
  await stopOwned(cli, proxyControl());
  assert.deepEqual(calls, []);
});

test("stopOwned stops the app's proxy only if the CLI still finds it running as that pid, in one call", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = proxyCli(() => runningAs(7));
  await stopOwned(cli, ctl);
  assert.deepEqual(calls, [["proxy", "stop", "--pid=7"]]);
  assert.equal(ctl.owned, null);
});

test("stopOwned leaves a proxy someone else started since, one in another container, or none", async () => {
  // The CLI's answer when the proxy isn't pid 7 here, or there is none.
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = fakeCli(() => {
    throw cliError("not found: pid 7 isn't this project's proxy here (the record is now pid 8's); nothing was stopped");
  });
  await stopOwned(cli, ctl);
  assert.deepEqual(calls, [["proxy", "stop", "--pid=7"]]);
  assert.equal(ctl.owned, null);
});

test("stopOwned: a stop that fails otherwise rejects", async () => {
  const ctl = proxyControl();
  ctl.owned = 7;
  const message = "conflict: the proxy (pid 7) is still running after being asked to stop";
  const { cli } = fakeCli(() => {
    throw cliError(message);
  });
  await assert.rejects(stopOwned(cli, ctl), { message });
  assert.equal(ctl.owned, null);
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
    if (args[1] === "restart") throw restartFailed(null);
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

test("restartFailure: the data decides, not the wording; a pid only for the proxy started again", () => {
  const timeout = "conflict: timed out after 10s";
  const back = cliError(`${timeout}; it went back, in other words`, { stopped: true, failure: timeout, restarted: { pid: 9, listen: "[::1]:8080" } });
  assert.deepEqual(restartFailure(back), { message: timeout, stopped: true, pid: 9 });
  // Not going back, a pid in the reason or in where it is now isn't the app's.
  const taken = `${BIND_FAILURE}; the proxy couldn't be started again on 127.0.0.1:8080: conflict: proxy already running on 127.0.0.1:7000 (pid 12). A proxy is running on 127.0.0.1:7000 (pid 12) now`;
  assert.deepEqual(restartFailure(cliError(taken, { stopped: true, failure: BIND_FAILURE, restarted: null })), { message: BIND_FAILURE, stopped: true, pid: null });
  // Called off by `proxy stop`: off.
  const off = "conflict: the restart was called off by `brainproxy proxy stop` after it had stopped the proxy (pid 7)";
  const calledOff = cliError(`${off}; the proxy is off`, { stopped: true, failure: off, restarted: null, called_off: true });
  assert.deepEqual(restartFailure(calledOff), { message: off, stopped: true, pid: null });
  // The old ending in a message without data is just a message.
  for (const message of [
    "conflict: the proxy was stopped or replaced while restarting it; see `brainproxy proxy status`",
    `${BIND_FAILURE}; the proxy was started again on 127.0.0.1:8080 (pid 9)`,
  ]) {
    assert.deepEqual(restartFailure(new Error(message)), { message, stopped: false, pid: null });
  }
});

test("moveProxy: a failed restart of a proxy the app didn't start leaves the app owning nothing new", async () => {
  for (const pid of [9, null]) {
    const ctl = proxyControl();
    ctl.owned = 3; // An earlier proxy of the app's, not the one moved.
    const { cli } = fakeCli((args) => {
      if (args[1] === "restart") throw restartFailed(pid);
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
  assert.deepEqual(calls.at(-1), ["proxy", "stop", "--pid=9"]);
  assert.equal(ctl.owned, null);
});

test("during a move that went back, a start waits and starts nothing", async () => {
  stubStorage();
  const { calls, cli } = proxyCli(() => runningAs(9), [9], (args) => args[1] === "restart");
  const ctl = proxyControl();
  const moved = moveProxy(cli, ctl, movable, 9090);
  assert.equal(await startProxy(cli, ctl), null);
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
    SHOW,
    ["proxy", "start", "--listen=127.0.0.1:9090", ...LIVE],
  ]);
  assert.equal(d.listen, "127.0.0.1:9090");
  assert.equal(ctl.owned, 8);
});

test("startLive starts a proxy that isn't running with the project's saved setup, plus live testing", async () => {
  stubStorage({ [PROXY_PORT]: "9090" });
  const { calls, cli } = fakeCli(withSaved({ network: "all", redirect: "https://app.acme.test" }, (args) => (args[1] === "status" ? { running: false, proxy: null } : { pid: 8 })));
  const d = await startLive(cli, proxyControl(), LIVE);
  assert.deepEqual(calls.at(-1), ["proxy", "start", "--listen=0.0.0.0:9090", "--redirect=https://app.acme.test", ...LIVE]);
  assert.equal(d.listen, "0.0.0.0:9090");
});

test("startLive leaves the saved setup alone for a proxy that runs: it keeps its own options", async () => {
  const { calls, cli } = proxyCli(() => ({ running: true, proxy: liveRunning }), [8]);
  await startLive(cli, proxyControl(), LIVE);
  assert.ok(!calls.some((c) => c[1] === "setup"), JSON.stringify(calls));
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
        throw cliError(
          pid == null
            ? `${failure}; the proxy couldn't be started again on 127.0.0.1:8081: conflict: cannot listen. It is off now`
            : `${failure}; the proxy was started again on 127.0.0.1:8081 (pid ${pid})`,
          { stopped: true, failure, restarted: pid == null ? null : { pid, listen: "127.0.0.1:8081" } },
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
  assert.equal(await started, null);
  assert.equal(calls.filter(isStart).length, 0);
  assert.equal(ctl.moving, null);
});

// The setup (proxyMode.ts): who can connect, invisible mode and the redirect.

test("startProxy starts with the setup saved in the project file", async () => {
  stubStorage({ [PROXY_PORT]: "80" });
  const fake = fakeCli(withSaved({ network: "all", invisible: true, redirect: "https://app.acme.test" }));
  assert.equal(await startProxy(fake.cli, proxyControl()), "0.0.0.0:80");
  assert.deepEqual(fake.calls, [SHOW, ["proxy", "start", "--listen=0.0.0.0:80", "--redirect=https://app.acme.test"]]);
  assert.equal(proxyListen(), "127.0.0.1:80");
});

test("startProxy: a setup that can't be read starts nothing", async () => {
  const fake = fakeCli((args) => {
    if (args[1] === "setup") throw new Error("internal: database is locked");
  });
  await assert.rejects(startProxy(fake.cli, proxyControl(), 8080), { message: "internal: database is locked" });
  assert.deepEqual(fake.calls, [SHOW]);
});

test("startProxy returns the address the proxy reports, or the one it asked for", async () => {
  let fake = fakeCli(withSaved({}, (args) => (isStart(args) ? { pid: 3, listen: "127.0.0.1:41000" } : {})));
  assert.equal(await startProxy(fake.cli, proxyControl(), 8080), "127.0.0.1:41000");
  fake = fakeCli();
  assert.equal(await startProxy(fake.cli, proxyControl(), 8080), "127.0.0.1:8080");
});

test("moveProxy with a setup: its host, invisible mode and redirect, the other options kept", async () => {
  const running = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--listen", "127.0.0.1:8080", "--timeout", "30", "--invisible"] };
  const { calls, cli } = fakeCli();
  const setup = { allInterfaces: true, invisible: false, redirect: "https://app.acme.test" };
  assert.equal(await moveProxy(cli, proxyControl(), running, 443, setup), "0.0.0.0:443");
  assert.deepEqual(calls, [["proxy", "restart", "--listen=0.0.0.0:443", "--timeout=30", "--redirect=https://app.acme.test"]]);
});

test("moveProxy with a setup on the same port: only the mode changes", async () => {
  const { calls, cli } = fakeCli();
  const setup = { allInterfaces: false, invisible: true, redirect: null };
  assert.equal(await moveProxy(cli, proxyControl(), { listen: "[::1]:8080" }, 8080, setup), "[::1]:8080");
  assert.deepEqual(calls, [["proxy", "restart", "--listen=[::1]:8080", "--invisible"]]);
});

test("moveProxy with a setup that fails: the CLI puts the proxy back as it was, and the app keeps it", async () => {
  const running = { listen: "127.0.0.1:8080", pid: 7, args: ["proxy", "run", "--listen", "127.0.0.1:8080", "--redirect", "https://old.test"] };
  const ctl = proxyControl();
  ctl.owned = 7;
  const { calls, cli } = proxyCli(() => runningAs(9), [9], (args) => args.includes("--listen=0.0.0.0:80"));
  await assert.rejects(moveProxy(cli, ctl, running, 80, { allInterfaces: true, invisible: true, redirect: null }), {
    message: `${HINTED} The proxy is back on 127.0.0.1:8080.`,
  });
  // One restart: going back, with the old options, is the CLI's job.
  assert.deepEqual(calls, [
    ["proxy", "restart", "--listen=0.0.0.0:80", "--invisible"],
    ["proxy", "status"],
  ]);
  assert.equal(ctl.owned, 9);
});

test("moveProxy back to this computer only: a proxy on every interface doesn't stay there", async () => {
  for (const host of ["0.0.0.0", "[::]", "192.168.1.5"]) {
    const running = { listen: `${host}:8080`, args: ["proxy", "run", "--listen", `${host}:8080`, "--invisible", "--redirect", "https://old.test", "--auth", "alice"] };
    const { calls, cli } = fakeCli();
    assert.equal(await moveProxy(cli, proxyControl(), running, 8080, { allInterfaces: false, invisible: false, redirect: null }), "127.0.0.1:8080", host);
    assert.deepEqual(calls, [["proxy", "restart", "--listen=127.0.0.1:8080", "--auth=alice"]], host);
  }
});

test("moveProxy with a setup: the app's proxy stays the app's, another's doesn't become it", async () => {
  const setup = { allInterfaces: true, invisible: true, redirect: null };
  const ctl = proxyControl();
  ctl.owned = 7;
  let fake = proxyCli(() => ({}), [8]);
  await moveProxy(fake.cli, ctl, { listen: "127.0.0.1:8080", pid: 7 }, 8080, setup);
  assert.equal(ctl.owned, 8);

  const other = proxyControl();
  fake = proxyCli(() => ({}), [9]);
  await moveProxy(fake.cli, other, { listen: "127.0.0.1:8080", pid: 7 }, 8080, setup);
  assert.equal(other.owned, null);
});

test("moveProxy without a setup keeps a shell's invisible mode and redirect, as one option each", async () => {
  const running = { listen: "0.0.0.0:80", args: ["proxy", "run", "--listen", "0.0.0.0:80", "--invisible", "--redirect", "https://app.acme.test", "--no-http2"] };
  const { calls, cli } = fakeCli();
  assert.equal(await moveProxy(cli, proxyControl(), running, 8080), "0.0.0.0:8080");
  assert.deepEqual(calls, [["proxy", "restart", "--listen=0.0.0.0:8080", "--invisible", "--redirect=https://app.acme.test", "--no-http2"]]);
});

test("startProxy: a saved redirect that isn't a plain origin never reaches the start", async () => {
  for (const redirect of ["https://me:pw@app.acme.test", "https://app.acme.test/api", "https://app.acme.test --listen=0.0.0.0:80"]) {
    const { calls, cli } = fakeCli(withSaved({ redirect }));
    await startProxy(cli, proxyControl());
    assert.deepEqual(calls, [SHOW, ["proxy", "start", "--listen=127.0.0.1:8080"]], redirect);
  }
});

test("startProxy: an unreadable saved setup starts on this computer only", async () => {
  for (const saved of [null, "all", { network: "ALL", invisible: "1" }]) {
    const fake = fakeCli(withSaved(saved as object));
    await startProxy(fake.cli, proxyControl(), 9090);
    assert.deepEqual(fake.calls, [SHOW, ["proxy", "start", "--listen=127.0.0.1:9090"]], JSON.stringify(saved));
  }
});

test("a start waiting on a setup move that left the proxy off starts it with the saved setup", async () => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  const { calls, cli } = fakeCli(async (args) => {
    if (args[1] === "setup") return { network: "all", redirect: "https://app.acme.test" };
    if (args[1] === "restart") {
      await held;
      throw cliError(BIND_FAILURE, { stopped: true, failure: BIND_FAILURE, restarted: null });
    }
    if (args[1] === "status") return { running: false, proxy: null };
    return {};
  });
  const ctl = proxyControl();
  const moved = moveProxy(cli, ctl, { listen: "127.0.0.1:8080" }, 80, { allInterfaces: true, invisible: false, redirect: "https://app.acme.test" });
  const started = startProxy(cli, ctl, 8080).catch((e) => e);
  release();
  await assert.rejects(moved);
  await started;
  // The move's restart and status, then the waiting start's status check, setup and its own start.
  assert.deepEqual(calls.at(-1), ["proxy", "start", "--listen=0.0.0.0:8080", "--redirect=https://app.acme.test"]);
});

test("lowPortNote says what privileges a low port needs", () => {
  assert.match(lowPortNote(80)!, /CAP_NET_BIND_SERVICE/);
  assert.match(lowPortNote(1)!, /stays off/);
  assert.equal(lowPortNote(65535), null);
});
