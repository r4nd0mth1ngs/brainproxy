import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_PROXY_PORT, PROXY_PORT, PROXY_PORTS, lowPortNote, moveProxy, portOf, portProblem, proxyListen, saveProxyPort, savedProxyPort, startPorts, startProxy, withPort, withPortHint } from "./proxyPort.ts";

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

/** A `cli` that records its calls; `answer` throws to make a call fail. */
function fakeCli(answer: (args: string[], call: number) => void = () => {}) {
  const calls: string[][] = [];
  const cli = async (args: string[]) => {
    calls.push(args);
    answer(args, calls.length);
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
  await startProxy(fake.cli);
  assert.deepEqual(fake.calls, [["proxy", "start", "--listen=127.0.0.1:9090"]]);

  stubStorage();
  fake = fakeCli();
  await startProxy(fake.cli);
  assert.deepEqual(fake.calls, [["proxy", "start", "--listen=127.0.0.1:8080"]]);
});

test("startProxy: a failed bind still rejects, now with the hint; other errors are unchanged", async () => {
  stubStorage();
  const failing = (message: string) =>
    fakeCli(() => {
      throw new Error(message);
    }).cli;
  await assert.rejects(startProxy(failing(BIND_FAILURE)), { message: HINTED });
  await assert.rejects(startProxy(failing("conflict: proxy already running")), { message: "conflict: proxy already running" });
});

test("moveProxy stops, then starts on the new port, and returns the address", async () => {
  const { calls, cli } = fakeCli();
  const target = await moveProxy(cli, { listen: "127.0.0.1:8080" }, 9090);
  assert.equal(target, "127.0.0.1:9090");
  assert.deepEqual(calls, [
    ["proxy", "stop"],
    ["proxy", "start", "--listen=127.0.0.1:9090"],
  ]);
});

test("moveProxy keeps the host", async () => {
  for (const host of ["0.0.0.0", "[::1]"]) {
    const { calls, cli } = fakeCli();
    assert.equal(await moveProxy(cli, { listen: `${host}:8080` }, 9090), `${host}:9090`);
    assert.deepEqual(calls[1], ["proxy", "start", `--listen=${host}:9090`]);
  }
});

test("moveProxy keeps the options the proxy runs with, but not --listen, --log or --wait", async () => {
  const running = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--listen", "127.0.0.1:8080", "--timeout", "30", "--verify-tls", "--log", "x.log"] };
  let fake = fakeCli();
  await moveProxy(fake.cli, running, 9090);
  assert.deepEqual(fake.calls[1], ["proxy", "start", "--listen=127.0.0.1:9090", "--timeout=30", "--verify-tls"]);

  fake = fakeCli();
  await moveProxy(fake.cli, { listen: "127.0.0.1:8080", args: ["proxy", "run", "--listen=127.0.0.1:8080", "--timeout=30", "--wait=5", "--log=x.log", "--auth=alice"] }, 9090);
  assert.deepEqual(fake.calls[1], ["proxy", "start", "--listen=127.0.0.1:9090", "--timeout=30", "--auth=alice"]);
});

test("moveProxy: when stop fails it rejects and starts nothing", async () => {
  const { calls, cli } = fakeCli(() => {
    throw new Error("stop failed");
  });
  await assert.rejects(moveProxy(cli, { listen: "127.0.0.1:8080" }, 9090), { message: "stop failed" });
  assert.deepEqual(calls, [["proxy", "stop"]]);
});

const movable = { listen: "127.0.0.1:8080", args: ["proxy", "run", "--listen", "127.0.0.1:8080", "--timeout", "30"] };

test("moveProxy: when the new port fails the proxy goes back where it was", async () => {
  const { calls, cli } = fakeCli((args) => {
    if (args.includes("--listen=127.0.0.1:9090")) throw new Error(BIND_FAILURE);
  });
  await assert.rejects(moveProxy(cli, movable, 9090), { message: `${HINTED} The proxy is back on 127.0.0.1:8080.` });
  assert.deepEqual(calls, [
    ["proxy", "stop"],
    ["proxy", "start", "--listen=127.0.0.1:9090", "--timeout=30"],
    ["proxy", "start", "--listen=127.0.0.1:8080", "--timeout=30"],
  ]);
});

test("moveProxy: when going back fails too, the error says the proxy is off", async () => {
  const { calls, cli } = fakeCli((args) => {
    if (isStart(args)) throw new Error(BIND_FAILURE);
  });
  await assert.rejects(moveProxy(cli, movable, 9090), { message: `${HINTED} The proxy is off.` });
  assert.equal(calls.length, 3);
});
