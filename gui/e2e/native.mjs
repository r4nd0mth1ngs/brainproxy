#!/usr/bin/env node
// A screenshot test of the native window: the built app, driven over WebDriver.
//
// tauri-driver starts the app and forwards WebDriver to the platform's webview driver
// (WebKitWebDriver on Linux). There's no WKWebView driver on macOS, so this runs on Linux
// (CI runs it under xvfb). The WebDriver client is the few calls below over fetch, so the
// test adds no npm dependencies.
//
// It makes a project with one recorded request, opens it from Welcome, checks that the
// shell rendered and that Traffic shows the row the CLI recorded, and saves a screenshot.
//
// Environment:
//   APP              the built app (default: src-tauri/target/debug/brainproxy-gui)
//   BRAINPROXY_BIN   the CLI the app runs (default: ../target/debug/brainproxy)
//   TAURI_DRIVER     tauri-driver (default: tauri-driver on PATH)
//   SCREENSHOT       where the PNG goes (default: e2e/native.png)

import { execFile, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const gui = resolve(here, "..");
const app = resolve(process.env.APP ?? join(gui, "src-tauri/target/debug/brainproxy-gui"));
const cli = resolve(process.env.BRAINPROXY_BIN ?? join(gui, "../target/debug/brainproxy"));
const driverBin = process.env.TAURI_DRIVER ?? "tauri-driver";
const shot = resolve(process.env.SCREENSHOT ?? join(here, "native.png"));
const PORT = 4444;
const BASE = `http://127.0.0.1:${PORT}`;
const PROBE = "/native-e2e-probe";

const run = promisify(execFile);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Async, not spawnSync: the fixture's server runs in this process, and a blocked event loop
// would leave `send` waiting on a server that can't answer.
async function brainproxy(project, args) {
  try {
    const { stdout } = await run(cli, ["--format", "json", "--project", project, ...args], { encoding: "utf8" });
    return JSON.parse(stdout);
  } catch (e) {
    throw new Error(`brainproxy ${args.join(" ")} failed: ${e.stderr || e.stdout || e.message}`);
  }
}

/** A project in a new folder with one request recorded against a local server. */
async function fixture(dir) {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("native e2e\n");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const project = join(dir, "native.bpdb");
  try {
    await brainproxy(project, ["engagement", "start", "--target", "127.0.0.1"]);
    await brainproxy(project, ["send", "--url", `http://127.0.0.1:${port}${PROBE}`]);
  } finally {
    server.close();
  }
  return project;
}

async function wd(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`WebDriver ${method} ${path}: ${res.status} ${JSON.stringify(json.value ?? json)}`);
  return json.value;
}

async function driverReady() {
  for (let i = 0; i < 100; i++) {
    try {
      const res = await fetch(`${BASE}/status`);
      if (res.ok) return;
    } catch {
      /* not listening yet */
    }
    await sleep(200);
  }
  throw new Error("tauri-driver didn't start");
}

/** Polls a script in the page until it returns something truthy. */
async function until(session, what, script, args = [], ms = 30_000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    try {
      last = await wd("POST", `/session/${session}/execute/sync`, { script, args });
      if (last) return last;
    } catch (e) {
      last = e;
    }
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${what} (last: ${last instanceof Error ? last.message : JSON.stringify(last)})`);
}

const CLICK_TEXT = `
  const [selector, text] = arguments;
  const label = (e) => (e.querySelector(".nav-label") ?? e).textContent.trim();
  const el = [...document.querySelectorAll(selector)].find((e) => label(e) === text);
  if (!el) return false;
  el.click();
  return true;`;

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "bp-native-"));
  const driver = spawn(driverBin, ["--port", String(PORT)], {
    stdio: "inherit",
    env: { ...process.env, BRAINPROXY_BIN: cli },
  });
  let session;
  try {
    const project = await fixture(dir);
    await driverReady();
    session = (
      await wd("POST", "/session", {
        capabilities: { alwaysMatch: { browserName: "wry", "tauri:options": { application: app } } },
      })
    ).sessionId;

    // Welcome lists Recent from localStorage. The proxy stays off, so the test needs no port.
    await until(session, "the Welcome screen", "return !!document.querySelector('.app, .welcome, button');");
    await wd("POST", `/session/${session}/execute/sync`, {
      script: `localStorage.setItem("recent-projects", JSON.stringify([arguments[0]]));
        localStorage.setItem("auto-proxy", "off");
        location.reload();
        return true;`,
      args: [project],
    });
    await until(session, "the project on Recent", "const b = document.querySelector('.recent-item'); if (b) b.click(); return !!b;");
    await until(session, "the app shell", "return !!document.querySelector('.app .nav-item');");
    await until(session, "the Proxy view", CLICK_TEXT, [".nav-item", "Proxy"]);
    await until(session, "the Traffic tab", CLICK_TEXT, [".subtabs button", "Traffic"]);
    // The row comes from `history list`, run by the CLI the app started.
    await until(session, "the recorded request in Traffic", "return document.body.innerText.includes(arguments[0]);", [PROBE]);

    const png = await wd("GET", `/session/${session}/screenshot`);
    writeFileSync(shot, Buffer.from(png, "base64"));
    console.log(`native window rendered; screenshot at ${shot}`);
  } catch (e) {
    if (session) {
      try {
        const png = await wd("GET", `/session/${session}/screenshot`);
        writeFileSync(shot, Buffer.from(png, "base64"));
        console.error(`failed; screenshot of the failure at ${shot}`);
      } catch {
        /* the window is gone */
      }
    }
    throw e;
  } finally {
    if (session) await wd("DELETE", `/session/${session}`).catch(() => {});
    driver.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
