import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { resolve, join } from "node:path";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// Dev-only bridge so the UI also runs in a plain browser (`npm run dev`): POST /api/cli runs
// the brainproxy CLI the same way the Tauri `cli` command does. It answers only requests
// to a localhost Host whose X-Brainproxy header is this run's random token, which blocks DNS
// rebinding and cross-site posts, and anything else on this machine that can send HTTP: an
// agent's `send` through MCP would otherwise run any command, with none of the MCP limits.
// The token is printed with the URL to open (#bridge=<token>; the fragment never reaches
// a server) and is in no page or file the dev server serves. Requests with brainproxy's
// own User-Agent are refused too. Never part of a build. POST /api/cli-cancel {call} stops
// a call started with that `call` id (SIGTERM, then SIGKILL), as the Tauri `cli_cancel`
// command does.
function cliBridge(): Plugin {
  const running = new Map<string, ChildProcess>();
  const cancelled = new Set<ChildProcess>();
  const token = randomBytes(32).toString("hex");
  const allowed = (req: IncomingMessage) => {
    const host = String(req.headers.host ?? "").replace(/:\d+$/, "");
    const given = Buffer.from(String(req.headers["x-brainproxy"] ?? ""));
    const tokenOk = given.length === token.length && timingSafeEqual(given, Buffer.from(token));
    const fromBrainproxy = String(req.headers["user-agent"] ?? "").toLowerCase().startsWith("brainproxy/");
    return req.method === "POST" && tokenOk && !fromBrainproxy && ["localhost", "127.0.0.1"].includes(host);
  };
  const refuse = (res: ServerResponse) => {
    res.statusCode = 403;
    res.setHeader("content-type", "application/json");
    const message = "The dev bridge needs this run's token: open the URL `npm run dev` printed (it ends in #bridge=...).";
    res.end(JSON.stringify({ ok: false, error: { kind: "gui", message } }));
  };
  const bin = process.env.BRAINPROXY_BIN ?? resolve(import.meta.dirname, `../target/debug/brainproxy${process.platform === "win32" ? ".exe" : ""}`);
  return {
    name: "brainproxy-cli-bridge",
    apply: "serve",
    configureServer(server) {
      const printUrls = server.printUrls;
      server.printUrls = () => {
        printUrls.call(server);
        const local = server.resolvedUrls?.local[0] ?? "http://127.0.0.1:5173/";
        server.config.logger.info(`  brainproxy dev bridge: open ${local}#bridge=${token}`);
      };
      server.middlewares.use("/api/cli-cancel", (req, res) => {
        if (!allowed(req)) {
          refuse(res);
          return;
        }
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          const { call } = JSON.parse(body) as { call: string };
          const child = running.get(call);
          if (child) {
            cancelled.add(child);
            // SIGTERM first, so a request already sent is recorded as cancelled; SIGKILL if it is
            // still running after 3 s. (On Windows both end the process at once.)
            child.kill("SIGTERM");
            const timer = setTimeout(() => child.kill("SIGKILL"), 3000);
            child.once("close", () => clearTimeout(timer));
          }
          res.end("{}");
        });
      });
      server.middlewares.use("/api/cli", (req, res) => {
        if (!allowed(req)) {
          refuse(res);
          return;
        }
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          const { project, args, stdin, env, call, requestFiles } = JSON.parse(body) as {
            project: string;
            args: string[];
            stdin?: number[] | null;
            requestFiles?: number[][] | null;
            env?: Record<string, string> | null;
            call?: string | null;
          };
          // Same rule as the Tauri command: only BRAINPROXY_SECRET_* variables may be set.
          const extra = Object.fromEntries(Object.entries(env ?? {}).filter(([k]) => k.startsWith("BRAINPROXY_SECRET_")));
          let requestDir: string | null = null;
          const cleanup = () => { if (requestDir) rmSync(requestDir, { recursive: true, force: true }); };
          try {
            if (requestFiles?.length) {
              requestDir = mkdtempSync(join(tmpdir(), "brainproxy-race-"));
              requestFiles.forEach((bytes, i) => {
                const at = args.indexOf(`--also=@request:${i}`);
                if (at < 0) throw new Error("missing race request argument");
                const path = join(requestDir!, `${i}.http`);
                writeFileSync(path, Buffer.from(bytes), { flag: "wx", mode: 0o600 });
                args[at] = `--also=${path}`;
              });
            }
          } catch (e) {
            cleanup();
            res.setHeader("content-type", "application/json");
            res.end(JSON.stringify({ ok: false, error: { kind: "gui", message: String(e) } }));
            return;
          }
          const child = spawn(bin, ["--format", "json", "--project", project, ...args], {
            stdio: [stdin == null ? "ignore" : "pipe", "pipe", "pipe"],
            // What the CLI records is marked as the app's (origin `gui`), as with the Tauri command.
            env: { ...process.env, ...extra, BRAINPROXY_CLIENT: "gui" },
          });
          if (call) running.set(call, child);
          if (stdin != null) {
            // The CLI may exit without reading stdin (EPIPE); unhandled, that would kill the dev server.
            child.stdin!.on("error", () => {});
            child.stdin!.end(Buffer.from(stdin));
          }
          let out = "";
          let err = "";
          child.stdout!.on("data", (c) => (out += c));
          child.stderr!.on("data", (c) => (err += c));
          child.on("error", (e: NodeJS.ErrnoException) => {
            cleanup();
            const fix = process.env.BRAINPROXY_BIN ? "check BRAINPROXY_BIN" : "run `cargo build` in the repository root, or set BRAINPROXY_BIN";
            const message = e.code === "ENOENT" ? `No brainproxy CLI at ${bin}: ${fix}.` : String(e);
            res.setHeader("content-type", "application/json");
            res.end(JSON.stringify({ ok: false, error: { kind: "gui", message } }));
          });
          // Also emitted after a failed spawn, once "error" has already answered.
          child.on("close", () => {
            cleanup();
            if (call) running.delete(call);
            const stopped = cancelled.delete(child);
            if (res.writableEnded) return;
            res.setHeader("content-type", "application/json");
            if (stopped) {
              // A CLI that exited in time answers itself (as the Tauri command does): marked cancelled.
              let v: any = null;
              try {
                v = JSON.parse(out);
              } catch {}
              if (v && typeof v === "object") {
                v.cancelled = true;
                if (v.ok === false && v.error) v.error = { ...v.error, cli_kind: v.error.kind, kind: "cancelled" };
                return res.end(JSON.stringify(v));
              }
              return res.end(JSON.stringify({ ok: false, command: "gui", error: { kind: "cancelled", message: "cancelled" } }));
            }
            res.end(out.trim() || JSON.stringify({ ok: false, error: { kind: "gui", message: err.trim() || "no output" } }));
          });
        });
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), cliBridge()],
  clearScreen: false,
  server: { port: 5173, strictPort: true, host: "127.0.0.1" },
  build: { target: "es2022", outDir: "dist" },
});
