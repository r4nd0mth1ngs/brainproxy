import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// Dev-only bridge so the UI also runs in a plain browser (`npm run dev`): POST /api/cli runs
// the brainproxy CLI the same way the Tauri `cli` command does. It answers only requests
// to a localhost Host with the X-Brainproxy header, which blocks DNS rebinding and simple
// cross-site posts. Never part of a build.
function cliBridge(): Plugin {
  const bin = process.env.BRAINPROXY_BIN ?? resolve(import.meta.dirname, `../target/debug/brainproxy${process.platform === "win32" ? ".exe" : ""}`);
  return {
    name: "brainproxy-cli-bridge",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/api/cli", (req, res) => {
        const host = (req.headers.host ?? "").replace(/:\d+$/, "");
        if (req.method !== "POST" || req.headers["x-brainproxy"] !== "1" || !["localhost", "127.0.0.1"].includes(host)) {
          res.statusCode = 403;
          res.end();
          return;
        }
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          const { project, args, stdin, env } = JSON.parse(body) as {
            project: string;
            args: string[];
            stdin?: number[] | null;
            env?: Record<string, string> | null;
          };
          // Same rules as the Tauri command: without a project only `project temp|sweep` run, and
          // only BRAINPROXY_SECRET_* variables may be set.
          if (!project && !["project temp", "project sweep"].includes(args.slice(0, 2).join(" "))) {
            res.setHeader("content-type", "application/json");
            res.end(JSON.stringify({ ok: false, error: { kind: "gui", message: "no project is open" } }));
            return;
          }
          const extra = Object.fromEntries(Object.entries(env ?? {}).filter(([k]) => k.startsWith("BRAINPROXY_SECRET_")));
          const child = spawn(bin, ["--format", "json", ...(project ? ["--project", project] : []), ...args], {
            stdio: [stdin == null ? "ignore" : "pipe", "pipe", "pipe"],
            env: { ...process.env, ...extra },
          });
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
            const fix = process.env.BRAINPROXY_BIN ? "check BRAINPROXY_BIN" : "run `cargo build` in the repository root, or set BRAINPROXY_BIN";
            const message = e.code === "ENOENT" ? `No brainproxy CLI at ${bin}: ${fix}.` : String(e);
            res.setHeader("content-type", "application/json");
            res.end(JSON.stringify({ ok: false, error: { kind: "gui", message } }));
          });
          // Also emitted after a failed spawn, once "error" has already answered.
          child.on("close", () => {
            if (res.writableEnded) return;
            res.setHeader("content-type", "application/json");
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
