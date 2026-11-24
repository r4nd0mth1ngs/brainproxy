import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_CLICKJACKING, DEFAULT_CSRF, defaultName, dropNames, joinPath, opacityArg, openWarning, pocArgs, readsStdin, summary, tabUrl, tempName, type ClickjackingPage, type CsrfPage } from "./poc.ts";

const defaults = { csrf: DEFAULT_CSRF, clickjacking: DEFAULT_CLICKJACKING };

test("a recorded request is named by its id, a Replay tab's goes on stdin", () => {
  assert.deepEqual(pocArgs("csrf", { historyId: 7 }, defaults), ["poc", "csrf", "--history-id", "7"]);
  const tab = { raw: "POST /a HTTP/1.1\nHost: x\n\n", target: "https://x.test" };
  assert.deepEqual(pocArgs("csrf", tab, defaults), ["poc", "csrf", "--file", "-", "--target", "https://x.test"]);
  assert.ok(readsStdin("csrf", tab));
  assert.ok(!readsStdin("csrf", { historyId: 7 }));
  // A clickjacking page frames the tab's URL: nothing on stdin.
  assert.deepEqual(pocArgs("clickjacking", tab, defaults), ["poc", "clickjacking", "--url", "https://x.test/a", "--opacity", "0.5", "--decoy=Click me"]);
  assert.ok(!readsStdin("clickjacking", tab));
});

test("the settings become flags", () => {
  const csrf = { technique: "fetch" as const, autoSubmit: true, drop: "csrf_token, _token  csrf_token" };
  assert.deepEqual(pocArgs("csrf", { historyId: 1 }, { ...defaults, csrf }), [
    "poc",
    "csrf",
    "--history-id",
    "1",
    "--technique",
    "fetch",
    "--auto-submit",
    "--drop-param=csrf_token",
    "--drop-param=_token",
  ]);
  const clickjacking = { opacity: 0.333, decoy: "--force" };
  assert.deepEqual(pocArgs("clickjacking", { historyId: 2 }, { ...defaults, clickjacking }, { path: "/tmp/p.html", overwrite: true }), [
    "poc",
    "clickjacking",
    "--history-id",
    "2",
    "--opacity",
    "0.33",
    "--decoy=--force",
    "--output",
    "/tmp/p.html",
    "--force",
  ]);
  assert.deepEqual(pocArgs("csrf", { historyId: 1 }, defaults, { path: "a.html", overwrite: false }).slice(-2), ["--output", "a.html"]);
  assert.deepEqual(pocArgs("clickjacking", { historyId: 2 }, { ...defaults, clickjacking: { opacity: 1, decoy: "" } }).slice(-1), ["--decoy=Click me"]);
});

test("names to leave out and the opacity are read forgivingly", () => {
  assert.deepEqual(dropNames(" a,b\nc ,, a "), ["a", "b", "c"]);
  assert.deepEqual(dropNames(""), []);
  assert.equal(opacityArg(2), "1");
  assert.equal(opacityArg(-1), "0");
  assert.equal(opacityArg(NaN), "0.5");
  assert.equal(opacityArg(0.25), "0.25");
});

test("a tab's URL", () => {
  assert.equal(tabUrl("GET /x?y=1 HTTP/1.1\r\nHost: a\r\n\r\n", "http://a.test:8080/"), "http://a.test:8080/x?y=1");
  assert.equal(tabUrl("GET https://b.test/z HTTP/1.1\n\n", "http://a.test"), "https://b.test/z");
  assert.equal(tabUrl("", "https://a.test"), "https://a.test/");
});

test("file names", () => {
  assert.equal(defaultName("csrf", { historyId: 12 }), "csrf-poc-12.html");
  assert.equal(defaultName("clickjacking", { raw: "", target: "" }), "clickjacking-poc.html");
  const name = tempName("csrf", () => 0.5);
  assert.match(name, /^brainproxy-poc-csrf-[0-9a-z]{10}\.html$/);
  assert.notEqual(tempName("csrf"), tempName("csrf"));
  assert.equal(joinPath("/tmp/", "a.html"), "/tmp/a.html");
  assert.equal(joinPath("/tmp", "a.html"), "/tmp/a.html");
  assert.equal(joinPath("C:\\Users\\me\\Temp", "a.html"), "C:\\Users\\me\\Temp\\a.html");
});

test("the opener may open only what tempName writes", async () => {
  const { readFileSync } = await import("node:fs");
  const caps = JSON.parse(readFileSync(new URL("../../src-tauri/capabilities/default.json", import.meta.url), "utf8"));
  const open = caps.permissions.find((p: any) => p.identifier === "opener:allow-open-path");
  const glob: string = open.allow.map((a: any) => a.path).find((p: string) => p.startsWith("$TEMP/"));
  assert.equal(glob, "$TEMP/brainproxy-poc-*.html");
  assert.ok(tempName("clickjacking").startsWith(glob.slice("$TEMP/".length, -"*.html".length)));
});

test("the summary and the warning before opening say what the page does", () => {
  const csrf: CsrfPage = {
    kind: "csrf",
    history_id: 1,
    method: "POST",
    action: "https://a.test/x",
    encoding: "urlencoded",
    technique: "form",
    fields: [],
    auto_submit: true,
    warnings: [],
    html: "",
    path: null,
  };
  assert.equal(summary(csrf), "Sends POST https://a.test/x from a form, with the visitor's cookies, as soon as the page opens.");
  const cj: ClickjackingPage = {
    kind: "clickjacking",
    history_id: 1,
    url: "https://a.test/",
    framing: { x_frame_options: "DENY", frame_ancestors: null, blocked: true },
    warnings: [],
    html: "",
    path: null,
  };
  assert.equal(summary(cj), "Frames https://a.test/, but its response says it can't be framed (X-Frame-Options: DENY).");
  assert.match(summary({ ...cj, framing: { x_frame_options: null, frame_ancestors: null, blocked: false } }), /sets no framing protection/);
  assert.match(summary({ ...cj, framing: { x_frame_options: null, frame_ancestors: null, blocked: null } }), /unknown/);
  assert.match(openWarning("csrf"), /not through brainproxy and its scope checks/);
  assert.match(openWarning("clickjacking"), /not through brainproxy and its scope checks/);
});
