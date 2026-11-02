import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { CURL_ARG_WARN, CurlError, parseCurl, shellQuote, toCurl } from "./curl.ts";
import { textBytes } from "../api.ts";

const lines = (...l: string[]) => l.join("\n");

/** The parse error's message, or "" when the command parses. */
function refusal(cmd: string): string {
  try {
    parseCurl(cmd);
    return "";
  } catch (e) {
    assert.ok(e instanceof CurlError, String(e));
    return e.message;
  }
}

test("a plain GET gets curl's Host and Accept", () => {
  const p = parseCurl("curl https://Example.com/a?b=1#frag");
  assert.equal(p.raw, "GET /a?b=1 HTTP/1.1\nHost: Example.com\nAccept: */*\n\n");
  assert.equal(p.target, "https://Example.com");
  assert.equal(p.url, "https://Example.com/a?b=1");
  assert.equal(p.binary, false);
  assert.deepEqual(p.warnings, []);
  // No scheme means http; a default port is dropped, another kept.
  assert.equal(parseCurl("curl h.test").raw, "GET / HTTP/1.1\nHost: h.test\nAccept: */*\n\n");
  assert.equal(parseCurl("curl h.test:80?x").target, "http://h.test");
  assert.equal(parseCurl("curl https://h.test:443/").target, "https://h.test");
  const p6 = parseCurl("curl 'http://[::1]:8080/x'");
  assert.equal(p6.target, "http://[::1]:8080");
  assert.match(p6.raw, /^GET \/x HTTP\/1\.1\nHost: \[::1\]:8080\n/);
});

test("data makes a POST, joined with & like curl", () => {
  const p = parseCurl("curl -d a=1 --data 'b=2 3' --data-raw @c http://h.test:8080/x");
  assert.equal(
    p.raw,
    lines("POST /x HTTP/1.1", "Host: h.test:8080", "Accept: */*", "Content-Length: 12", "Content-Type: application/x-www-form-urlencoded", "", "a=1&b=2 3&@c"),
  );
  assert.equal(p.target, "http://h.test:8080");
  // -X changes the method only; an empty -d still sends a body.
  assert.match(parseCurl("curl -X PUT -d '' https://h.test").raw, /^PUT \/ HTTP\/1\.1\n[^]*Content-Length: 0\n/);
  assert.match(parseCurl("curl -X DELETE https://h.test/1").raw, /^DELETE \/1 HTTP\/1\.1\n/);
});

test("--data-urlencode and -G put data in the query", () => {
  const p = parseCurl("curl -G -d q=x --data-urlencode 'name=a b&c' --data-urlencode =é --data-urlencode 'x y' 'https://h.test/s?z=1'");
  assert.equal(p.raw, "GET /s?z=1&q=x&name=a%20b%26c&%C3%A9&x%20y HTTP/1.1\nHost: h.test\nAccept: */*\n\n");
  assert.match(parseCurl("curl --data-urlencode 'k=1+1' https://h.test").raw, /\n\nk=1%2B1$/);
  assert.match(parseCurl("curl --url-query a=b+c --url-query +raw=%41 https://h.test/p").raw, /^GET \/p\?a=b%2Bc&raw=%41 /);
  assert.match(refusal("curl --data-urlencode name@file https://h.test"), /reads a file/);
});

test("headers replace, remove and add to curl's own", () => {
  const p = parseCurl(
    "curl -H 'Accept: text/html' -H 'User-Agent:' -H 'X-Empty;' -H 'host: other.test' -H 'X-A:  spaced' -A ua -e 'https://ref.test/;auto' https://h.test",
  );
  assert.equal(p.raw, lines("GET / HTTP/1.1", "host: other.test", "Referer: https://ref.test/", "Accept: text/html", "X-Empty: ", "X-A: spaced", "", ""));
  assert.equal(p.target, "https://h.test");
  // Removing Content-Type leaves the body without one.
  assert.doesNotMatch(parseCurl("curl -H 'Content-Type:' -d a https://h.test").raw, /Content-Type/);
  assert.match(refusal("curl -H 'Bad header' https://h.test"), /isn't a header/);
  assert.match(refusal("curl -H $'X: a\\r\\nInjected: 1' https://h.test"), /line break/);
  assert.match(refusal("curl -A $'x\\nY: z' https://h.test"), /line break/);
  assert.match(refusal("curl -H @headers.txt https://h.test"), /reads headers from a file/);
});

test("credentials, cookies, range and compression", () => {
  const p = parseCurl("curl -u user:pass -b 'a=1' -b 'b=2; c=3' -r 0-99 --compressed https://h.test");
  assert.equal(
    p.raw,
    lines("GET / HTTP/1.1", "Host: h.test", "Authorization: Basic dXNlcjpwYXNz", "Range: bytes=0-99", "Accept: */*", "Accept-Encoding: deflate, gzip, br, zstd", "Cookie: a=1; b=2; c=3", "", ""),
  );
  assert.match(parseCurl("curl https://us%40er:p%3Ass@h.test/").raw, /Authorization: Basic dXNAZXI6cDpzcw==\n/);
  assert.match(parseCurl("curl https://user@h.test/").raw, /Authorization: Basic dXNlcjo=\n/);
  assert.match(parseCurl("curl --oauth2-bearer tok https://h.test/").raw, /Authorization: Bearer tok\n/);
  assert.equal(parseCurl("curl -u a:b https://h.test/").raw.includes("Host: h.test\n"), true);
  assert.match(refusal("curl -u user https://h.test"), /password/);
  assert.match(refusal("curl -b cookies.txt https://h.test"), /from a file/);
  assert.match(refusal("curl --digest -u a:b https://h.test"), /auth profile/);
});

test("method rules: -I, -G, --json, HTTP versions", () => {
  assert.match(parseCurl("curl -I https://h.test").raw, /^HEAD \/ HTTP\/1\.1\n/);
  assert.match(parseCurl("curl -I -G -d a=1 https://h.test").raw, /^HEAD \/\?a=1 HTTP\/1\.1\n/);
  assert.match(refusal("curl -I -d a=1 https://h.test"), /-I/);
  assert.match(parseCurl("curl --http2 https://h.test").raw, /^GET \/ HTTP\/2\n/);
  assert.match(parseCurl("curl --http2 --http1.1 https://h.test").raw, /^GET \/ HTTP\/1\.1\n/);
  assert.match(parseCurl("curl -0 https://h.test").raw, /^GET \/ HTTP\/1\.0\n/);
  const h3 = parseCurl("curl --http3 https://h.test");
  assert.match(h3.raw, /HTTP\/1\.1/);
  assert.match(h3.warnings[0], /HTTP\/3/);
  const j = parseCurl(`curl --json '{"a":1}' --json '{"b":2}' https://h.test/api`);
  assert.equal(
    j.raw,
    lines("POST /api HTTP/1.1", "Host: h.test", "Accept: application/json", "Content-Length: 14", "Content-Type: application/json", "", '{"a":1}{"b":2}'),
  );
  assert.match(parseCurl("curl -X POST https://h.test --request-target '*'").raw, /^POST \* HTTP\/1\.1\n/);
});

test("curl removes dot segments unless --path-as-is", () => {
  assert.match(parseCurl("curl https://h.test/a/b/../c/./d?x=/../").raw, /^GET \/a\/c\/d\?x=\/\.\.\/ /);
  assert.match(parseCurl("curl https://h.test/../../etc/passwd").raw, /^GET \/etc\/passwd /);
  assert.match(parseCurl("curl https://h.test/a/..").raw, /^GET \/ /);
  assert.match(parseCurl("curl --path-as-is https://h.test/a/../b").raw, /^GET \/a\/\.\.\/b /);
});

test("-F builds a multipart body; files are refused", () => {
  const p = parseCurl(`curl -F 'a=1' -F 'b=x;type=text/plain' -F 'c="q;\\"uoted";filename=n.txt' --form-string 'd=@literal' https://h.test/up`);
  const b = "------------------------brainproxy";
  const body =
    `--${b}\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n` +
    `--${b}\r\nContent-Disposition: form-data; name="b"\r\nContent-Type: text/plain\r\n\r\nx\r\n` +
    `--${b}\r\nContent-Disposition: form-data; name="c"; filename="n.txt"\r\n\r\nq;"uoted\r\n` +
    `--${b}\r\nContent-Disposition: form-data; name="d"\r\n\r\n@literal\r\n` +
    `--${b}--\r\n`;
  assert.equal(p.raw, lines("POST /up HTTP/1.1", "Host: h.test", "Accept: */*", `Content-Length: ${body.length}`, `Content-Type: multipart/form-data; boundary=${b}`, "", body));
  assert.match(refusal("curl -F file=@a.png https://h.test"), /reads a file/);
  assert.match(refusal("curl -F 'f=<a.txt' https://h.test"), /reads a file/);
  assert.match(refusal("curl -F a=1 -d b=2 https://h.test"), /-d and -F/);
  assert.match(refusal("curl -F 'a=1;headers=X: y' https://h.test"), /headers=/);
  assert.match(refusal("curl -F $'a=1;type=text/plain\\r\\nX: y' https://h.test"), /line break/);
});

test("POSIX quoting: single, double, $'…', continuations", () => {
  const p = parseCurl(
    lines(
      `curl "https://h.test/a b" \\`,
      `  -H "X-D: a \\"b\\" \\$x \\\\ \\z" \\`,
      `  -H 'X-S: it'\\''s $HOME' \\`,
      `  -H $'X-C: tab\\there \\x41\\101\\u00e9\\'q\\''`,
    ),
  );
  assert.equal(p.raw, lines("GET /a b HTTP/1.1", "Host: h.test", "Accept: */*", 'X-D: a "b" $x \\ \\z', "X-S: it's $HOME", "X-C: tab\there AAé'q'", "", ""));
  // Clusters and attached values.
  assert.match(parseCurl("curl -sSLkXPOST -HX-A:1 -d1 https://h.test").raw, /^POST \/ HTTP\/1\.1\n[^]*X-A: 1\n/);
  assert.match(parseCurl("curl -- https://h.test/-x").raw, /^GET \/-x /);
  assert.match(parseCurl("/usr/bin/curl --url https://h.test/u").raw, /^GET \/u /);
  // Bytes that aren't UTF-8 make a binary request.
  const bin = parseCurl("curl --data-binary $'\\xff\\xfe\\n' https://h.test");
  assert.equal(bin.binary, true);
  assert.deepEqual([...textBytes(bin.raw, true).slice(-3)], [0xff, 0xfe, 0x0a]);
});

test("shell syntax that curl wouldn't see as written is refused", () => {
  assert.match(refusal('curl -H "Authorization: Bearer $TOKEN" https://h.test'), /shell variables/);
  assert.match(refusal("curl https://h.test/$(id)"), /shell variables/);
  assert.match(refusal("curl https://h.test/`id`"), /shell variables/);
  assert.match(refusal("curl https://h.test/?a=1&b=2"), /Unquoted "&"/);
  assert.match(refusal("curl https://h.test; rm -rf ~"), /Unquoted ";"/);
  assert.match(refusal("curl 'https://h.test"), /Unterminated/);
  assert.match(refusal("curl --data-binary $'a\\x00b' https://h.test"), /NUL/);
  assert.match(refusal("wget https://h.test"), /start with curl/);
  assert.match(refusal("curl"), /no URL/);
  assert.match(refusal("curl https://a.test https://b.test"), /more than one URL/);
  assert.match(refusal("curl ftp://h.test/"), /Only http and https/);
  assert.match(refusal("curl $'https://h.test\\r\\nX: y/'"), /host/);
  assert.match(refusal("curl https://h.test:99999/"), /Bad port/);
});

test("unknown options are reported, harmless ones ignored, route options warned about", () => {
  assert.match(refusal("curl --frobnicate https://h.test"), /Unknown curl option --frobnicate/);
  assert.match(refusal("curl --constructor x https://h.test"), /Unknown curl option --constructor/);
  assert.match(refusal("curl --no-toString https://h.test"), /Unknown curl option --no-toString/);
  assert.match(refusal("curl -z yesterday https://h.test"), /Unknown curl option -z/);
  assert.match(refusal("curl -d @body.json https://h.test"), /reads a file/);
  assert.match(refusal("curl -T up.bin https://h.test"), /uploads a file/);
  assert.match(refusal("curl -K cfg https://h.test"), /reads options/);
  const p = parseCurl("curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 --retry 2 -L --no-progress-meter --no-compressed -x http://127.0.0.1:8080 --resolve h.test:443:1.2.3.4 https://h.test");
  assert.equal(p.raw, "GET / HTTP/1.1\nHost: h.test\nAccept: */*\n\n");
  assert.equal(p.warnings.length, 2);
  assert.match(p.warnings.join(" "), /proxy[^]*--resolve/);
  assert.doesNotMatch(parseCurl("curl --compressed --no-compressed https://h.test").raw, /Accept-Encoding/);
});

test("Chrome's Copy as cURL (bash)", () => {
  const cmd = lines(
    "curl 'https://app.test/api/items?x=1' \\",
    "  -H 'accept: application/json' \\",
    "  -H 'content-type: application/json' \\",
    "  -H 'cookie: sid=abc; theme=dark' \\",
    "  -H 'user-agent: Mozilla/5.0' \\",
    `  --data-raw $'{"name":"it\\'s","n":1}' \\`,
    "  --compressed",
  );
  const p = parseCurl(cmd);
  const body = `{"name":"it's","n":1}`;
  assert.equal(
    p.raw,
    lines(
      "POST /api/items?x=1 HTTP/1.1",
      "Host: app.test",
      "Accept-Encoding: deflate, gzip, br, zstd",
      "accept: application/json",
      "content-type: application/json",
      "cookie: sid=abc; theme=dark",
      "user-agent: Mozilla/5.0",
      `Content-Length: ${body.length}`,
      "",
      body,
    ),
  );
  // CRLF line endings from a Windows clipboard read the same.
  assert.equal(parseCurl(cmd.replace(/\n/g, "\r\n")).raw, p.raw);
});

/** Chrome's escaping for "Copy as cURL (cmd)" (DevTools' escapeStringWin). */
function chromeWin(s: string): string {
  return (
    '^"' +
    s
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/[^a-zA-Z0-9\s_\-:=+~'/.',?;()*`&]/g, "^$&")
      .replace(/%(?=[a-zA-Z0-9_])/g, "%^")
      .replace(/\r?\n/g, "^\n\n") +
    '^"'
  );
}

test("Chrome's Copy as cURL (cmd)", () => {
  const url = 'https://app.test/s?q=%22a b%22&x=<1>|^!';
  const body = '{"path":"C:\\\\dir\\\\f","q":"say \\"hi\\"","pct":"100%x"}\nline 2 é';
  const cmd = [`curl ${chromeWin(url)}`, `-H ${chromeWin("accept: */*")}`, `-H ${chromeWin('x-q: "quoted" ^caret^ %PATH%')}`, `--data-raw ${chromeWin(body)}`].join(" ^\n  ");
  const p = parseCurl(cmd);
  const len = new TextEncoder().encode(body).length;
  assert.equal(
    p.raw,
    lines("POST /s?q=%22a b%22&x=<1>|^! HTTP/1.1", "Host: app.test", "accept: */*", 'x-q: "quoted" ^caret^ %PATH%', `Content-Length: ${len}`, "Content-Type: application/x-www-form-urlencoded", "", body),
  );
  // A one-line command by hand, with ^ escapes but no quotes.
  assert.match(parseCurl('curl.exe ^"https://h.test/a^&b^" -H "X: 1"').raw, /^GET \/a&b HTTP\/1\.1\n[^]*X: 1\n/);
});

// ---------- toCurl ----------

test("toCurl writes a request curl sends the same way", () => {
  const raw = lines("GET /a?b=1 HTTP/1.1", "Host: h.test", "User-Agent: ua", "Accept: */*", "", "");
  assert.equal(toCurl(raw, "https://h.test").command, "curl 'https://h.test/a?b=1' \\\n  -H 'User-Agent: ua' \\\n  -H 'Accept: */*'");
  const post = "POST /login HTTP/1.1\r\nHost: h.test:8443\r\nContent-Length: 7\r\n\r\nu=a&p=b";
  assert.equal(
    toCurl(post, "https://h.test:8443/").command,
    ["curl 'https://h.test:8443/login'", "-H 'User-Agent:'", "-H 'Accept:'", "-H 'Content-Type:'", "--data-raw 'u=a&p=b'"].join(" \\\n  "),
  );
  // A Host that differs from the target is kept; methods other than GET/POST get -X.
  const put = toCurl("PUT /x HTTP/1.1\nHost: other.test\nX-Empty:\n\n", "http://h.test").command;
  assert.match(put, /-X 'PUT'/);
  assert.match(put, /-H 'Host: other\.test'/);
  assert.match(put, /-H 'X-Empty;'/);
  assert.match(toCurl("HEAD / HTTP/1.1\nHost: h.test\n\n", "https://h.test").command, /--head/);
  assert.match(toCurl("GET /x HTTP/1.1\nHost: h.test\nContent-Length: 3\n\nabc", "https://h.test").command, /-X 'GET'[^]*--data-raw 'abc'/);
  assert.throws(() => toCurl("GET / HTTP/1.1\n\n", ""), /Set a target/);
  assert.throws(() => toCurl("\n\n", "https://h.test"), /request line/);
});

test("toCurl flags: HTTP/2, globbing, dot segments, request targets", () => {
  assert.match(toCurl("GET / HTTP/2\nhost: h.test\n\n", "https://h.test").command, /--http2 /);
  assert.match(toCurl("GET / HTTP/2\nhost: h.test\n\n", "http://h.test").command, /--http2-prior-knowledge/);
  assert.match(toCurl("GET / HTTP/1.0\n\n", "http://h.test").command, /--http1\.0/);
  assert.doesNotMatch(toCurl("GET / HTTP/1.1\n\n", "http://h.test").command, /--http/);
  assert.match(toCurl("GET /?a[0]=1&b={x} HTTP/1.1\n\n", "https://h.test").command, /--globoff/);
  assert.match(toCurl("GET /a/../../etc/passwd HTTP/1.1\n\n", "https://h.test").command, /--path-as-is/);
  assert.doesNotMatch(toCurl("GET /a/..b/c HTTP/1.1\n\n", "https://h.test").command, /--path-as-is/);
  assert.match(toCurl("OPTIONS * HTTP/1.1\n\n", "https://h.test").command, /^curl 'https:\/\/h\.test\/' \\\n {2}--request-target '\*' \\\n {2}-X 'OPTIONS'/);
  assert.match(toCurl("GET http://h.test/abs HTTP/1.1\n\n", "https://other.test").command, /^curl 'http:\/\/h\.test\/abs'/);
  // A fragment or a space would be dropped or encoded in a URL, so the target goes as is.
  assert.match(toCurl("GET /a b#c HTTP/1.1\n\n", "https://h.test").command, /^curl 'https:\/\/h\.test\/' \\\n {2}--request-target '\/a b#c'/);
  assert.equal(parseCurl(toCurl("GET /a b#c HTTP/1.1\n\n", "https://h.test").command).raw, "GET /a b#c HTTP/1.1\nHost: h.test\n\n");
});

test("toCurl quotes everything a target controls", () => {
  const nasty = `'; touch /tmp/pwned; echo '$(id)\`id\`"`;
  const raw = lines("POST /p HTTP/1.1", "Host: h.test", `Cookie: s=${nasty}`, `X-Bidi: a\u202Eb`, "Content-Type: text/plain", "", `@/etc/passwd ${nasty}`);
  const { command } = toCurl(raw, "https://h.test");
  // A body starting with @ goes through --data-raw, which never reads a file.
  assert.match(command, /--data-raw '@\/etc\/passwd /);
  assert.doesNotMatch(command, /--data-binary/);
  assert.match(command, /-H 'Cookie: s='\\''; touch \/tmp\/pwned; echo '\\''\$\(id\)`id`"'/);
  assert.match(command, /-H \$'X-Bidi: a\\xe2\\x80\\xaeb'/);
  assert.equal(shellQuote("it's"), `'it'\\''s'`);
  assert.equal(shellQuote("a\r\nb\t\x1b[31m\\'"), `$'a\\r\\nb\\t\\x1b[31m\\\\\\''`);
  assert.equal(shellQuote("\xff"), `$'\\xff'`);
  assert.throws(() => shellQuote("a\0b"), /NUL/);
});

test("toCurl handles binary bodies and size limits", () => {
  const bin = "POST /b HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/octet-stream\r\n\r\n\x89PNG\r\n\x1a\n\xff";
  assert.match(toCurl(bin, "https://h.test", true).command, /--data-raw \$'\\x89PNG\\r\\n\\x1a\\n\\xff'$/);
  const nul = toCurl("POST /n HTTP/1.1\nContent-Type: x\n\na\0%\\'b", "https://h.test", true).command;
  assert.match(nul, /^printf 'a\\000%%\\\\\\047b' \| curl 'https:\/\/h\.test\/n'/);
  assert.match(nul, /--data-binary @-$/);
  const big = toCurl(`POST / HTTP/1.1\nContent-Type: x\nExpect: 100-continue\n\n${"a".repeat(CURL_ARG_WARN + 1)}`, "https://h.test");
  assert.match(big.warnings[0], /128 KB/);
  assert.doesNotMatch(big.command, /-H 'Expect:'/);
  assert.match(toCurl(`POST / HTTP/1.1\nContent-Type: x\n\n${"a".repeat(2000)}`, "https://h.test").command, /-H 'Expect:'/);
  assert.throws(() => toCurl(`POST / HTTP/1.1\n\n${"a".repeat(2_000_001)}`, "https://h.test"), /too large/);
  assert.match(toCurl("POST / HTTP/1.1\nTransfer-Encoding: chunked\n\n1\r\na\r\n0\r\n\r\n", "https://h.test").warnings[0], /chunk/);
});

test("toCurl then parseCurl gives the request back", () => {
  const cases: [string, string, boolean][] = [
    [lines("GET /a?b=1 HTTP/1.1", "Host: h.test", "User-Agent: ua", "Accept: */*", "Cookie: a=b", "", ""), "https://h.test", false],
    [lines("POST /form HTTP/1.1", "Host: h.test:8080", "Content-Type: application/x-www-form-urlencoded", "X-Q: it's \"q\" $x", "", "a=1&b=@x"), "http://h.test:8080", false],
    [lines("PUT /j HTTP/2", "host: h.test", "content-type: application/json", "", '{"a":"é\\n"}\r\nmore'), "https://h.test", false],
    [lines("PATCH /bin HTTP/1.1", "Host: h.test", "Content-Type: application/octet-stream", "", "\xff\x80\x7f\x01 bytes"), "https://h.test", true],
    [lines("GET /a/../b?c[]=1 HTTP/1.1", "Host: h.test", "X-Empty: ", "", ""), "https://h.test", false],
  ];
  // Header order and Content-Length are curl's; the rest must match.
  const norm = (raw: string) => {
    const [head, ...rest] = raw.split("\n\n");
    const [line, ...hs] = head.split("\n");
    const keep = hs.filter((h) => !/^content-length:/i.test(h)).map((h) => h.replace(/:\s*/, ": ").trimEnd().toLowerCase());
    return { line, headers: keep.sort(), body: rest.join("\n\n") };
  };
  for (const [raw, target, binary] of cases) {
    const { command } = toCurl(raw, target, binary);
    const back = parseCurl(command);
    assert.equal(back.target, target, command);
    assert.equal(back.binary, binary, command);
    assert.deepEqual(norm(back.raw), norm(raw), command);
  }
});

// Runs the command in bash with curl replaced by a function that prints its arguments and stdin,
// so the test sees exactly what curl would get.
const hasBash = !spawnSync("bash", ["-c", "true"]).error;

function underBash(command: string): { args: Buffer[]; stdin: Buffer } {
  const script = `curl() { printf '%s\\0' "$#" "$@"; cat; }\n${command}\n`;
  const r = spawnSync("bash", ["-c", script], { input: "", env: { PATH: process.env.PATH ?? "", LC_ALL: "C" } });
  assert.equal(r.status, 0, r.stderr.toString());
  const out = r.stdout as Buffer;
  const fields: Buffer[] = [];
  let at = 0;
  const next = () => {
    const end = out.indexOf(0, at);
    const f = out.subarray(at, end);
    at = end + 1;
    return f;
  };
  const n = Number(next().toString());
  for (let k = 0; k < n; k++) fields.push(next());
  return { args: fields, stdin: out.subarray(at) };
}

test("a real shell passes the exact bytes to curl", { skip: !hasBash && "bash not found" }, () => {
  const body = "x'$(touch /tmp/pwned)`id`\"\\ \r\n\t\x1b\xe9\xff\x80 end";
  const header = "v'; echo $HOME `id` \"\\";
  const raw = `POST /p?a='b' HTTP/1.1\r\nHost: h.test\r\nX-N: ${header}\r\nContent-Type: x\r\n\r\n${body}`;
  const { args } = underBash(toCurl(raw, "https://h.test", true).command);
  const at = args.findIndex((a) => a.toString() === "--data-raw");
  assert.deepEqual([...args[at + 1]], [...textBytes(body, true)]);
  assert.ok(args.some((a) => a.equals(Buffer.from(`X-N: ${header}`, "latin1"))));
  assert.equal(args[0].toString(), "https://h.test/p?a='b'");

  // A NUL byte goes through printf on stdin.
  const withNul = "a\0b\x01%s\\n'\xff";
  const piped = underBash(toCurl(`POST / HTTP/1.1\nContent-Type: x\n\n${withNul}`, "https://h.test", true).command);
  assert.deepEqual([...piped.stdin], [...textBytes(withNul, true)]);
  assert.equal(piped.args[piped.args.length - 1].toString(), "@-");
});

// ---------- edge cases and refusals ----------

test("every header curl builds refuses a line break", () => {
  for (const cmd of [
    "curl -b $'a=1\\r\\nX: y' https://h.test",
    "curl --oauth2-bearer $'t\\nX: y' https://h.test",
    "curl -r $'0-1\\nX: y' https://h.test",
    "curl -e $'https://r.test/\\nX: y' https://h.test",
    "curl -H $'X: a\\nY: b' https://h.test",
    "curl --request-target $'/a\\r\\nX: y' https://h.test",
  ]) {
    assert.match(refusal(cmd), /line break/, cmd);
  }
  // A method can't carry a request line or a header.
  assert.match(refusal("curl -X 'GET / HTTP/1.1' https://h.test"), /isn't a valid method/);
  assert.match(refusal("curl -X $'GET\\r\\nX: y' https://h.test"), /isn't a valid method/);
  // -u always ends up base64, so its bytes can't break a line.
  assert.match(parseCurl("curl -u $'a:b\\r\\nX: y' https://h.test").raw, /^Authorization: Basic YTpiDQpYOiB5$/m);
});

test("the target is the host curl would connect to", () => {
  // A fragment or user info can't move the request to another host than curl's.
  assert.equal(parseCurl("curl 'https://evil.test#@h.test/'").target, "https://evil.test");
  assert.equal(parseCurl("curl 'https://evil.test?@h.test/'").target, "https://evil.test");
  assert.equal(parseCurl("curl 'https://u:p@h.test@evil.test/'").target, "https://evil.test");
  assert.equal(parseCurl("curl 'https://h.test/?x=a@b.test'").target, "https://h.test");
  assert.equal(parseCurl("curl 'https://h.test/a@b.test'").target, "https://h.test");
  // The scheme is case-insensitive; a host with a port and no scheme is http.
  assert.equal(parseCurl("curl HTTPS://h.test").target, "https://h.test");
  assert.equal(parseCurl("curl h.test:8443").target, "http://h.test:8443");
  assert.equal(parseCurl("curl https://h.test:80/").target, "https://h.test:80");
  for (const url of ["file:///etc/passwd", "gopher://h.test/", "dict://h.test/", "ldap://h.test/"]) {
    assert.match(refusal(`curl '${url}'`), /Only http and https/, url);
  }
  assert.match(refusal("curl https://h.test:0/"), /Bad port/);
  assert.match(refusal("curl 'http://::1/'"), /host/);
  assert.match(refusal("curl 'https://:443/'"), /host/);
  assert.match(refusal("curl $'https://h.test\\t.evil/'"), /host/);
});

test("more shell syntax is refused or read as the shell would", () => {
  assert.match(refusal('curl "https://h.test/${HOME}"'), /shell variables/);
  assert.match(refusal('curl "https://h.test/$1"'), /shell variables/);
  assert.match(refusal("curl https://h.test > out.txt"), /Unquoted ">"/);
  assert.match(refusal("curl https://h.test | sh"), /Unquoted "\|"/);
  assert.match(refusal("curl https://h.test && echo"), /Unquoted "&"/);
  assert.match(refusal("curl $(echo https://h.test)"), /shell variables/);
  assert.match(refusal('curl "https://h.test'), /Unterminated " quote/);
  assert.match(refusal("curl $'https://h.test"), /Unterminated \$' quote/);
  assert.match(refusal("curl $'\\U00110000' https://h.test"), /isn't a Unicode character/);
  // A $ that starts no expansion is a plain character, quoted or not.
  assert.match(parseCurl(`curl -H "X: a$" -H 'Y: $(id)' https://h.test/$`).raw, /^GET \/\$ [^]*\nX: a\$\nY: \$\(id\)\n/);
  // A comment after the command, and a #fragment in the URL, aren't sent.
  assert.equal(parseCurl("curl https://h.test/a#b # -H 'X: y'").raw, "GET /a HTTP/1.1\nHost: h.test\nAccept: */*\n\n");
  // Backslash quotes the next character outside quotes.
  assert.match(parseCurl("curl -H X:\\ a\\&b https://h.test").raw, /\nX: a&b\n/);
});

test("options are read as curl reads them, or refused", () => {
  // curl has no --name=value form, so such a word isn't silently read as --name.
  assert.match(refusal("curl --data=x https://h.test"), /Unknown curl option --data=x/);
  assert.match(refusal("curl https://h.test -H"), /--header needs a value/);
  assert.match(refusal("curl https://h.test -X"), /--request needs a value/);
  // A value attached to a route option is that option's, not the URL.
  const x = parseCurl("curl -xhttp://p.test:8 https://h.test");
  assert.equal(x.target, "https://h.test");
  assert.match(x.warnings[0], /proxy/);
  assert.match(parseCurl("curl -E cert.pem https://h.test").warnings[0], /client certificate/);
  assert.match(parseCurl("curl --unix-socket /run/docker.sock http://h.test/").warnings[0], /Unix socket/);
  // A warning is given once, however often the option repeats.
  assert.equal(parseCurl("curl -x a -x b --proxy c https://h.test").warnings.length, 1);
  for (const opt of ["--ntlm", "--negotiate", "--anyauth", "--netrc", "-n", "--netrc-file f", "--next", "-:", "--config f", "--upload-file f"]) {
    assert.notEqual(refusal(`curl ${opt} https://h.test`), "", opt);
  }
  // Repeated headers are all sent; a custom Authorization replaces -u and a bearer token.
  assert.match(parseCurl("curl -H 'X-A: 1' -H 'x-a: 2' https://h.test").raw, /\nX-A: 1\nx-a: 2\n/);
  const auth = parseCurl("curl -u a:b --oauth2-bearer t -H 'Authorization: Custom' https://h.test").raw;
  assert.equal(auth.match(/authorization/gi)?.length, 1);
  assert.match(auth, /\nAuthorization: Custom\n/);
  // -u wins over a bearer token, which wins over user info in the URL.
  assert.match(parseCurl("curl -u a:b --oauth2-bearer t https://x:y@h.test").raw, /Authorization: Basic YTpi\n/);
  assert.match(parseCurl("curl --oauth2-bearer t https://x:y@h.test").raw, /Authorization: Bearer t\n/);
  // --no-get turns -G back off.
  assert.match(parseCurl("curl -G --no-get -d a=1 https://h.test").raw, /^POST \/ /);
});

test("bodies: byte lengths, -G with --url-query, multipart details", () => {
  // Content-Length counts UTF-8 bytes, not characters.
  assert.match(parseCurl("curl -d é€ https://h.test").raw, /Content-Length: 5\n/);
  assert.match(parseCurl("curl -G -d a --url-query b=c https://h.test/?z").raw, /^GET \/\?z&a&b=c /);
  // --form-string keeps @, < and ;type= as text.
  const fs = parseCurl("curl --form-string 'a=@x;type=y' --form-string 'b=<z' https://h.test").raw;
  assert.match(fs, /name="a"\r\n\r\n@x;type=y\r\n/);
  assert.match(fs, /name="b"\r\n\r\n<z\r\n/);
  assert.match(refusal("curl --form-string novalue https://h.test"), /name=value/);
  assert.match(refusal("curl -F =x https://h.test"), /name=value/);
  assert.match(refusal("curl -G -F a=1 https://h.test"), /-F with -G/);
  assert.match(refusal("curl -F 'a=1;encoder=quoted-printable' https://h.test"), /encoder=/);
  assert.match(parseCurl("curl -F 'a=1;foo=bar' https://h.test").warnings[0], /unknown -F field: foo=bar/);
  // A value holding the boundary gets a longer one.
  const clash = parseCurl("curl -F 'a=--------------------------brainproxy' https://h.test").raw;
  const boundary = /boundary=(\S+)/.exec(clash)![1];
  assert.notEqual(boundary, "------------------------brainproxy");
  assert.equal(clash.split(`--${boundary}`).length - 1, 2);
  // A field name or file name can't break out of its Content-Disposition.
  const esc = parseCurl(`curl --form-string $'a"\\r\\nX: y=1' -F $'f=v;filename=n\\r"x.txt' https://h.test`).raw;
  assert.match(esc, /name="a%22%0D%0AX: y"\r\n/);
  assert.match(esc, /; filename="n%0D%22x\.txt"\r\n/);
  assert.doesNotMatch(esc, /\r\nX: y"/);
});

test("pasted commands that arrive with stray whitespace", () => {
  // Leading prompt-less whitespace, tabs and a trailing continuation all read the same.
  const want = "GET /a HTTP/1.1\nHost: h.test\nAccept: */*\n\n";
  assert.equal(parseCurl("  \tcurl\thttps://h.test/a \\\n").raw, want);
  assert.equal(parseCurl("curl \\\r\n  https://h.test/a").raw, want);
  assert.equal(parseCurl('curl.exe "https://h.test/a"').raw, want);
  assert.match(refusal("   "), /Paste a curl command/);
  assert.match(refusal("curlx https://h.test"), /start with curl/);
});

test("toCurl: a target, method or header can't add shell syntax", () => {
  const m = toCurl("$(id) / HTTP/1.1\nHost: h.test\n\n", "https://h.test").command;
  assert.match(m, /-X '\$\(id\)'/);
  assert.match(toCurl("GET / HTTP/1.1\n\n", "https://h'$(id).test").command, /^curl 'https:\/\/h'\\''\$\(id\)\.test\/'/);
  // Control characters in a header name or the request target go in $'…' with hex escapes.
  assert.match(toCurl("GET / HTTP/1.1\nX\x1b[2J: v\n\n", "https://h.test").command, /-H \$'X\\x1b\[2J: v'/);
  assert.match(toCurl("GET /a\x01b HTTP/1.1\n\n", "https://h.test").command, /--request-target \$'\/a\\x01b'/);
  // Placeholders (an auth macro's values) are copied as they are, never resolved.
  assert.match(toCurl("GET / HTTP/1.1\nCookie: «auth:main:var:csrf#7»\n\n", "https://h.test").command, /-H 'Cookie: «auth:main:var:csrf#7»'/);
  // Targets other than http(s)://host[:port] are refused.
  for (const t of ["ftp://h.test", "https://h.test/path", "https://h.test?x", "h.test", "https://h test"]) {
    assert.throws(() => toCurl("GET / HTTP/1.1\n\n", t), CurlError, t);
  }
  assert.match(toCurl("GET / HTTP/1.1\n\n", "  https://h.test///  ").command, /^curl 'https:\/\/h\.test\/'/);
});

test("toCurl: headers it skips, keeps and warns about", () => {
  const c = toCurl("GET / HTTP/1.1\nHost: H.TEST\nX-A: 1\n folded\nX-A: 2\nContent-Length: 99\n\n", "https://h.test");
  // Host matching the target (any case) and Content-Length are curl's to write.
  assert.doesNotMatch(c.command, /Host:|Content-Length/);
  assert.match(c.command, /-H 'X-A: 1' \\\n {2}-H 'X-A: 2'/);
  assert.match(c.warnings[0], /isn't a header: {2}folded/);
  // A Host with the default port written out differs from the URL's, so it's kept.
  assert.match(toCurl("GET / HTTP/1.1\nHost: h.test:443\n\n", "https://h.test").command, /-H 'Host: h\.test:443'/);
  // Content-Length: 0 sends an empty body; a POST without one gets -X.
  assert.match(toCurl("POST / HTTP/1.1\nContent-Length: 0\n\n", "https://h.test").command, /--data-raw ''$/);
  assert.match(toCurl("POST / HTTP/1.1\n\n", "https://h.test").command, /-X 'POST'/);
  assert.doesNotMatch(toCurl("POST / HTTP/1.1\n\n", "https://h.test").command, /--data/);
  // A HEAD with a body keeps the body and says HEAD with -X.
  assert.match(toCurl("HEAD / HTTP/1.1\nContent-Length: 1\n\nx", "https://h.test").command, /-X 'HEAD'[^]*--data-raw 'x'/);
  // The request's own Content-Type, User-Agent and Accept aren't removed.
  const own = toCurl("POST / HTTP/1.1\nUser-Agent: u\nAccept: a\nContent-Type: c\n\nx", "https://h.test").command;
  assert.doesNotMatch(own, /-H '(User-Agent|Accept|Content-Type):'/);
});

test("toCurl: size limits count bytes", () => {
  const head = "POST / HTTP/1.1\nContent-Type: x\nExpect:\n\n";
  // Up to the limit is written; one byte more is refused.
  assert.ok(toCurl(head + "a".repeat(2_000_000), "https://h.test").command.length > 2_000_000);
  assert.throws(() => toCurl(head + "a".repeat(2_000_001), "https://h.test"), CurlError);
  // Multi-byte text counts as its UTF-8 bytes.
  assert.throws(() => toCurl(head + "é".repeat(1_000_001), "https://h.test"), /2000002 bytes/);
  assert.deepEqual(toCurl(head + "a".repeat(CURL_ARG_WARN), "https://h.test").warnings, []);
  assert.equal(toCurl(head + "é".repeat(CURL_ARG_WARN / 2 + 1), "https://h.test").warnings.length, 1);
});

test("toCurl then parseCurl: more requests come back the same", () => {
  const cases: [string, string, boolean][] = [
    ["HEAD /h HTTP/1.1\nHost: h.test\n\n", "https://h.test", false],
    ["GET /old HTTP/1.0\nHost: h.test\nUser-Agent: u\n\n", "http://h.test", false],
    ["OPTIONS * HTTP/1.1\nHost: h.test\n\n", "https://h.test", false],
    ["POST /at HTTP/1.1\nHost: h.test\nContent-Type: text/plain\n\n@/etc/passwd", "https://h.test", false],
    ["GET /q?a[1]={b} HTTP/1.1\nHost: h.test\n\n", "https://h.test:8443", false],
    ["DELETE /x HTTP/1.1\nHost: h.test\nX-Bidi: a\u202Eb\nX-Q: '\"$`\\\n\n", "https://h.test", false],
    ["GET /with-body HTTP/1.1\nHost: h.test\nContent-Type: text/plain\n\nbody", "https://h.test", false],
  ];
  for (const [raw, target, binary] of cases) {
    const { command } = toCurl(raw, target, binary);
    const back = parseCurl(command);
    assert.equal(back.target, target, command);
    const [line, ...hs] = back.raw.split("\n\n")[0].split("\n");
    const [wantLine, ...wantHs] = raw.split("\n\n")[0].split("\n");
    assert.equal(line, wantLine, command);
    const norm = (h: string[]) => h.filter((x) => !/^(content-length|host):/i.test(x)).map((x) => x.toLowerCase()).sort();
    assert.deepEqual(norm(hs), norm(wantHs), command);
    assert.equal(back.raw.split("\n\n").slice(1).join("\n\n"), raw.split("\n\n").slice(1).join("\n\n"), command);
  }
});

test("a real shell passes a hostile method, target and headers exactly", { skip: !hasBash && "bash not found" }, () => {
  const method = "$(touch${IFS}/tmp/pwned)";
  const target = "https://h'`id`$(id).test:8443";
  const ctrl = "X-C: a\x1b]0;title\x07\u202Eb\x7f";
  const placeholder = "Cookie: «auth:main:var:csrf#7»; s=$HOME";
  const raw = `${method} /p?q=$(id)&r=\`id\` HTTP/1.1\nHost: h.test\n${ctrl}\n${placeholder}\n\n`;
  const { args } = underBash(toCurl(raw, target).command);
  assert.equal(args[0].toString(), `${target}/p?q=$(id)&r=\`id\``);
  const x = args.findIndex((a) => a.toString() === "-X");
  assert.equal(args[x + 1].toString(), method);
  assert.ok(args.some((a) => a.equals(Buffer.from(ctrl))));
  assert.ok(args.some((a) => a.equals(Buffer.from(placeholder))));
  // A request target the URL can't hold arrives as is.
  const rt = underBash(toCurl("GET /a b#c\x01 HTTP/1.1\n\n", "https://h.test").command).args;
  assert.equal(rt[rt.findIndex((a) => a.toString() === "--request-target") + 1].toString(), "/a b#c\x01");
});
