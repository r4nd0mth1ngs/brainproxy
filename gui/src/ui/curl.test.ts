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
