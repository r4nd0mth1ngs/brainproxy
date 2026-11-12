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
  // A custom header goes as curl sends it: as written, spaces kept, and "Name;" as "Name:".
  assert.equal(p.raw, lines("GET / HTTP/1.1", "host: other.test", "Referer: https://ref.test/", "Accept: text/html", "X-Empty:", "X-A:  spaced", "", ""));
  assert.equal(p.target, "https://h.test");
  // Removing Content-Type leaves the body without one.
  assert.doesNotMatch(parseCurl("curl -H 'Content-Type:' -d a https://h.test").raw, /Content-Type/);
  assert.match(refusal("curl -H 'Bad header' https://h.test"), /"Bad header" can't be imported exactly/);
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
  assert.match(h3.raw, /^GET \/ HTTP\/3\n/);
  assert.deepEqual(h3.warnings, []);
  assert.match(parseCurl("curl --http3-only https://h.test").warnings[0], /--http3-only/);
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
      `curl "https://h.test/a%20b" \\`,
      `  -H "X-D: a \\"b\\" \\$x \\\\ \\z" \\`,
      `  -H 'X-S: it'\\''s $HOME' \\`,
      `  -H $'X-C: tab\\there \\x41\\101\\u00e9\\'q\\''`,
    ),
  );
  assert.equal(p.raw, lines("GET /a%20b HTTP/1.1", "Host: h.test", "Accept: */*", 'X-D: a "b" $x \\ \\z', "X-S: it's $HOME", "X-C: tab\there AAé'q'", "", ""));
  // Clusters and attached values.
  assert.match(parseCurl("curl -sSLkXPOST -HX-A:1 -d1 https://h.test").raw, /^POST \/ HTTP\/1\.1\n[^]*X-A:1\n/);
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
  const url = "https://app.test/s?q=%22a%20b%22&x=<1>|^!";
  const body = '{"path":"C:\\\\dir\\\\f","q":"say \\"hi\\"","pct":"100%x"}\nline 2 é';
  const cmd = [`curl ${chromeWin(url)}`, `-H ${chromeWin("accept: */*")}`, `-H ${chromeWin('x-q: "quoted" ^caret^ %PATH%')}`, `--data-raw ${chromeWin(body)}`].join(" ^\n  ");
  const p = parseCurl(cmd);
  const len = new TextEncoder().encode(body).length;
  assert.equal(
    p.raw,
    lines("POST /s?q=%22a%20b%22&x=<1>|^! HTTP/1.1", "Host: app.test", "accept: */*", 'x-q: "quoted" ^caret^ %PATH%', `Content-Length: ${len}`, "Content-Type: application/x-www-form-urlencoded", "", body),
  );
  // A one-line command by hand, with ^ escapes but no quotes.
  assert.match(parseCurl('curl.exe ^"https://h.test/a^&b^" -H "X: 1"').raw, /^GET \/a&b HTTP\/1\.1\n[^]*X: 1\n/);
});

// ---------- toCurl ----------

test("toCurl writes a request curl sends the same way", () => {
  const raw = lines("GET /a?b=1 HTTP/1.1", "Host: h.test", "User-Agent: ua", "Accept: */*", "", "");
  assert.equal(toCurl(raw, "https://h.test").command, "curl 'https://h.test/a?b=1' \\\n  --http1.1 \\\n  -H 'User-Agent: ua' \\\n  -H 'Accept: */*'");
  const post = "POST /login HTTP/1.1\r\nHost: h.test:8443\r\nContent-Length: 7\r\n\r\nu=a&p=b";
  assert.equal(
    toCurl(post, "https://h.test:8443/").command,
    ["curl 'https://h.test:8443/login'", "--http1.1", "-H 'User-Agent:'", "-H 'Accept:'", "-H 'Content-Type:'", "--data-raw 'u=a&p=b'"].join(" \\\n  "),
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
  // Over https curl would negotiate HTTP/2, so an HTTP/1.x request keeps its version.
  assert.match(toCurl("GET / HTTP/1.1\n\n", "https://h.test").command, /--http1\.1/);
  assert.match(toCurl("GET / HTTP/1.0\n\n", "https://h.test").command, /--http1\.0/);
  assert.doesNotMatch(toCurl("GET / HTTP/1.0\n\n", "https://h.test").command, /--http1\.1/);
  assert.doesNotMatch(toCurl("GET / HTTP/2\n\n", "https://h.test").command, /--http1/);
  assert.match(parseCurl(toCurl("GET / HTTP/1.1\n\n", "https://h.test").command).raw, /^GET \/ HTTP\/1\.1\n/);
  assert.match(toCurl("GET /?a[0]=1&b={x} HTTP/1.1\n\n", "https://h.test").command, /--globoff/);
  assert.match(toCurl("GET /a/../../etc/passwd HTTP/1.1\n\n", "https://h.test").command, /--path-as-is/);
  assert.doesNotMatch(toCurl("GET /a/..b/c HTTP/1.1\n\n", "https://h.test").command, /--path-as-is/);
  assert.match(toCurl("OPTIONS * HTTP/1.1\n\n", "https://h.test").command, /^curl 'https:\/\/h\.test\/' \\\n {2}--request-target '\*' \\\n {2}--http1\.1 \\\n {2}-X 'OPTIONS'/);
  // An absolute URL goes to the target, as Send sends it, not to the host it names.
  assert.match(toCurl("GET http://h.test/abs HTTP/1.1\n\n", "https://other.test").command, /^curl 'https:\/\/other\.test\/' \\\n {2}--request-target 'http:\/\/h\.test\/abs'/);
  // A fragment or a space would be dropped or encoded in a URL, so the target goes as is.
  assert.match(toCurl("GET /a b#c HTTP/1.1\n\n", "https://h.test").command, /^curl 'https:\/\/h\.test\/' \\\n {2}--request-target '\/a b#c'/);
  // A request without Host is copied without one (curl adds it otherwise).
  assert.equal(parseCurl(toCurl("GET /a b#c HTTP/1.1\n\n", "https://h.test").command).raw, "GET /a b#c HTTP/1.1\n\n");
  assert.match(toCurl("GET / HTTP/1.1\n\n", "https://h.test").command, /-H 'Host:'/);
  assert.doesNotMatch(toCurl("GET / HTTP/2\n\n", "https://h.test").command, /-H 'Host:'/);
});

test("toCurl quotes everything a target controls", () => {
  const nasty = `'; touch /tmp/pwned; echo '$(id)\`id\`"`;
  const raw = lines("POST /p HTTP/1.1", "Host: h.test", `Cookie: s=${nasty}`, `X-Bidi: a\u202Eb`, "Content-Type: text/plain", "", `@/etc/passwd ${nasty}`);
  const { command } = toCurl(raw, "https://h.test");
  // A body starting with @ goes through --data-raw, which never reads a file.
  assert.match(command, /--data-raw '@\/etc\/passwd /);
  assert.doesNotMatch(command, /--data-binary/);
  assert.match(command, /-H 'Cookie: s='\\''; touch \/tmp\/pwned; echo '\\''\$\(id\)`id`"'/);
  assert.match(command, /-H 'X-Bidi: a'"\$\(printf '\\342\\200\\256'\)"'b'/);
  assert.equal(shellQuote("it's"), `'it'\\''s'`);
  // \ and ' stand outside the quotes; control bytes and bytes that aren't UTF-8 go through printf.
  assert.equal(shellQuote("a\r\nb\t\x1b[31m\\'"), `'a'"$(printf '\\015')"'\nb'"$(printf '\\011\\033')"'[31m'\\\\\\'`);
  assert.equal(shellQuote("\xff"), `"$(printf '\\377')"`);
  assert.equal(shellQuote(""), "''");
  assert.throws(() => shellQuote("a\0b"), /NUL/);
});

test("toCurl handles binary bodies and size limits", () => {
  const bin = "POST /b HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/octet-stream\r\n\r\n\x89PNG\r\n\x1a\n\xff";
  assert.match(toCurl(bin, "https://h.test", true).command, /^printf '\\211PNG\\015\\n\\032\\n\\377' \| curl [^]*--data-binary @-$/);
  const nul = toCurl("POST /n HTTP/1.1\nContent-Type: x\n\na\0%\\'b", "https://h.test", true).command;
  assert.match(nul, /^printf 'a\\000%%\\134\\047b' \| curl 'https:\/\/h\.test\/n'/);
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

// Runs the command in a shell with curl replaced by a function that prints its arguments and
// stdin, so the test sees exactly what curl would get. dash is /bin/sh on Debian and Ubuntu.
const shells = ["sh", "dash", "bash", "zsh"].filter((sh) => !spawnSync(sh, ["-c", "true"]).error);
const hasBash = shells.includes("bash");

function underShell(shell: string, command: string): { args: Buffer[]; stdin: Buffer } {
  const script = `curl() { printf '%s\\0' "$#" "$@"; cat; }\n${command}\n`;
  const r = spawnSync(shell, ["-c", script], { input: "", env: { PATH: process.env.PATH ?? "", LC_ALL: "C" } });
  assert.equal(r.status, 0, `${shell}: ${r.stderr.toString()}`);
  assert.equal(r.stderr.toString(), "", shell);
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

const underBash = (command: string) => underShell("bash", command);

/** What printf prints for a format with only the escapes toCurl writes. */
function printfOut(fmt: string): Buffer {
  const out: number[] = [];
  for (let i = 0; i < fmt.length; ) {
    const c = fmt[i++];
    const oct = c === "\\" ? /^[0-7]{1,3}/.exec(fmt.slice(i, i + 3)) : null;
    if (oct) out.push(parseInt(oct[0], 8)), (i += oct[0].length);
    else if (c === "\\" && fmt[i] === "n") out.push(10), i++;
    else if (c === "%" && fmt[i] === "%") out.push(37), i++;
    else if (c === "\\" || c === "%") throw new Error(`printf would read ${c}${fmt[i]} differently`);
    else out.push(...Buffer.from(c));
  }
  return Buffer.from(out);
}

/**
 * Words as fish reads them: inside '…' a \\ or \' is an escape, which POSIX shells don't have,
 * and "…" may only hold toCurl's $(printf '…').
 */
function fishWords(command: string): Buffer[] {
  const words: Buffer[] = [];
  let cur: number[] = [];
  let inWord = false;
  let i = 0;
  const single = () => {
    let out = "";
    for (;;) {
      const c = command[i++];
      if (c === undefined) throw new Error("unterminated '");
      if (c === "'") return out;
      if (c === "\\" && (command[i] === "\\" || command[i] === "'")) out += command[i++];
      else out += c;
    }
  };
  const add = (b: Buffer) => {
    cur.push(...b);
    inWord = true;
  };
  while (i < command.length) {
    const c = command[i];
    if (c === " " || c === "\n") {
      if (inWord) words.push(Buffer.from(cur));
      cur = [];
      inWord = false;
      i++;
    } else if (c === "\\") {
      if (command[i + 1] !== "\n") add(Buffer.from(command[i + 1]));
      i += 2;
    } else if (c === "'") {
      i++;
      add(Buffer.from(single()));
    } else if (c === '"') {
      assert.ok(command.startsWith(`"$(printf '`, i), `fish would read "…" differently at ${i}`);
      i += 11;
      add(printfOut(single()));
      assert.ok(command.startsWith(`)"`, i));
      i += 2;
    } else if (/[\w@:.\-|]/.test(c)) {
      add(Buffer.from(c));
      i++;
    } else throw new Error(`unquoted ${JSON.stringify(c)} at ${i}`);
  }
  if (inWord) words.push(Buffer.from(cur));
  return words;
}

/** What curl gets when fish runs the command: its arguments and stdin. */
function underFish(command: string): { args: Buffer[]; stdin: Buffer } {
  const w = fishWords(command);
  if (w[0].toString() !== "printf") return { args: w.slice(1), stdin: Buffer.alloc(0) };
  assert.equal(w[2].toString(), "|");
  return { args: w.slice(4), stdin: printfOut(w[1].toString("latin1")) };
}

/** Requests whose values try to end the quoting in one shell or another. */
const hostile: [string, string, boolean][] = [
  // dash has no $'…': a control byte and a quote once broke out there.
  ["GET / HTTP/1.1\nHost: x.test\nX-A: \x01'; echo INJECTED #\n\n", "http://x.test", false],
  // fish reads \' and \\ inside '…' as escapes.
  ["POST / HTTP/1.1\nHost: x.test\nContent-Type: x\n\nv=\\'|echo INJECTED #", "https://x.test", false],
  ["GET / HTTP/1.1\nHost: x.test\nX-B: ends in \\\nX-C: \\\\'\\'; echo INJECTED #\n\n", "https://x.test", false],
  ["POST /p?a='b' HTTP/1.1\r\nHost: h.test\r\nX-N: v'; echo $HOME `id` \"\\\r\nContent-Type: x\r\n\r\nx'$(touch /tmp/pwned)`id`\"\\ \r\n\t\x1b\xe9\xff\x80 end", "https://h.test", true],
  ["PUT /\x1b[2J\\' HTTP/1.1\nX-Bidi: a‮b\\'\nX\x01: \\\n\n", "https://h.test", false],
  // A body that starts with - must not be read as printf's option.
  ["POST / HTTP/1.1\nContent-Type: x\n\n-v\0x", "https://h.test", true],
  ["POST / HTTP/1.1\nContent-Type: x\n\n--\x01\\'%s%%\n", "https://h.test", false],
];

test("a real shell passes the exact bytes to curl", { skip: !hasBash && "bash not found" }, () => {
  const body = "x'$(touch /tmp/pwned)`id`\"\\ \r\n\t\x1b\xe9\xff\x80 end";
  const header = "v'; echo $HOME `id` \"\\";
  const raw = `POST /p?a='b' HTTP/1.1\r\nHost: h.test\r\nX-N: ${header}\r\nContent-Type: x\r\n\r\n${body}`;
  const { args, stdin } = underBash(toCurl(raw, "https://h.test", true).command);
  // Control and non-UTF-8 bytes in a body go through printf on stdin.
  assert.deepEqual([...stdin], [...textBytes(body, true)]);
  assert.equal(args[args.length - 1].toString(), "@-");
  assert.ok(args.some((a) => a.equals(Buffer.from(`X-N: ${header}`, "latin1"))));
  assert.equal(args[0].toString(), "https://h.test/p?a='b'");

  // A NUL byte goes through printf on stdin.
  const withNul = "a\0b\x01%s\\n'\xff";
  const piped = underBash(toCurl(`POST / HTTP/1.1\nContent-Type: x\n\n${withNul}`, "https://h.test", true).command);
  assert.deepEqual([...piped.stdin], [...textBytes(withNul, true)]);
  assert.equal(piped.args[piped.args.length - 1].toString(), "@-");
});

test("sh, dash, bash, zsh and fish read the same command the same way", { skip: !hasBash && "bash not found" }, () => {
  for (const [raw, target, binary] of hostile) {
    const { command } = toCurl(raw, target, binary);
    const want = underBash(command);
    // Every header arrives whole as one argument, and the body as it was.
    const [head, ...rest] = raw.split(/\r?\n\r?\n/);
    for (const line of head.split(/\r?\n/).slice(1)) {
      if (/^(host|content-length):/i.test(line)) continue;
      // A name that isn't a token is left out with a note.
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+:/.test(line)) {
        assert.ok(!want.args.some((a) => a.includes(textBytes(line.split(":")[0], binary))), `${JSON.stringify(line)}: ${command}`);
        continue;
      }
      const header = textBytes(line.replace(/^([^:]*):\s*/, "$1: "), binary);
      assert.ok(want.args.some((a) => a.equals(header)), `${JSON.stringify(line)}: ${command}`);
    }
    const body = textBytes(rest.join("\n\n"), binary);
    assert.ok(want.stdin.equals(body) || want.args.some((a) => a.equals(body)), command);
    for (const shell of shells) {
      const got = underShell(shell, command);
      assert.deepEqual(got.args, want.args, `${shell}: ${command}`);
      assert.deepEqual(got.stdin, want.stdin, `${shell}: ${command}`);
    }
    const fish = underFish(command);
    assert.deepEqual(fish.args, want.args, `fish: ${command}`);
    assert.deepEqual(fish.stdin, want.stdin, `fish: ${command}`);
    // And brainproxy reads its own command back to the same bytes.
    const back = parseCurl(command);
    assert.equal(back.target, target, command);
  }
  // The injection attempt arrives whole, as the header's value.
  const dashed = underShell(shells[0], toCurl(hostile[0][0], hostile[0][1]).command);
  assert.ok(dashed.args.some((a) => a.equals(Buffer.from("X-A: \x01'; echo INJECTED #"))));
  assert.deepEqual([...underShell(shells[0], toCurl(hostile[5][0], hostile[5][1], true).command).stdin], [0x2d, 0x76, 0, 0x78]);
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
  // A bearer token wins over -u (curl asks for Bearer auth alone), and -u over user info in the URL.
  assert.match(parseCurl("curl -u a:b --oauth2-bearer t https://x:y@h.test").raw, /Authorization: Bearer t\n/);
  assert.match(parseCurl("curl --oauth2-bearer t -u a:b https://h.test").raw, /Authorization: Bearer t\n/);
  assert.match(parseCurl("curl --oauth2-bearer t https://x:y@h.test").raw, /Authorization: Bearer t\n/);
  assert.match(parseCurl("curl -u a:b https://x:y@h.test").raw, /Authorization: Basic YTpi\n/);
  assert.match(parseCurl("curl -u a:b --basic https://h.test").raw, /Authorization: Basic YTpi\n/);
  // With --basic as well curl sends neither until the server's challenge.
  assert.match(refusal("curl -u a:b --basic --oauth2-bearer t https://h.test"), /challenge/);
  assert.match(parseCurl("curl -u a:b --basic --oauth2-bearer t --no-basic https://h.test").raw, /Authorization: Bearer t\n/);
  // A custom Authorization header is sent at once instead, and -H 'Authorization:' sends none.
  assert.match(parseCurl("curl --basic --oauth2-bearer t -H 'Authorization: Custom' https://h.test").raw, /\nAuthorization: Custom\n/);
  assert.doesNotMatch(parseCurl("curl -u a:b --basic --oauth2-bearer t -H 'Authorization:' https://h.test").raw, /authorization/i);
  assert.match(parseCurl("curl --basic --oauth2-bearer t -H 'Authorization;' https://h.test").raw, /\nAuthorization:\n/);
  // A custom Authorization in any of the three forms stands in for -u and a bearer token.
  for (const flags of ["--basic --oauth2-bearer t", "--oauth2-bearer t", "-u a:b"]) {
    assert.match(parseCurl(`curl ${flags} -H 'Authorization:x' http://h.test/`).raw, /\nAuthorization:x\n/, flags);
    assert.doesNotMatch(parseCurl(`curl ${flags} -H 'Authorization:  ' http://h.test/`).raw, /authorization/i, flags);
    const empty = parseCurl(`curl ${flags} -H 'authorization;' http://h.test/`).raw;
    assert.equal(empty.match(/authorization/gi)?.length, 1, flags);
    assert.match(empty, /\nauthorization:\n/, flags);
  }
  // A header named otherwise doesn't, so a bearer token stays where curl sends it.
  assert.match(refusal("curl --basic --oauth2-bearer t -H 'X-Authorization: y' http://h.test/"), /challenge/);
  assert.match(parseCurl("curl --oauth2-bearer t -H 'X-Authorization: y' http://h.test/").raw, /\nAuthorization: Bearer t\n[^]*\nX-Authorization: y\n/);
  // Forms curl reads by rules of its own are refused, whatever the name, so none can leave a
  // second copy of curl's header beside a custom one, or drop it without a replacement.
  for (const h of ["Authorization;foo: bar", "Authorization : x", "authorization :", "Authorization ;", " Authorization: z", "Authorization;foo;", "Host;other.test:80", "Host : other.test", "User-Agent;x: y", "User-Agent : y", "Content-Type ;", "X-A;b;", "X-A; ", "X-A", ";", "X A: b", "X\"A: b", "X(A): b", "Accept\t: x"]) {
    for (const flags of ["", "--oauth2-bearer t", "--basic --oauth2-bearer t", "-A ua -d a"]) {
      assert.match(refusal(`curl ${flags} -H $'${h}' http://h.test/`), /can't be imported exactly/, `${flags} ${h}`);
    }
  }
  // The three forms for curl's other headers, each written as curl sends it.
  const forms = (h: string) => parseCurl(`curl -A ua -d a -H '${h}' http://h.test/`).raw.split("\n\n")[0].split("\n").slice(1);
  assert.deepEqual(forms("Host:other.test:80"), ["Host:other.test:80", "User-Agent: ua", "Accept: */*", "Content-Length: 1", "Content-Type: application/x-www-form-urlencoded"]);
  assert.deepEqual(forms("host:"), ["User-Agent: ua", "Accept: */*", "Content-Length: 1", "Content-Type: application/x-www-form-urlencoded"]);
  assert.deepEqual(forms("Host;"), ["Host:", "User-Agent: ua", "Accept: */*", "Content-Length: 1", "Content-Type: application/x-www-form-urlencoded"]);
  assert.deepEqual(forms("user-agent: u2"), ["Host: h.test", "Accept: */*", "user-agent: u2", "Content-Length: 1", "Content-Type: application/x-www-form-urlencoded"]);
  assert.deepEqual(forms("User-Agent:"), ["Host: h.test", "Accept: */*", "Content-Length: 1", "Content-Type: application/x-www-form-urlencoded"]);
  assert.deepEqual(forms("User-Agent;"), ["Host: h.test", "Accept: */*", "User-Agent:", "Content-Length: 1", "Content-Type: application/x-www-form-urlencoded"]);
  assert.deepEqual(forms("Accept;"), ["Host: h.test", "User-Agent: ua", "Accept:", "Content-Length: 1", "Content-Type: application/x-www-form-urlencoded"]);
  assert.deepEqual(forms("Content-Type:\ttext/plain"), ["Host: h.test", "User-Agent: ua", "Accept: */*", "Content-Type:\ttext/plain", "Content-Length: 1"]);
  assert.deepEqual(forms("Content-Type;"), ["Host: h.test", "User-Agent: ua", "Accept: */*", "Content-Type:", "Content-Length: 1"]);
  assert.deepEqual(forms("Content-Length:"), ["Host: h.test", "User-Agent: ua", "Accept: */*", "Content-Type: application/x-www-form-urlencoded"]);
  // A custom Host goes in Host's place.
  assert.match(parseCurl("curl -H 'X: 1' -H 'Host: a.test' http://h.test/").raw, /^GET \/ HTTP\/1\.1\nHost: a\.test\nAccept: \*\/\*\nX: 1\n\n$/);
  // More than one Host, in any form, is refused: which ones curl sends depends on their order.
  for (const hs of ["-H 'Host: a.test' -H 'Host: b.test'", "-H 'Host:' -H 'Host: a.test' -H 'Host: b.test'", "-H 'Host: a.test' -H 'Host:'", "-H 'host;' -H 'Host: a.test'"])
    assert.match(refusal(`curl ${hs} http://h.test/`), /Host more than once/);
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
  // A header name that isn't a token is left out; control characters in the request target
  // go through printf.
  const ctl = toCurl("GET / HTTP/1.1\nX\x1b[2J: v\nA;b: c\nX Y: z\n\n", "https://h.test");
  assert.doesNotMatch(ctl.command, /-H '(X|A;)/);
  assert.equal(ctl.warnings.length, 3);
  assert.match(toCurl("GET /a\x01b HTTP/1.1\n\n", "https://h.test").command, /--request-target '\/a'"\$\(printf '\\001'\)"'b'/);
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
  for (const shell of shells) {
    const { args } = underShell(shell, toCurl(raw, target).command);
    assert.equal(args[0].toString(), `${target}/p?q=$(id)&r=\`id\``, shell);
    const x = args.findIndex((a) => a.toString() === "-X");
    assert.equal(args[x + 1].toString(), method, shell);
    assert.ok(args.some((a) => a.equals(Buffer.from(ctrl))), shell);
    assert.ok(args.some((a) => a.equals(Buffer.from(placeholder))), shell);
  }
  const { args } = underBash(toCurl(raw, target).command);
  const x = args.findIndex((a) => a.toString() === "-X");
  assert.equal(args[x + 1].toString(), method);
  assert.ok(args.some((a) => a.equals(Buffer.from(ctrl))));
  assert.ok(args.some((a) => a.equals(Buffer.from(placeholder))));
  // A request target the URL can't hold arrives as is.
  const rt = underBash(toCurl("GET /a b#c\x01 HTTP/1.1\n\n", "https://h.test").command).args;
  assert.equal(rt[rt.findIndex((a) => a.toString() === "--request-target") + 1].toString(), "/a b#c\x01");
});

test("header values keep a trailing 0xA0 byte (à, Р)", () => {
  const c = toCurl("GET / HTTP/1.1\nHost: h.test\nX-Name: voilà\nX-Cyr: Р\n\n", "https://h.test");
  assert.match(c.command, /-H 'X-Name: voilà'/);
  assert.match(c.command, /-H 'X-Cyr: Р'/);
  assert.match(parseCurl("curl -H 'X-Name: voilà' https://h.test").raw, /\nX-Name: voilà\n/);
  // A value of only that byte isn't read as "remove this header".
  assert.match(parseCurl("curl -H $'X-Nb: \\xa0' https://h.test").raw, /\nX-Nb: \xa0\n/);
  assert.match(parseCurl("curl -H 'X-E:   ' https://h.test").raw, /^GET \/ HTTP\/1\.1\nHost: h\.test\nAccept: \*\/\*\n\n$/);
});

test("HTTP/2 pseudo-headers are left out with a note", () => {
  const p = parseCurl("curl -H ':authority: h.test' -H ':path;' https://h.test");
  assert.equal(p.raw, "GET / HTTP/1.1\nHost: h.test\nAccept: */*\n\n");
  assert.deepEqual(p.warnings, ["Left out the HTTP/2 pseudo-header :authority.", "Left out the HTTP/2 pseudo-header :path;."]);
});

test("a header named @… isn't copied, as curl would read it as a file", () => {
  const c = toCurl("GET / HTTP/1.1\nHost: h.test\n@hdr: x\n@x;\nX-A: 1\n\n", "https://h.test");
  assert.doesNotMatch(c.command, /@/);
  assert.match(c.command, /-H 'X-A: 1'/);
  assert.equal(c.warnings.length, 2);
  assert.match(c.warnings[0], /isn't a valid token/);
});

test("Windows cmd is told apart from a POSIX command holding ^", () => {
  const json = parseCurl(`curl 'https://x.test/api' -H 'content-type: application/json' --data-raw '{"a":"^"}'`);
  assert.match(json.raw, /\n\n\{"a":"\^"\}$/);
  assert.equal(json.target, "https://x.test");
  assert.match(parseCurl(`curl -H 'X: ^"a"' https://h.test`).raw, /\nX: \^"a"\n/);
  // A line ending in ^ inside a quoted multi-line body.
  assert.match(parseCurl("curl https://h.test \\\n  --data-raw 'a ^\nb'").raw, /\n\na \^\nb$/);
  // cmd by hand: every line ends in ^, no single quotes.
  assert.match(parseCurl('curl "https://h.test/a" ^\n  -H "X: 1"').raw, /^GET \/a HTTP\/1\.1\n[^]*X: 1\n/);
});

test("--proto-default, --http2 over http, and URLs curl refuses", () => {
  assert.equal(parseCurl("curl --proto-default https h.test/a").target, "https://h.test");
  assert.equal(parseCurl("curl --proto-default https http://h.test/a").target, "http://h.test");
  assert.match(refusal("curl --proto-default ftp h.test"), /Only http and https/);
  const h2c = parseCurl("curl --http2 http://h.test/");
  assert.match(h2c.raw, /^GET \/ HTTP\/1\.1\n/);
  assert.match(h2c.warnings[0], /upgrade/);
  assert.match(parseCurl("curl --http2-prior-knowledge http://h.test/").raw, /^GET \/ HTTP\/2\n/);
  assert.match(parseCurl("curl --http2 https://h.test/").raw, /^GET \/ HTTP\/2\n/);
  assert.match(refusal("curl 'https://h.test/a b'"), /space or control/);
  assert.match(refusal("curl $'https://h.test/a\\x01'"), /space or control/);
  assert.match(refusal("curl $'https://h.test/a\\x7f'"), /space or control/);
  // --request-target is sent as is, as curl does.
  assert.match(parseCurl("curl --request-target '/a b' https://h.test").raw, /^GET \/a b HTTP\/1\.1\n/);
});

test("the printf forms toCurl writes are read back", () => {
  const p = parseCurl("printf '\\055v\\000x\\134\\047%%\\n' | curl 'https://h.test/' \\\n  --data-binary @-");
  assert.match(p.raw, /\n\n-v\0x\\'%\n$/);
  assert.match(parseCurl(`curl -H 'X: a'"$(printf '\\033\\342\\200\\256')"'b' https://h.test`).raw, /\nX: a\x1b\u202eb\n/);
  assert.equal(parseCurl(`curl -H "X: $(printf '\\377')" https://h.test`).binary, true);
  // Nothing else that looks like it is.
  assert.match(refusal("curl -H \"X: $(printf '%s')\" https://h.test"), /Only %%/);
  assert.match(refusal("curl -H \"X: $(printf '\\x41')\" https://h.test"), /printf escape/);
  assert.match(refusal("curl -H \"X: $(printf 'a' b)\" https://h.test"), /shell variables/);
  assert.match(refusal("curl -H \"X: $(id)\" https://h.test"), /shell variables/);
  assert.match(refusal("curl -H \"X: $(printf '\\000')\" https://h.test"), /NUL/);
  assert.match(refusal("printf 'a' | curl -d @- https://h.test"), /reads a file/);
  assert.match(refusal("printf 'a' | curl https://h.test"), /--data-binary @-/);
  assert.match(refusal("echo a | curl https://h.test"), /Unquoted "\|"/);
});

test("toCurl keeps an absolute-form request on the target, as Send does", () => {
  const c = toCurl("GET http://other.test/p HTTP/1.1\nHost: other.test\n\n", "https://x.test").command;
  assert.match(c, /^curl 'https:\/\/x\.test\/' \\\n {2}--request-target 'http:\/\/other\.test\/p'/);
  assert.match(c, /-H 'Host: other\.test'/);
  assert.doesNotMatch(c, /^curl 'http:\/\/other/);
  const back = parseCurl(c);
  assert.equal(back.target, "https://x.test");
  assert.match(back.raw, /^GET http:\/\/other\.test\/p HTTP\/1\.1\nHost: other\.test\n/);
  assert.match(toCurl("GET http://other.test/p HTTP/2\n\n", "https://x.test").command, /--http2 /);
});

test("URL globbing is read as curl reads it, unless -g", () => {
  // A set or a range with several values is several requests.
  for (const url of ["http://h.test/{a,b}", "http://h.test/[1-3]", "http://h.test/[a-c]", "http://h.test/x[1-9:2]", "http://{a,b}.h.test/"]) {
    assert.match(refusal(`curl '${url}'`), /several requests/, url);
    assert.match(parseCurl(`curl -g '${url}'`).raw, /^GET /, url);
  }
  assert.match(parseCurl("curl --globoff 'http://h.test/{a,b}[1-3]'").raw, /^GET \/\{a,b\}\[1-3\] /);
  assert.match(parseCurl("curl -sg 'http://h.test/{a,b}'").raw, /^GET \/\{a,b\} /);
  // One value is written out; \ quotes a bracket; an IPv6 address and [] stay as they are.
  assert.match(parseCurl("curl 'http://h.test/{a}'").raw, /^GET \/a /);
  assert.match(parseCurl("curl 'http://h.test/{a\\,b}'").raw, /^GET \/a,b /);
  assert.match(parseCurl("curl 'http://h.test/[1-1]x[05-5][c-c]'").raw, /^GET \/1x05c /);
  // Big numbers keep every digit; curl refuses one above 2^63 - 2.
  assert.match(parseCurl("curl 'http://h.test/[9007199254740993-9007199254740993]'").raw, /^GET \/9007199254740993 /);
  assert.match(parseCurl("curl 'http://h.test/[09223372036854775806-9223372036854775806]'").raw, /^GET \/09223372036854775806 /);
  assert.match(refusal("curl 'http://h.test/[9007199254740992-9007199254740993]'"), /several requests/);
  assert.match(refusal("curl 'http://h.test/[9223372036854775807-9223372036854775807]'"), /-g/);
  assert.match(refusal("curl 'http://h.test/[1-1:9223372036854775807]'"), /-g/);
  assert.match(parseCurl("curl 'http://h.test/\\{a\\}\\[1-3\\]'").raw, /^GET \/\{a\}\[1-3\] /);
  assert.match(parseCurl("curl 'http://h.test/?a[]=1'").raw, /^GET \/\?a\[\]=1 /);
  assert.equal(parseCurl("curl 'http://[::1]:8080/x'").target, "http://[::1]:8080");
  assert.equal(parseCurl("curl 'http://[fe80::1%25eth0]/'").target, "http://[fe80::1%25eth0]");
  // What curl can't read as a glob is refused too ("bad range", "unmatched brace").
  for (const url of ["http://h.test/{}", "http://h.test/{a", "http://h.test/a}", "http://h.test/]", "http://h.test/[x]", "http://h.test/[3-1]", "http://h.test/[1-2:5]", "http://h.test/{a,[1-2]}"]) {
    assert.match(refusal(`curl '${url}'`), /-g/, url);
  }
  // The URL a copied command holds goes back as it was.
  assert.match(parseCurl(toCurl("GET /?a[0]=1&b={x,y} HTTP/1.1\n\n", "https://h.test").command).raw, /^GET \/\?a\[0\]=1&b=\{x,y\} /);
});

test("long options take a value after =", () => {
  assert.match(parseCurl("curl --data=x https://h.test").raw, /^POST [^]*\n\nx$/);
  // An empty value is a value, and only the first = splits.
  assert.match(parseCurl("curl --data= https://h.test").raw, /Content-Length: 0\n/);
  assert.match(parseCurl("curl --header=X:1 --header=Y:a=b https://h.test").raw, /\nX:1\nY:a=b\n/);
  assert.match(refusal("curl --header==X:1 https://h.test"), /"=X:1" can't be imported exactly/);
  assert.match(parseCurl("curl --url=https://h.test/u --request=PUT").raw, /^PUT \/u /);
  assert.equal(parseCurl("curl --output=/dev/null --max-time=5 --proxy=http://p.test https://h.test").warnings.length, 1);
  // A switch ignores a value, as curl does.
  assert.match(parseCurl("curl --get=x -d a https://h.test").raw, /^GET \/\?a /);
  assert.match(refusal("curl --bogus=1 https://h.test"), /Unknown curl option --bogus/);
  assert.match(refusal("curl --upload-file=f https://h.test"), /-T uploads a file/);
  // A short option keeps = in its value.
  assert.match(parseCurl("curl -d=x https://h.test").raw, /\n\n=x$/);
});

test("-G and --url-query add & only after a query with something in it", () => {
  assert.match(parseCurl("curl -G -d x 'http://h.test/a?'").raw, /^GET \/a\?x /);
  assert.match(parseCurl("curl -G -d x 'http://h.test/a?b=1&'").raw, /^GET \/a\?b=1&x /);
  assert.match(parseCurl("curl -G -d x 'http://h.test/a?b=1'").raw, /^GET \/a\?b=1&x /);
  assert.match(parseCurl("curl --url-query y 'http://h.test/a?'").raw, /^GET \/a\?y /);
  assert.match(parseCurl("curl --url-query y --url-query z 'http://h.test/a?#f'").raw, /^GET \/a\?y&z /);
  // A query ending in a literal ? still gets a &, and the parts are joined before they are added.
  assert.match(parseCurl("curl -G -d x 'http://h.test/a?b?'").raw, /^GET \/a\?b\?&x /);
  assert.match(parseCurl("curl --url-query '+a&' --url-query b http://h.test/").raw, /^GET \/\?a&&b /);
  assert.match(parseCurl("curl -G -d 'x&' -d y http://h.test/").raw, /^GET \/\?x&&y /);
});

// ---------- headers as recorded, and what the copy can't carry over ----------

test("toCurl copies header lines as written, spaces included", () => {
  // A space before the colon (a Transfer-Encoding obfuscation probe) and spaces in a value are
  // sent by curl as written, so they are copied that way.
  const te = toCurl("POST / HTTP/1.1\nHost: h.test\nTransfer-Encoding : chunked\nX-Foo: bar  \nX-B:  v\nY:z\nContent-Type: x\n\n1\r\na\r\n0\r\n\r\n", "http://h.test");
  assert.match(te.command, /-H 'Transfer-Encoding : chunked'/);
  assert.match(te.command, /-H 'X-Foo: bar {2}'/);
  assert.match(te.command, /-H 'X-B: {2}v'/);
  assert.match(te.command, /-H 'Y:z'/);
  // curl doesn't read that header as chunked, so it would add a Content-Length the request
  // didn't have: removed.
  assert.match(te.command, /-H 'Content-Length:'/);
  assert.doesNotMatch(te.warnings.join("\n"), /chunks the body/);
  assert.match(te.warnings.join("\n"), /space before the colon: Transfer-Encoding\.[^]*pasting the command back into brainproxy is refused/);
  assert.match(refusal(te.command), /can't be imported exactly/);
  // The shell hands curl those exact lines.
  if (hasBash) {
    const { args } = underBash(te.command);
    for (const h of ["Transfer-Encoding : chunked", "X-Foo: bar  ", "X-B:  v", "Y:z", "Content-Length:"]) assert.ok(args.some((a) => a.toString() === h), h);
  }
  // A spaced name is none of curl's own headers: curl's Host, User-Agent and Accept are still
  // removed, and a spaced Content-Length goes as written in place of curl's.
  const own = toCurl("POST / HTTP/1.1\nHost : h.test\nUser-Agent : u\nContent-Length : 5\nContent-Type: x\n\nabc", "http://h.test").command;
  for (const h of ["Host : h.test", "User-Agent : u", "Content-Length : 5", "Host:", "User-Agent:", "Accept:", "Content-Length:"]) assert.ok(own.includes(`-H '${h}'`), `${h}: ${own}`);
  // An empty value can only go as "Name:", which curl writes for "Name;".
  const empty = toCurl("GET / HTTP/1.1\nHost: h.test\nX-E: \nX-F:\nX-G :\n\n", "http://h.test");
  assert.match(empty.command, /-H 'X-E;' \\\n {2}-H 'X-F;' \\\n {2}-H 'X-G;'/);
  assert.match(empty.warnings.join("\n"), /X-E, X-G lose the spaces around the colon/);
  // Plain headers bring no notes.
  assert.deepEqual(toCurl("GET / HTTP/1.1\nHost: h.test\nX-A: 1\n\n", "https://h.test").warnings, []);
});

test("toCurl warns when curl would send another Host, Content-Length or HTTP/2 header", () => {
  // curl sends only the first of several Host headers; all are written, in order.
  const hosts = toCurl("GET / HTTP/1.1\nHost: h.test\nHost: evil.test\n\n", "https://h.test");
  assert.match(hosts.command, /-H 'Host: h\.test' \\\n {2}-H 'Host: evil\.test'/);
  assert.match(hosts.warnings.join("\n"), /2 Host headers and curl sends only the first \(h\.test\)/);
  // A Content-Length that isn't the body's is replaced by curl's.
  const wrong = toCurl("POST / HTTP/1.1\nContent-Type: x\nContent-Length: 10\n\nabc", "https://h.test");
  assert.doesNotMatch(wrong.command, /Content-Length/);
  assert.match(wrong.warnings.join("\n"), /curl sends Content-Length: 3, the body's length, in place of the request's 10\./);
  assert.match(toCurl("POST / HTTP/1.1\nContent-Type: x\nContent-Length: 3\nContent-Length: 3\n\nabc", "https://h.test").warnings.join("\n"), /in place of the request's 3, 3/);
  assert.deepEqual(toCurl("POST / HTTP/1.1\nContent-Type: x\nContent-Length: 3\n\nabc", "https://h.test").warnings, []);
  // With chunked, curl sends no Content-Length at all.
  assert.match(toCurl("POST / HTTP/1.1\nTransfer-Encoding: chunked\nContent-Length: 4\n\nabcd", "https://h.test").warnings.join("\n"), /chunked twice, and it sends no Content-Length/);
  // chunked counts as one of the codings, not as part of a word.
  assert.match(toCurl("POST / HTTP/1.1\nTransfer-Encoding: gzip, CHUNKED \nContent-Type: x\n\nabcd", "https://h.test").warnings.join("\n"), /chunked twice/);
  for (const v of ["xchunked", "chunked;x"]) {
    const c = toCurl(`POST / HTTP/1.1\nTransfer-Encoding: ${v}\nContent-Type: x\n\nabcd`, "https://h.test");
    assert.doesNotMatch(c.warnings.join("\n"), /chunked twice/, v);
    assert.match(c.command, /-H 'Content-Length:'/, v);
  }
  // Another Transfer-Encoding: curl adds no Content-Length the request didn't have.
  const gzip = toCurl("POST / HTTP/1.1\nTransfer-Encoding: gzip\nContent-Type: x\n\nabc", "https://h.test");
  assert.match(gzip.command, /-H 'Content-Length:'/);
  assert.doesNotMatch(toCurl("POST / HTTP/1.1\nContent-Type: x\n\nabc", "https://h.test").command, /Content-Length/);
  // HTTP/2 has no connection-specific headers: curl leaves them out.
  const h2 = toCurl("POST / HTTP/2\nhost: h.test\nconnection: keep-alive\nupgrade: h2c\ntransfer-encoding: chunked\nte: trailers\ncontent-type: x\n\na", "https://h.test");
  assert.match(h2.warnings.join("\n"), /Over HTTP\/2 curl leaves out connection, upgrade, transfer-encoding,/);
  assert.doesNotMatch(h2.warnings.join("\n"), /chunks the body|leaves out[^\n]*\bte\b|TE as/);
  assert.match(toCurl("GET / HTTP/2\nte: gzip\n\n", "https://h.test").warnings.join("\n"), /leaves out te,/);
  // TE naming trailers among other codings is cut to "trailers", not left out.
  const te = toCurl("GET / HTTP/2\nte: gzip, Trailers\n\n", "https://h.test").warnings.join("\n");
  assert.match(te, /sends TE as "trailers" alone/);
  assert.doesNotMatch(te, /leaves out/);
  assert.deepEqual(toCurl("GET / HTTP/1.1\nConnection: close\nTE: gzip\n\n", "https://h.test").warnings, []);
});

test("toCurl notes the credentials a command carries", () => {
  const c = toCurl("GET / HTTP/1.1\nHost: h.test\nAuthorization: Bearer t\nCookie: s=1\ncookie: t=2\nX-Api-Key: k\n\n", "https://h.test");
  assert.equal(c.warnings.length, 1);
  assert.match(c.warnings[0], /credentials as they are \(Authorization, Cookie, X-Api-Key\)/);
});

test("pasted headers are kept as curl sends them", () => {
  assert.match(parseCurl("curl -H 'X: a  ' -H 'Y:\tb' https://h.test").raw, /\nX: a {2}\nY:\tb\n/);
  // Only spaces and tabs make a header empty, so it is removed; \v and \f are sent.
  assert.doesNotMatch(parseCurl("curl -H $'X: \\t ' https://h.test").raw, /\nX:/);
  assert.match(parseCurl("curl -H $'X: \\v\\f' https://h.test").raw, /\nX: \v\f\n/);
  assert.match(toCurl("GET / HTTP/1.1\nHost: h.test\nX: \v\f\n\n", "https://h.test").command, /-H 'X: '"\$\(printf '\\013\\014'\)"/);
  // toCurl's lines come back the same.
  assert.match(parseCurl(toCurl("GET / HTTP/1.1\nHost: h.test\nX-Foo: bar  \nY:z\n\n", "https://h.test").command).raw, /\nX-Foo: bar {2}\nY:z\n/);
});

test("$(printf …) is read only inside double quotes", () => {
  // Unquoted, a shell would split what printf prints into words.
  assert.match(refusal("curl -H X:$(printf '\\101') https://h.test"), /shell variables or command substitution/);
  assert.match(refusal("curl -d $(printf 'a b') https://h.test"), /shell variables or command substitution/);
  assert.match(parseCurl(`curl -H "X:$(printf '\\101')" https://h.test`).raw, /\nX:A\n/);
});

test("format characters go through printf", () => {
  // Soft hyphen, word joiner and invisible operators, zero-width joiner, a tag character, and
  // the bidi and zero-width ones as before.
  for (const ch of ["\u00ad", "\u2060", "\u2062", "\u2064", "\u200d", "\u{e0041}", "\u202e", "\u200b", "\ufeff", "\u2028", "\u2029"]) {
    const q = shellQuote(Buffer.from(`a${ch}b`).toString("latin1"));
    assert.match(q, /^'a'"\$\(printf '(\\\d{3})+'\)"'b'$/, JSON.stringify(ch));
    assert.match(parseCurl(`curl -H X:${q} https://h.test`).raw, new RegExp(`\\nX:a${ch}b\\n`, "u"));
  }
  // Ordinary text, accents and emoji stay in the quotes.
  assert.equal(shellQuote(Buffer.from("é ü € 😀").toString("latin1")), "'é ü € 😀'");
});
