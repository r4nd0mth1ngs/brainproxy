import { test } from "node:test";
import assert from "node:assert/strict";
import { accessConfirm, changeKinds, definesMutation, graphqlDocuments, highlightArgs, isLogout, isMutationRequest, isRefused, scanArgs, scanBlocker, scanConfirm, unsafeMethods, withHighlight, type HistoryPick } from "./trafficActions.ts";

const get: HistoryPick = { id: 7, method: "GET", url: "https://shop.test/search?q=x" };
const post: HistoryPick = { id: 9, method: "post", url: "https://shop.test/contact" };
const off = { nuclei: false };

test("methods that can change data", () => {
  assert.deepEqual(unsafeMethods([get, { ...get, method: "HEAD" }, { ...get, method: "options" }]), []);
  assert.deepEqual(unsafeMethods([get, post, { ...post, id: 10 }, { ...post, method: "DELETE" }]), ["POST", "DELETE"]);
});

test("a scan from Traffic uses the Scans view's defaults", () => {
  assert.deepEqual(scanArgs([get], { nuclei: false }), ["scan", "active", "--history-id=7", "--strength=medium", "--background"]);
  assert.deepEqual(scanArgs([get, post], { nuclei: true }), [
    "scan",
    "active",
    "--history-id=7",
    "--history-id=9",
    "--strength=medium",
    "--checks=nuclei,brainproxy",
    "--check-include-tags=eol",
    "--check-severity=high",
    "--background",
  ]);
  assert.throws(() => scanArgs([], { nuclei: false }), /No request/);
});

test("the question before a scan names the request and warns about a POST", () => {
  const g = scanConfirm([get], off);
  assert.equal(g.title, "Scan this request?");
  assert.match(g.message, /real attack traffic/);
  assert.match(g.message, /GET https:\/\/shop\.test\/search\?q=x is sent again/);
  assert.doesNotMatch(g.message, /side effects/);
  assert.match(g.message, /engagement scope/);

  const p = scanConfirm([post], off);
  assert.match(p.message, /POST https:\/\/shop\.test\/contact is sent again/);
  assert.match(p.message, /replayed even though it is a POST, and that can change data or trigger side effects/);

  const many = scanConfirm([get, post], off);
  assert.equal(many.title, "Scan 2 requests?");
  assert.match(many.message, /2 requests are sent again/);
  assert.match(many.message, /POST requests among them are replayed too/);
});

test("highlight on and off", () => {
  assert.deepEqual(highlightArgs(3, true), ["history", "tag", "3", "--add", "highlight"]);
  assert.deepEqual(highlightArgs(3, false), ["history", "tag", "3", "--remove", "highlight"]);
  assert.deepEqual(withHighlight(["api"], true), ["api", "highlight"]);
  assert.deepEqual(withHighlight(["api", "highlight"], true), ["api", "highlight"]);
  assert.deepEqual(withHighlight(["highlight", "api"], false), ["api"]);
});

test("methods: none picked, case folded, first-seen order, anything but GET/HEAD/OPTIONS", () => {
  assert.deepEqual(unsafeMethods([]), []);
  assert.deepEqual(unsafeMethods([{ ...get, method: "get" }, { ...get, method: "Head" }]), []);
  assert.deepEqual(unsafeMethods([{ ...post, method: "patch" }, post, { ...post, method: "POST" }, { ...post, method: "PATCH" }]), ["PATCH", "POST"]);
  assert.deepEqual(unsafeMethods(["PUT", "TRACE", "CONNECT", "PROPFIND"].map((method) => ({ ...get, method }))), ["PUT", "TRACE", "CONNECT", "PROPFIND"]);
});

test("a scan from Traffic attacks only the picked entries, by id", () => {
  // The URL never reaches the argv: a recorded URL can't add a flag, another target or a wider selection.
  const hostile: HistoryPick = { id: 12, method: "GET", url: "--where=1=1 https://elsewhere.test/ --crawl" };
  for (const nuclei of [false, true]) {
    const args = scanArgs([hostile, get], { nuclei });
    assert.ok(!args.some((a) => a.includes("elsewhere") || a.includes("shop.test")), args.join(" "));
    assert.ok(!args.some((a) => /^--(where|crawl|include-methods|api|from)\b/.test(a)), args.join(" "));
    assert.ok(!args.some((a) => !a.startsWith("--") && a !== "scan" && a !== "active"), "no positional URL");
    assert.deepEqual(args.filter((a) => a.startsWith("--history-id=")), ["--history-id=12", "--history-id=7"]);
    // In the background, so the call returns the job id at once.
    assert.equal(args.at(-1), "--background");
  }
});

test("a scan of many picks keeps them all, in order", () => {
  const picks = Array.from({ length: 50 }, (_, i) => ({ ...get, id: 1000 - i }));
  const ids = scanArgs(picks, { nuclei: false }).filter((a) => a.startsWith("--history-id="));
  assert.deepEqual(ids, picks.map((p) => `--history-id=${p.id}`));
});

test("the question before a scan: plain wording, labels, and every method that changes data", () => {
  const q = scanConfirm([get], off);
  assert.equal(q.ok, "Start scan");
  assert.equal(q.cancel, "Cancel");
  assert.match(q.message, /^This sends real attack traffic to the site: /);

  // A lower-case method is named in upper case.
  const put = scanConfirm([{ ...post, method: "put" }], off);
  assert.match(put.message, /PUT https:\/\/shop\.test\/contact is sent again/);
  assert.match(put.message, /even though it is a PUT, and that can change data/);
  assert.match(put.message, /one contact form can send a lot of emails/);

  // Several safe requests: no replay warning, plural wording.
  const reads = scanConfirm([get, { ...get, id: 8, method: "HEAD" }], off);
  assert.equal(reads.title, "Scan 2 requests?");
  assert.match(reads.message, /2 requests are sent again/);
  assert.doesNotMatch(reads.message, /side effects|replayed/);

  // Each method once, whatever its case.
  const mixed = scanConfirm([get, post, { ...post, id: 10, method: "POST" }, { ...post, id: 11, method: "delete" }], off);
  assert.equal(mixed.title, "Scan 4 requests?");
  assert.match(mixed.message, / POST, DELETE requests among them are replayed too, and that can change data/);
});

test("the question shows the URL as recorded, as text", () => {
  const url = "https://shop.test/a?x=<script>alert(1)</script>&y=\"'";
  const q = scanConfirm([{ ...get, url }], off);
  assert.ok(q.message.includes(`GET ${url} is sent again`));
  assert.ok(!q.title.includes(url), "the title stays short");
});

test("highlight: only that tag changes, and the row's tags are not changed in place", () => {
  assert.deepEqual(highlightArgs(123456789, true), ["history", "tag", "123456789", "--add", "highlight"]);
  const tags = ["api", "highlight", "highlighted", "Highlight"];
  const off = withHighlight(tags, false);
  assert.deepEqual(off, ["api", "highlighted", "Highlight"]);
  assert.deepEqual(tags, ["api", "highlight", "highlighted", "Highlight"]);
  const on = withHighlight(off, true);
  assert.deepEqual(on, ["api", "highlighted", "Highlight", "highlight"]);
  assert.notEqual(on, off);
  assert.deepEqual(withHighlight([], true), ["highlight"]);
  assert.deepEqual(withHighlight([], false), []);
  assert.deepEqual(withHighlight(["api"], false), ["api"]);
});

test("a request with no response, or one the proxy refused, can't be scanned", () => {
  assert.equal(scanBlocker({ status: 200 }), null);
  assert.equal(scanBlocker({ status: 500, error: null }), null);
  // select_targets skips an entry with no response even when named by id, so the job would fail.
  assert.equal(scanBlocker({ status: null }), "No response recorded to scan");
  assert.equal(scanBlocker({ status: null, error: "connection refused" }), "No response recorded to scan");
  assert.match(scanBlocker({ status: null, error: "out of scope: other.test" }) ?? "", /Out of scope/);
  assert.ok(isRefused({ status: null, error: "out of scope: other.test" }));
  assert.ok(!isRefused({ status: null, error: "timed out" }));
});

test("an access-control run of a POST from Traffic asks first, naming who sends it", () => {
  assert.equal(accessConfirm([get], ["alice"], true), null);
  const one = accessConfirm([post], ["alice", "bob"], true);
  assert.equal(one?.title, "Replay this POST?");
  assert.match(one?.message ?? "", /^This POST is sent again twice as its owner, then as alice and bob and with no session\. That can change data/);
  assert.match(one?.message ?? "", /engagement scope/);
  const many = accessConfirm([get, post, { ...post, id: 11, method: "DELETE" }], ["alice", "bob", "carol"], false);
  assert.equal(many?.title, "Replay requests that can change data?");
  assert.match(many?.message ?? "", /^The POST, DELETE requests are sent again twice as their owners, then as alice, bob and carol\. /);
  assert.match(accessConfirm([post], [], true)?.message ?? "", /^This POST is sent again twice as its owner, then with no session\./);
  // runArgs refuses a run with nobody to send as; the question still reads.
  assert.match(accessConfirm([post], [], false)?.message ?? "", /^This POST is sent again twice as its owner\. /);
});

const logout: HistoryPick = { id: 21, method: "GET", url: "https://shop.test/account/logout?next=/" };

test("logout-like paths, as authz run's default --exclude", () => {
  for (const path of ["/logout", "/account/log-out", "/LogOff", "/auth/sign_out", "/signoff?x=1", "/api/logout.json", "/user/signout/"]) {
    assert.ok(isLogout({ ...get, url: `https://shop.test${path}` }), path);
  }
  for (const path of ["/logouts", "/catalog", "/blog/outdoor", "/signal/offer", "/?next=/logout", "/logoutnow"]) {
    assert.ok(!isLogout({ ...get, url: `https://shop.test${path}` }), path);
  }
  // The path as recorded, not normalised: authz run matches /logout/../account too.
  assert.ok(isLogout({ ...get, url: "https://shop.test/logout/../account" }));
  assert.ok(isLogout({ ...get, url: "https://shop.test:8443/a/%2e%2e/sign-off" }));
  assert.ok(isLogout({ ...get, url: "https://shop.test/#/logout" }));
  // The host is not the path.
  assert.ok(!isLogout({ ...get, url: "https://logout.shop.test/" }));
  assert.ok(!isLogout({ ...get, url: "http://sign-out:8080/home" }));
  // Not a URL: the path is what comes before the query.
  assert.ok(isLogout({ ...get, url: "/sign-out?x" }));
  assert.ok(!isLogout({ ...get, url: "/x?sign-out" }));
});

test("an access-control run of a logout from Traffic asks first, even for a GET", () => {
  const q = accessConfirm([logout], ["alice"], true);
  assert.equal(q?.title, "Replay this logout?");
  assert.match(q?.message ?? "", /^This request is sent again twice as its owner, then as alice and with no session\. It looks like a logout: /);
  assert.match(q?.message ?? "", /end the owner's session and each identity's/);
  assert.doesNotMatch(q?.message ?? "", /change data/);

  const both = accessConfirm([{ ...logout, method: "POST" }], ["alice"], false);
  assert.equal(both?.title, "Replay this POST?");
  assert.match(both?.message ?? "", /That can change data.* It looks like a logout/);

  const many = accessConfirm([get, logout, { ...logout, id: 22, url: "https://shop.test/signoff" }], ["bob"], true);
  assert.equal(many?.title, "Replay requests that look like logouts?");
  assert.match(many?.message ?? "", /^These 3 requests are sent again twice as their owners, then as bob and with no session\. #21 and #22 look like a logout: sending them /);
  assert.match(accessConfirm([get, logout], ["bob"], true)?.message ?? "", / #21 looks like a logout: sending it /);
});

test("a scan of a logout says it can end its session", () => {
  assert.match(scanConfirm([logout], off).message, / It looks like a logout: sending it again can end the session it was recorded with\./);
  assert.doesNotMatch(scanConfirm([get], off).message, /logout/);
  assert.match(scanConfirm([get, logout], off).message, / One of them looks like a logout: sending it again /);
  assert.match(scanConfirm([logout, { ...logout, id: 22 }], off).message, / 2 of them look like a logout: sending them again can end the session they were /);
});

test("a scan with the Nuclei templates says they reach other paths of the site", () => {
  assert.doesNotMatch(scanConfirm([get], off).message, /Nuclei/);
  assert.match(scanConfirm([get], { nuclei: true }).message, / The downloaded Nuclei templates also run against its site, on paths of their own\. Every request/);
  assert.match(scanConfirm([get, post], { nuclei: true }).message, /against their sites/);
});

const graphqlPost = (body: string, type = "application/json") => `POST /graphql HTTP/1.1\r\nHost: shop.test\r\nContent-Type: ${type}\r\n\r\n${body}`;

test("GraphQL documents of a recorded request, as the scanner reads them", () => {
  assert.deepEqual(graphqlDocuments(graphqlPost('{"query":"mutation { a }","variables":{}}')), ["mutation { a }"]);
  assert.deepEqual(graphqlDocuments(graphqlPost('[{"query":"query A { a }"},{"x":1},{"query":"mutation B { b }"}]')), ["query A { a }", "mutation B { b }"]);
  assert.deepEqual(graphqlDocuments(graphqlPost("mutation { a }", "application/graphql; charset=utf-8")), ["mutation { a }"]);
  assert.deepEqual(graphqlDocuments("GET /graphql?query=mutation%20%7B%20a%20%7D&x=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n"), ["mutation { a }"]);
  assert.deepEqual(graphqlDocuments("GET /graphql?query=mutation+%7B+a+%7D HTTP/1.1\r\nHost: shop.test\r\n\r\n"), ["mutation { a }"]);
  // Like the scanner's parser: no CRLF blank line, no request.
  assert.deepEqual(graphqlDocuments("POST /graphql HTTP/1.1\nContent-Type: application/json\n\n{\"query\":\"mutation { a }\"}"), []);
  assert.deepEqual(graphqlDocuments(graphqlPost("name=mutation", "application/x-www-form-urlencoded")), []);
  // Any Content-Type header saying so, as the scanner checks each one.
  assert.deepEqual(graphqlDocuments(graphqlPost("mutation { a }", "text/plain\r\nContent-Type: application/graphql")), ["mutation { a }"]);
  assert.deepEqual(graphqlDocuments(graphqlPost('{"query":5}')), []);
  assert.deepEqual(graphqlDocuments(graphqlPost("")), []);
});

test("a GraphQL document defines a mutation when a top-level definition starts with the word", () => {
  assert.ok(definesMutation("mutation { a }"));
  assert.ok(definesMutation("  # comment\n mutation Login($u: String) { login(u: $u) { ok } }"));
  assert.ok(definesMutation("query A { a } mutation B { b }"));
  assert.ok(definesMutation("fragment F on T { x } mutation { a }"));
  assert.ok(!definesMutation("query { mutation }"));
  assert.ok(!definesMutation("{ a(x: \"mutation\") }"));
  assert.ok(!definesMutation('{ a(x: """\nmutation { b }\n""") }'));
  assert.ok(!definesMutation("# mutation { a }\nquery { a }"));
  assert.ok(!definesMutation("mutations { a }"));
  assert.ok(!definesMutation("query mutation { a }"));
  assert.ok(!definesMutation(""));
  assert.ok(definesMutation("mutation"));
});

test("a GraphQL mutation is named as one in both questions, whatever its method", () => {
  assert.ok(isMutationRequest(graphqlPost('{"query":"mutation { delete(id: 1) }"}')));
  assert.ok(!isMutationRequest(graphqlPost('{"query":"{ me { id } }"}')));
  // Cut short, the JSON no longer parses: the word is enough to ask.
  const cut = graphqlPost('{"query":"mutation Upload($f: String) { upload(f: $f) }","variables":{"f":"AAAA');
  assert.ok(!isMutationRequest(cut));
  assert.ok(isMutationRequest(cut, true));
  assert.ok(!isMutationRequest(graphqlPost('{"query":"query { mutations }","variables":{"f":"AA'), true));
  const m: HistoryPick = { ...post, method: "POST", url: "https://shop.test/graphql", mutation: true };
  assert.deepEqual(changeKinds([m]), ["GraphQL mutation"]);
  assert.deepEqual(changeKinds([{ ...m, mutation: false }]), ["POST"]);
  // One sent as GET still changes data.
  assert.deepEqual(changeKinds([get, { ...m, method: "GET" }, { ...post, method: "DELETE" }]), ["GraphQL mutation", "DELETE"]);
  assert.match(scanConfirm([m], off).message, /replayed even though it is a GraphQL mutation, and that can change data/);
  assert.match(scanConfirm([m, { ...post, id: 30 }], off).message, / GraphQL mutation, POST requests among them are replayed too/);
  const q = accessConfirm([{ ...m, method: "GET" }], ["alice"], true);
  assert.equal(q?.title, "Replay this GraphQL mutation?");
  assert.match(q?.message ?? "", /^This GraphQL mutation is sent again twice as its owner/);
});
