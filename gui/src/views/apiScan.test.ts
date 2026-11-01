import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_AUTH,
  EMPTY_TARGET,
  KEY_ENV,
  apiResultNotes,
  authProblems,
  authProfile,
  authSummary,
  baseUrlProblem,
  baselineText,
  checkArgs,
  checkMeaning,
  credentialOnRequest,
  credentialText,
  defaultProfileName,
  defaultSelection,
  defaultTarget,
  dropOptIn,
  excludedText,
  filterOperations,
  hostLabel,
  likelyInScope,
  hostScopeText,
  includeMethods,
  isApiJob,
  keyAddArgs,
  keyDefaults,
  keyEnv,
  keyKindDefaults,
  keyProblems,
  listWords,
  looksSecret,
  methodSummary,
  needsOptIn,
  newSignerForm,
  newSignerProblems,
  operationCount,
  operationOrigins,
  optInMethods,
  pickCheckOperation,
  previewArgs,
  previewTitle,
  profileProblems,
  scanArgs,
  scrubSecret,
  selectShown,
  selectionProblems,
  sendsPost,
  sendsStateChanging,
  serverProblems,
  serverSummary,
  signRuleArgs,
  signerCoverage,
  signerFormOrigins,
  signerOnRequest,
  sourceKind,
  sourceProblem,
  targetArgs,
  tickable,
  urlPatternMatches,
  variableInputs,
  type ApiCredential,
  type ApiOperation,
  type ApiPreview,
  type AuthState,
  type CheckFacts,
} from "./apiScan.ts";
import type { SessionRule } from "./sessionRules.ts";

const op = (index: number, method: string, patch: Partial<ApiOperation> = {}): ApiOperation => {
  const m = method.toUpperCase();
  const changing = ["PUT", "PATCH", "DELETE"].includes(m);
  return {
    index,
    name: `op${index}`,
    method: m,
    url: `https://api.test/v1/${index}`,
    headers: [],
    body: { encoding: "utf8", content: "", length: 0, truncated: false },
    state_changing: changing,
    in_scope: true,
    scope_confirmed: true,
    included: !changing,
    excluded_reason: changing ? "method" : null,
    ...patch,
  };
};

// Shaped as `import api --dry-run` prints it (see crates/cli/tests/api_scan.rs).
const OPS: ApiOperation[] = [
  op(0, "POST"),
  op(1, "DELETE"),
  op(2, "GET"),
  op(3, "PUT"),
  op(4, "GET", { in_scope: false, included: false, excluded_reason: "scope", url: "https://other.test/x" }),
  op(5, "OPTIONS"),
  op(6, "PATCH"),
];

const SHA = "a".repeat(64);

test("the preview and its target's arguments", () => {
  assert.deepEqual(previewArgs(" /a/spec.yaml ", EMPTY_TARGET), ["import", "api", "--dry-run", "--limit=1000", "--", "/a/spec.yaml"]);
  assert.deepEqual(targetArgs({ server: 1, baseUrl: "", vars: {} }), ["--server=1"]);
  assert.deepEqual(targetArgs({ server: 0, baseUrl: " http://a.test/v1 ", vars: {} }), ["--base-url=http://a.test/v1"], "a base URL overrides the server");
  assert.deepEqual(targetArgs({ server: null, baseUrl: "", vars: { tenant: "-acme", empty: "" } }), ["--var=tenant=-acme"], "a value may start with a dash; an empty one isn't sent");
  // A file named like a flag stays a file.
  assert.equal(previewArgs("-x.yaml", EMPTY_TARGET).at(-2), "--");
});

test("the same names count as secret here and in the CLI", () => {
  // crates/core/src/apiimport/mod.rs: looks_secret and its test's lists.
  for (const n of ["Authorization", "Cookie", "X-Auth-User", "x_auth", "api_key", "X-API-KEY", "apikey", "my_token", "PASSWD", "Proxy-Authorization", "set_cookie", " secret "]) assert.ok(looksSecret(n), n);
  for (const n of ["Accept", "limit", "author", "id", "X-Trace", "monkey"]) assert.ok(!looksSecret(n), n);
});

test("a secret never goes in any argument", () => {
  const secret = "FAKE-TOP-SECRET";
  const t = { server: null, baseUrl: "", vars: { apiKey: secret, password: secret, x_auth: secret, tenant: "a" } };
  assert.deepEqual(targetArgs(t), ["--var=tenant=a"]);
  assert.ok(!previewArgs("/s", t).join(" ").includes(secret));
  assert.ok(!checkArgs("/s", SHA, t, 0, "p").join(" ").includes(secret));
  const plan = { source: "/s", sha256: SHA, target: t, operations: OPS, selected: [2], profile: "p", depth: "quick" as const, speedArgs: [] };
  assert.ok(!scanArgs(plan).join(" ").includes(secret));

  for (const a of [{ ...EMPTY_AUTH, keyName: "X-Api-Key", profileName: "k" }, { ...EMPTY_AUTH, keyKind: "bearer" as const, profileName: "k" }, { ...EMPTY_AUTH, place: "query" as const, keyName: "api_key", profileName: "k" }]) {
    const args = keyAddArgs(a, ["https://api.test"]);
    assert.ok(!args.join(" ").includes(secret));
    assert.ok(args.join(" ").includes(KEY_ENV));
  }
  assert.deepEqual(keyEnv("api_key", ` ${secret} `), { [KEY_ENV]: secret });
  assert.deepEqual(keyEnv("bearer", secret), { [KEY_ENV]: `Bearer ${secret}` });
  assert.deepEqual(keyEnv("bearer", `bearer ${secret}`), { [KEY_ENV]: `bearer ${secret}` });
  assert.equal(scrubSecret(`bad key ${secret}!`, ` ${secret} `), "bad key ********!");
  assert.equal(scrubSecret("msg", ""), "msg");
  // Nothing in a problem repeats the value: they only learn whether there is one.
  const problems = keyProblems({ ...EMPTY_AUTH, profileName: "k", keyName: "X-A" }, [], true, []);
  assert.deepEqual(problems, []);
});

test("URLs on the command line hold no credentials", () => {
  assert.equal(sourceKind("HTTP://a.test/s"), "url");
  assert.equal(sourceKind("/a/s.json"), "file");
  assert.equal(sourceProblem("https://a.test/openapi.json"), "");
  assert.match(sourceProblem(""), /Choose a file/);
  assert.match(sourceProblem("https://u:p@a.test/s"), /username and password/);
  assert.match(sourceProblem("https://a.test/s?api_key=x"), /key or token/);
  assert.match(sourceProblem("-"), /full path/, "a bare dash would read stdin");
  assert.match(sourceProblem("spec.yaml"), /full path/);
  assert.equal(sourceProblem("/a/spec.yaml"), "");
  assert.equal(sourceProblem("C:\\a\\spec.yaml"), "");
  assert.equal(baseUrlProblem(""), "");
  assert.equal(baseUrlProblem("http://a.test/v1"), "");
  assert.match(baseUrlProblem("ftp://a.test"), /http/);
  assert.match(baseUrlProblem("http://a.test/?token=x"), /key or token/);
});

test("the server step", () => {
  const preview = (patch: Partial<ApiPreview>) => ({ base_url_required: false, requests: OPS, hosts: [], ...patch });
  assert.deepEqual(defaultTarget({ servers: [{ index: 0, url: "https://a.test" }] }), { server: 0, baseUrl: "", vars: {} });
  assert.deepEqual(defaultTarget({ servers: [] }), { server: null, baseUrl: "", vars: {} });
  assert.deepEqual(serverProblems(preview({}), EMPTY_TARGET), []);
  assert.match(serverProblems(preview({ base_url_required: true }), EMPTY_TARGET)[0], /base URL/);
  assert.deepEqual(serverProblems(preview({ base_url_required: true }), { ...EMPTY_TARGET, baseUrl: "https://a.test" }), []);
  assert.match(serverProblems(preview({}), { ...EMPTY_TARGET, baseUrl: "nope" })[0], /http/);
  const out = serverProblems(preview({ requests: [op(0, "GET", { in_scope: false })] }), EMPTY_TARGET, ["a.test", "b.test"]);
  assert.match(out[0], /approved scope \(a\.test, b\.test\)/);
  assert.match(out[0], /can't be widened/);
  assert.equal(serverSummary({ servers: [{ index: 1, url: "https://a.test" }] }, { ...EMPTY_TARGET, server: 1 }), "https://a.test");
  assert.equal(serverSummary({ servers: [] }, EMPTY_TARGET), "the addresses in the definition");
  assert.equal(hostLabel({ host: "a.test", port: 443, in_scope: true, scope_confirmed: true }), "a.test");
  assert.equal(hostLabel({ host: "a.test", port: 8443, in_scope: true, scope_confirmed: true }), "a.test:8443");
  assert.equal(hostScopeText({ host: "a.test", port: 443, in_scope: true, scope_confirmed: true }), "in scope");
  assert.match(hostScopeText({ host: "a.test", port: 443, in_scope: true, scope_confirmed: false }), /resolves/);
  assert.match(hostScopeText({ host: "a.test", port: 443, in_scope: false, scope_confirmed: false }), /skipped/);
  assert.deepEqual(operationOrigins([{ url: "https://a.test/x" }, { url: "https://a.test:443/y" }, { url: "http://b.test:81/" }, { url: "bad" }]), ["https://a.test", "http://b.test:81"]);
  assert.equal(previewTitle({ title: "Pets", version: "1.0", format: "openapi3" }), "Pets 1.0");
  assert.equal(previewTitle({ title: null, version: null, format: "postman" }), "Postman collection");
});

test("variables to ask about", () => {
  // As the CLI gives them: a secret one is not in unresolved_variables.
  const p = {
    variables: [
      { name: "base", value: "http://a.test", source: "collection", secret: false, used: true },
      { name: "spare", value: "x", source: "collection", secret: false, used: false },
      { name: "apiKey", value: null, source: "collection", secret: true, used: true },
      { name: "viaAuth", value: null, source: "document", secret: true, used: true },
    ],
    unresolved_variables: ["tenant"],
  };
  const inputs = variableInputs(p);
  assert.deepEqual(inputs.map((v) => v.name), ["base", "apiKey", "viaAuth", "tenant"]);
  assert.deepEqual(inputs.filter((v) => v.secret).map((v) => v.name), ["apiKey", "viaAuth"]);
  assert.deepEqual(inputs.filter((v) => v.unresolved).map((v) => v.name), ["tenant"]);
  assert.equal(inputs[1].value, "");
  // One typed earlier stays on the form though the new preview has resolved it.
  assert.ok(variableInputs(p, { region: "eu" }).some((v) => v.name === "region" && v.unresolved));
});

test("default selection: in scope, and a method sent by default", () => {
  assert.deepEqual(defaultSelection(OPS), [0, 2, 5]);
  assert.ok(needsOptIn({ method: "put" }) && needsOptIn({ method: "TRACE" }) && !needsOptIn({ method: "post" }));
  assert.ok(!tickable(OPS[4], true), "out of scope stays out");
  assert.ok(!tickable(OPS[1], false) && tickable(OPS[1], true));
  assert.deepEqual(filterOperations(OPS, "  DELETE ").map((o) => o.index), [1]);
  assert.deepEqual(filterOperations(OPS, "other.test").map((o) => o.index), [4]);
  assert.equal(filterOperations(OPS, "").length, OPS.length);
});

test("opting in, and select all", () => {
  assert.deepEqual(selectShown([], OPS, false, true), [0, 2, 5], "all doesn't tick what needs opting in");
  assert.deepEqual(selectShown([], OPS, true, true), [0, 1, 2, 3, 5, 6], "nor what's out of scope");
  assert.deepEqual(selectShown([0, 2, 5], [OPS[2]], false, false), [0, 5], "only those shown");
  assert.deepEqual(dropOptIn([0, 1, 3, 5, 6], OPS), [0, 5]);
  assert.deepEqual(optInMethods(OPS), ["PUT", "PATCH", "DELETE"]);
  assert.deepEqual(optInMethods([op(9, "TRACE"), op(10, "DELETE", { in_scope: false })]), ["TRACE"], "only among those in scope");
  assert.deepEqual(includeMethods(OPS, [0, 2]), []);
  assert.deepEqual(includeMethods(OPS, [6, 1, 0]), ["PATCH", "DELETE"]);
  assert.equal(listWords(["PUT", "PATCH", "DELETE"]), "PUT, PATCH and DELETE");
  assert.equal(listWords(["PUT"]), "PUT");
  assert.equal(methodSummary(OPS, [0, 2, 5, 3]), "1 GET, 1 OPTIONS, 1 POST, 1 PUT");
  assert.equal(methodSummary(OPS, []), "none");
  assert.ok(sendsPost(OPS, [0]) && !sendsPost(OPS, [2]));
  assert.ok(sendsStateChanging(OPS, [3]) && !sendsStateChanging(OPS, [0, 2]));
  assert.equal(operationCount(1), "1 operation will be sent");
  assert.equal(operationCount(2), "2 operations will be sent");
  assert.deepEqual(selectionProblems([1]), []);
  assert.equal(selectionProblems([]).length, 1);
  assert.match(excludedText(OPS[4], false), /Outside the project's scope/);
  assert.match(excludedText(OPS[4], true), /Outside the project's scope/);
  assert.match(excludedText(OPS[1], false), /DELETE isn't sent unless/);
  assert.equal(excludedText(OPS[1], true), "");
  assert.equal(excludedText(OPS[2], false), "");
});

test("the check operation is never state-changing or a POST", () => {
  assert.equal(pickCheckOperation(OPS, [0])?.index, 2, "a GET in scope, ticked or not");
  const none = [op(0, "POST"), op(1, "DELETE"), op(2, "PUT"), op(3, "PATCH"), op(4, "GET", { in_scope: false })];
  assert.equal(pickCheckOperation(none, [0, 1, 2, 3, 4]), null, "not even when nothing else exists");
  assert.equal(pickCheckOperation([op(0, "POST"), op(1, "HEAD")], [])?.index, 1);
  // OPTIONS only if ticked.
  const opts = [op(0, "POST"), op(1, "OPTIONS")];
  assert.equal(pickCheckOperation(opts, []), null);
  assert.equal(pickCheckOperation(opts, [1])?.index, 1);
  // The server's word on state_changing counts even on a GET.
  assert.equal(pickCheckOperation([op(0, "GET", { state_changing: true })], [0]), null);
  assert.deepEqual(checkArgs("/s.yaml", SHA, { ...EMPTY_TARGET, server: 1 }, 4, "p"), ["import", "api", "--only=4", "--max-requests=1", `--expect-sha256=${SHA}`, "--server=1", "--auth=p", "--", "/s.yaml"]);
  assert.ok(!checkArgs("/s.yaml", SHA, EMPTY_TARGET, 0, "").some((a) => a.startsWith("--auth")));
});

test("the scan's arguments", () => {
  const plan = { source: " /s.yaml ", sha256: SHA, target: { ...EMPTY_TARGET, server: 0 }, operations: OPS, selected: [5, 0, 2], profile: "", depth: "quick" as const, speedArgs: [] };
  assert.deepEqual(scanArgs(plan), ["scan", "active", "--api=/s.yaml", `--expect-sha256=${SHA}`, "--server=0", "--only=0,2,5", "--preset", "quick", "--background"]);
  const risky = scanArgs({ ...plan, selected: [1, 3, 6], profile: "p", depth: "thorough", speedArgs: ["-c", "3"] });
  assert.deepEqual(risky.slice(5), ["--only=1,3,6", "--include-methods=PUT,PATCH,DELETE", "--auth=p", "--preset", "thorough", "-c", "3", "--background"]);
  // A thousand operations, about 4 KB: well inside any argv limit.
  const many = Array.from({ length: 1000 }, (_, i) => op(i, "GET"));
  const only = scanArgs({ ...plan, operations: many, selected: many.map((o) => o.index) }).find((a) => a.startsWith("--only="))!;
  assert.ok(only.length < 4000, String(only.length));
  // A job's own arguments tell an API scan from others, after a reload.
  assert.ok(isApiJob(scanArgs(plan)));
  assert.ok(isApiJob(["scan", "active", "--api", "x"]));
  assert.ok(!isApiJob(["scan", "active", "https://a.test", "--apiary"]));
  assert.ok(!isApiJob(null) && !isApiJob(undefined));
});

test("what the key form starts on", () => {
  const cred = (patch: Partial<ApiCredential>): ApiCredential => ({ kind: "api_key", in: "header", name: "X-K", source: "s", embedded: false, ...patch });
  assert.deepEqual(keyDefaults([]), { keyKind: "api_key", place: "header", keyName: "" });
  assert.deepEqual(keyDefaults([cred({ in: "query", name: "k" })]), { keyKind: "api_key", place: "query", keyName: "k" });
  assert.deepEqual(keyDefaults([cred({ embedded: true, name: "E" }), cred({ name: "D" })]), { keyKind: "api_key", place: "header", keyName: "D" }, "a declared scheme first");
  assert.deepEqual(keyDefaults([cred({ in: "cookie" })]), { keyKind: "api_key", place: "header", keyName: "" }, "a cookie can't be set up here");
  assert.deepEqual(keyDefaults([cred({ kind: "bearer", name: "Authorization" })]), { keyKind: "bearer", place: "header", keyName: "Authorization" });
  assert.deepEqual(keyKindDefaults([], "bearer"), { keyKind: "bearer", place: "header", keyName: "Authorization" });
  assert.deepEqual(keyKindDefaults([cred({ name: "A" })], "api_key"), { keyKind: "api_key", place: "header", keyName: "A" });

  assert.equal(defaultProfileName("Pet Store!", []), "pet-store-api");
  assert.equal(defaultProfileName("My API", []), "my-api");
  assert.equal(defaultProfileName(null, ["api"]), "api-2");
  assert.deepEqual(profileProblems("ok_1.a", []), []);
  assert.match(profileProblems("a b", [])[0], /letters/);
  assert.match(profileProblems("p", ["p"])[0], /already exists/, "`auth add` would replace it");
});

test("the key's arguments and problems", () => {
  const a: AuthState = { ...EMPTY_AUTH, mode: "key", keyName: "X-Api-Key", profileName: " k " };
  assert.deepEqual(keyAddArgs(a, ["https://a.test"]), ["auth", "add", `--header-env=X-Api-Key=${KEY_ENV}`, "--", "k"]);
  assert.deepEqual(keyAddArgs({ ...a, keyKind: "bearer", keyName: "ignored" }, []), ["auth", "add", `--header-env=Authorization=${KEY_ENV}`, "--", "k"]);
  assert.deepEqual(keyAddArgs({ ...a, place: "query", keyName: "api_key" }, ["https://a.test", "http://b.test:81"]), ["auth", "add", `--query-key=api_key=${KEY_ENV}`, "--key-origin=https://a.test", "--key-origin=http://b.test:81", "--", "k"]);
  assert.deepEqual(keyProblems(a, [], true, []), []);
  assert.match(keyProblems({ ...a, keyName: "" }, [], true, [])[0], /Name the header/);
  assert.match(keyProblems({ ...a, keyName: "X Bad" }, [], true, [])[0], /valid header/);
  assert.match(keyProblems(a, [], false, [])[0], /Enter the key/);
  assert.match(keyProblems({ ...a, keyKind: "bearer" }, [], false, [])[0], /Enter the token/);
  const q = { ...a, place: "query" as const, keyName: "api_key" };
  assert.deepEqual(keyProblems(q, [], true, ["https://a.test"]), []);
  assert.match(keyProblems(q, [], true, [])[0], /No in-scope address/);
  // Those the CLI's own check refuses, said before they get there.
  for (const name of ["a b", "a&b", "a=b", "a[b]", "ключ"]) assert.match(keyProblems({ ...q, keyName: name }, [], true, ["https://a.test"])[0], /query parameter's name/, name);
  for (const name of ["api_key", "api-key", "a.b", "a~b"]) assert.deepEqual(keyProblems({ ...q, keyName: name }, [], true, ["https://a.test"]), [], name);
});

test("which profile a scan runs with", () => {
  const signer = { profile: "s", name: "hm" };
  assert.equal(authProfile(EMPTY_AUTH), "");
  assert.equal(authProfile({ ...EMPTY_AUTH, mode: "key", savedProfile: "k" }), "k");
  assert.equal(authProfile({ ...EMPTY_AUTH, mode: "profile", existing: "e" }), "e");
  assert.equal(authProfile({ ...EMPTY_AUTH, signing: true, signer }), "s");
  assert.equal(authProfile({ ...EMPTY_AUTH, signing: false, signer }), "", "unticked");

  assert.deepEqual(authProblems(EMPTY_AUTH), [], "no authentication is always fine");
  assert.match(authProblems({ ...EMPTY_AUTH, mode: "key" })[0], /Save the key/);
  assert.match(authProblems({ ...EMPTY_AUTH, mode: "profile" })[0], /Choose a profile/);
  assert.match(authProblems({ ...EMPTY_AUTH, signing: true })[0], /signer/);
  assert.match(authProblems({ ...EMPTY_AUTH, mode: "key", savedProfile: "k", signing: true, signer })[0], /A scan uses one profile/);
  assert.deepEqual(authProblems({ ...EMPTY_AUTH, mode: "key", savedProfile: "s", signing: true, signer }), []);

  assert.match(newSignerProblems({ ...EMPTY_AUTH, mode: "key" }, [])[0], /Save the key first/);
  assert.deepEqual(newSignerProblems({ ...EMPTY_AUTH, mode: "profile", existing: "e" }, ["e"]), []);
  assert.match(newSignerProblems({ ...EMPTY_AUTH, profileName: "taken" }, ["taken"])[0], /already exists/);

  assert.equal(authSummary(EMPTY_AUTH), "none");
  assert.equal(authSummary({ ...EMPTY_AUTH, mode: "profile", existing: "e" }), 'existing profile "e"');
  assert.equal(authSummary({ ...EMPTY_AUTH, mode: "key", keyKind: "api_key", place: "query", keyName: "k", savedProfile: "p" }), 'API key in query parameter k, saved in profile "p"');
  assert.match(authSummary({ ...EMPTY_AUTH, mode: "key", keyKind: "bearer", savedProfile: "p" }), /bearer token/);
});

test("signer coverage", () => {
  const signer = { name: "hm", origins: ["https://api.test"] };
  const urls = ["https://api.test/v1/a"];
  const rule = (patch: Partial<SessionRule>): SessionRule => ({ id: 1, actions: [{ action: "sign", signer: "hm" }], ...patch }) as SessionRule;
  assert.equal(signerCoverage([], signer, urls).state, "no_rule");
  assert.equal(signerCoverage([rule({ actions: [{ action: "sign", signer: "other" }] })], signer, urls).state, "no_rule");
  assert.deepEqual(signerCoverage([rule({})], signer, urls), { state: "covered", checkCovered: true, message: "" });
  assert.deepEqual(signerCoverage([rule({ tools: [] })], signer, urls), { state: "covered", checkCovered: true, message: "" });

  // A rule for scans alone: a scan signs, and the check (`import api`, the crawl tool) doesn't.
  assert.deepEqual(signerCoverage([rule({ tools: ["scan"] })], signer, urls), { state: "covered", checkCovered: false, message: "" });
  const crawl = signerCoverage([rule({ tools: ["crawl"] })], signer, urls);
  assert.equal(crawl.state, "tool_limited");
  assert.ok(crawl.checkCovered);
  assert.match(crawl.message, /unsigned/);

  assert.equal(signerCoverage([rule({ url: "https://api.test/v1/" })], signer, urls).state, "covered");
  assert.equal(signerCoverage([rule({ url: "https://api.test/v2/" })], signer, urls).state, "url_limited");
  assert.equal(signerCoverage([rule({ url: "*.api.test" })], signer, urls).state, "covered");
  const outside = signerCoverage([rule({})], signer, ["https://other.test/x"]);
  assert.equal(outside.state, "origin_limited");
  assert.match(outside.message, /other\.test/);

  // As session.rs matches: a prefix with a scheme, else the host; *.x covers x itself.
  assert.ok(urlPatternMatches("https://a.test/", "https://a.test/x"));
  assert.ok(urlPatternMatches("HTTPS://A.test/", "https://a.test/x"));
  assert.ok(urlPatternMatches("https://*.a.test/", "https://b.a.test/x"));
  assert.ok(!urlPatternMatches("https://a.test/", "http://a.test/x"));
  assert.ok(urlPatternMatches("a.test", "https://a.test:8/x"));
  assert.ok(!urlPatternMatches("a.test", "https://b.a.test/x"));
  assert.ok(urlPatternMatches("*.a.test", "https://a.test/"));
  assert.ok(urlPatternMatches("*.a.test", "https://b.a.test/"));
  assert.ok(!urlPatternMatches("*.a.test", "https://evil-a.test/"));
  assert.ok(!urlPatternMatches("a.test", "not a url"));

  assert.deepEqual(signerFormOrigins({ origins: " https://a.test \n\nhttps://b.test" }), ["https://a.test", "https://b.test"]);
  assert.deepEqual(newSignerForm(["https://a.test", "https://b.test"]).origins, "https://a.test\nhttps://b.test");
  const rules = signRuleArgs("p", "hm", ["https://a.test", "https://a.test:443", "not a url", "http://b.test:81"]);
  assert.equal(rules.length, 2, "one rule per origin");
  assert.deepEqual(rules[0], ["auth", "rule", "add", "--action=sign:hm", "--url=https://a.test/", "--description=Signs the API guided scan's requests", "--", "p"]);
});

test("what a recorded request shows", () => {
  const raw = (line: string) => `GET /x?${line} HTTP/1.1\r\nHost: a.test\r\n\r\n`;
  assert.ok(signerOnRequest("GET / HTTP/1.1\r\nX-Sig: «auth:p:sign:hm»\r\n\r\n", "p", "hm"));
  assert.ok(signerOnRequest("GET / HTTP/1.1\r\nX-Sig: «auth:p:sign:hm:abc»\r\n\r\n", "p", "hm"));
  assert.ok(!signerOnRequest("GET / HTTP/1.1\r\nX-Sig: «auth:p:sign:hm2»\r\n\r\n", "p", "hm"), "another signer");
  assert.ok(!signerOnRequest("GET / HTTP/1.1\r\nX-Sig: «auth:q:sign:hm»\r\n\r\n", "p", "hm"), "another profile");
  assert.ok(credentialOnRequest(raw("api_key=«auth:p:query:api_key»"), "p"));
  assert.ok(credentialOnRequest("GET / HTTP/1.1\r\nX-K: «auth:p:header:X-K»\r\n\r\n", "p"));
  assert.ok(!credentialOnRequest("GET / HTTP/1.1\r\nX-Sig: «auth:p:sign:hm»\r\n\r\n", "p"), "a signature isn't a credential");
  assert.ok(!credentialOnRequest(raw("a=1"), "p"));
  assert.ok(!credentialOnRequest("GET / HTTP/1.1\r\nX-K: «auth:q:header:X-K»\r\n\r\n", "p"));
});

test("what the check found, in plain words", () => {
  const facts = (patch: Partial<CheckFacts>): CheckFacts => ({ status: 200, profile: "", signer: "", credentialOn: null, signerOn: null, signerRuleApplies: true, ...patch });
  const m = (patch: Partial<CheckFacts>) => checkMeaning(facts(patch));
  assert.equal(m({}).tone, "ok");
  assert.match(m({}).text, /without authentication/);
  assert.match(m({ profile: "p", credentialOn: true }).text, /credentials from "p" were on it/);
  assert.match(m({ profile: "p", credentialOn: false }).text, /Nothing from "p" was on it/);
  assert.match(m({ profile: "p" }).text, /couldn't be read/);
  assert.equal(m({ status: 401, profile: "p", credentialOn: true }).tone, "bad");
  assert.match(m({ status: 401, profile: "p", credentialOn: true }).text, /check the key/);
  assert.match(m({ status: 403 }).text, /without authentication/);
  assert.equal(m({ status: 302 }).tone, "warn");
  assert.match(m({ status: 500 }).text, /says nothing about authentication/);
  assert.match(m({ status: 404 }).text, /example values/);
  assert.equal(m({ status: null, error: "connection refused" }).tone, "bad");
  assert.match(m({ status: null, error: "connection refused" }).text, /connection refused/);

  const signed = { profile: "p", signer: "hm" };
  assert.match(m({ ...signed, credentialOn: false, signerOn: true }).text, /signature from "hm" was on it/);
  assert.match(m({ ...signed, credentialOn: false, signerOn: false }).text, /signature from "hm" was not on it/);
  // A rule for scans alone: the check goes out unsigned, and that is no verdict on the scan.
  const scanOnly = { ...signed, credentialOn: false, signerOn: false, signerRuleApplies: false };
  assert.equal(m(scanOnly).tone, "ok");
  assert.match(m(scanOnly).text, /doesn't apply to this check\. A scan may still sign/);
  const rejected = m({ ...scanOnly, status: 401 });
  assert.equal(rejected.tone, "warn");
  assert.match(rejected.text, /unsigned/);
  assert.doesNotMatch(rejected.text, /check the key/);
  // A signature that should have been there and wasn't is a real failure.
  assert.equal(m({ ...signed, status: 401, credentialOn: false, signerOn: false }).tone, "bad");
});

test("credentials, in plain words and without values", () => {
  const c = (patch: Partial<ApiCredential>): ApiCredential => ({ kind: "api_key", in: "header", name: "X-K", source: "s", embedded: false, ...patch });
  assert.equal(credentialText(c({})), "API key (header X-K): the definition asks for this.");
  assert.match(credentialText(c({ embedded: true })), /the file held this credential\. It will not be used/);
  assert.match(credentialText(c({ in: "cookie", name: "sid" })), /Create a profile/);
  assert.match(credentialText(c({ kind: "oauth2", in: null, name: null })), /OAuth 2: can't be set up here/);
  assert.match(credentialText(c({ kind: "other", in: null, name: "password", embedded: true })), /Other \(password\)/);
  assert.match(credentialText(c({ kind: "bearer", in: "header", name: "Authorization" })), /Bearer token: the definition asks/);
});

test("progress and what a finished scan says", () => {
  assert.equal(baselineText({ sent: 2, total: 5 }), "Sending each operation once to record a normal response: 2 of 5 sent.");
  assert.equal(baselineText({}), "Sending each operation once to record a normal response: 0 of 0 sent.");
  assert.deepEqual(apiResultNotes(null), []);
  assert.deepEqual(apiResultNotes({ sent: 3, by_status: { "200": 3 }, errors: 0, skipped_out_of_scope: 0, out_of_scope_hosts: [], skipped: [] }), []);
  const notes = apiResultNotes({ sent: 5, by_status: { "401": 1, "403": 1, "200": 2, error: 1 }, errors: 1, skipped_out_of_scope: 2, out_of_scope_hosts: ["o.test"], skipped: [{ operation: "GET /x", reason: "r" }] });
  assert.match(notes[0], /2 operations were rejected \(401 or 403\) of 5 sent/);
  assert.match(notes[1], /1 operation got no response/);
  assert.match(notes[2], /2 operations outside the project's scope were skipped \(o\.test\)/);
  assert.match(notes[3], /1 operation in the definition couldn't be built/);
});

test("a host only an IP scope might allow isn't ticked next to one the scope lists", () => {
  const listed = op(0, "GET");
  const unlisted = op(1, "GET", { scope_confirmed: false });
  assert.deepEqual(defaultSelection([listed, unlisted]), [0]);
  // With nothing listed by name there's no better guess: the scope's own check decides at send.
  assert.deepEqual(defaultSelection([unlisted]), [1]);
  assert.deepEqual(likelyInScope([{ in_scope: false, scope_confirmed: false }]), []);
});
