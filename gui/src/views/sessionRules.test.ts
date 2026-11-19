import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_SIGNER,
  HMAC_HASHES,
  JWT_ALGS,
  actionLabel,
  actionSpec,
  cleanOrigin,
  editedStep,
  inferOrigin,
  insertVar,
  macroAddArgs,
  macroEditArgs,
  macroEditProblem,
  macroEditor,
  parseParams,
  ruleAddArgs,
  ruleProblems,
  signerAddArgs,
  signerForm,
  signerLabel,
  signerProblems,
  stepLine,
  stepTextProblem,
  varsBefore,
  type Action,
  type EditorStep,
  type MacroDetail,
  type Signer,
  type SignerForm,
} from "./sessionRules.ts";

test("actions turn into --action specs the CLI parses", () => {
  const cases: [Action, string][] = [
    [{ action: "check", every: 1 }, "check"],
    [{ action: "check", every: 20 }, "check:20"],
    [{ action: "run_macro", macro: "csrf", every: 0 }, "macro:csrf"],
    [{ action: "run_macro", macro: "csrf", every: 1 }, "macro:csrf:each"],
    [{ action: "run_macro", macro: "csrf", every: 5 }, "macro:csrf:5"],
    [{ action: "update", params: [] }, "update"],
    [{ action: "update", params: [["csrf", "csrf"], ["X-Token", "tok"]] }, "update:csrf,X-Token=tok"],
    [{ action: "login" }, "login"],
    [{ action: "sign", signer: "hm" }, "sign:hm"],
  ];
  for (const [a, spec] of cases) assert.equal(actionSpec(a), spec);
  assert.equal(actionLabel({ action: "run_macro", macro: "csrf", every: 1 }), "run csrf on every request");
  assert.deepEqual(parseParams(" csrf , X-Token = tok,,"), [["csrf", "csrf"], ["X-Token", "tok"]]);
});

test("macro and rule arguments keep values that start with a dash", () => {
  assert.deepEqual(
    macroAddArgs("app", " login ", [12, 15].map((id): EditorStep => ({ key: `history${id}`, kind: "history", id, line: "" })), [
      { step: 1, var: "csrf", from: "input", expr: "csrf" },
      { step: 2, var: "tok", from: "regex", expr: '-"t":"([^"]+)"' },
      { step: 2, var: " ", from: "json", expr: "ignored" },
    ]),
    {
      args: ["auth", "macro", "add", "--step=12", "--step=15", "--extract=1:csrf=input:csrf", '--extract=2:tok=regex:-"t":"([^"]+)"', "--", "app", "login"],
      requestFiles: [],
    },
  );
  const rule = {
    tools: ["scan", "fuzz"] as const,
    url: " https://app.test/api/ ",
    invalid: "invalid csrf",
    description: "",
    actions: [{ action: "run_macro", macro: "csrf", every: 1 }, { action: "update", params: [["csrf", "csrf"]] }] as Action[],
  };
  assert.deepEqual(ruleAddArgs("app", { ...rule, tools: [...rule.tools] }), [
    "auth", "rule", "add", "--action=macro:csrf:each", "--action=update:csrf", "--tool=scan,fuzz",
    "--url=https://app.test/api/", "--invalid=invalid csrf", "--", "app",
  ]);
  // Every tool ticked is the same as none: no --tool.
  const all = ruleAddArgs("app", { ...rule, tools: ["proxy", "send", "fuzz", "crawl", "scan", "checks"] });
  assert.ok(!all.some((a) => a.startsWith("--tool")));
});

test("a rule that can't be saved says why", () => {
  const r = { tools: [], url: "", invalid: "", description: "", actions: [] as Action[] };
  assert.deepEqual(ruleProblems(r, [], [], true, true), ["Add at least one action."]);
  const bad = { ...r, actions: [{ action: "check", every: 1 }, { action: "login" }, { action: "run_macro", macro: "x", every: 0 }] as Action[] };
  assert.deepEqual(ruleProblems(bad, ["csrf"], [], false, false), [
    "A session check needs the profile's check URL.",
    "Log in needs a profile with a login URL.",
    'No macro named "x".',
  ]);
  assert.deepEqual(ruleProblems(bad, ["x"], [], true, true), []);
  const update = { action: "update", params: [] } as Action;
  assert.deepEqual(ruleProblems({ ...r, actions: [update] }, [], [], true, true), ["Update with no parameters needs a macro before it."]);
  assert.deepEqual(ruleProblems({ ...r, actions: [{ action: "run_macro", macro: "x", every: 1 }, update] }, ["x"], [], true, true), []);
  const sign = { ...r, actions: [{ action: "sign", signer: "hm" }] as Action[] };
  assert.deepEqual(ruleProblems(sign, [], [], true, true), ['No signer named "hm".']);
  assert.deepEqual(ruleProblems(sign, [], ["hm"], true, true), []);
});

const hmacForm: SignerForm = {
  ...EMPTY_SIGNER,
  name: " hm ",
  key: " API_SECRET ",
  origins: " https://api.test \n\nhttps://b.test",
  toName: " X-Signature ",
  headers: "X-Timestamp: {{timestamp}}\n\n",
  canonical: "{{method}}\\n{{path}} ",
};

test("an HMAC signer's arguments name where the key is, and keep its template as typed", () => {
  assert.deepEqual(signerAddArgs("api", hmacForm), [
    "auth", "sign", "add", "--secret-env=API_SECRET", "--origin=https://api.test", "--origin=https://b.test",
    "--to=header:X-Signature", "--set-header=X-Timestamp: {{timestamp}}",
    "--canonical={{method}}\\n{{path}} ", "--hash=sha256", "--output=hex", "--", "api", "hm",
  ]);
  for (const hash of HMAC_HASHES) assert.ok(signerAddArgs("api", { ...hmacForm, hash }).includes(`--hash=${hash}`));
  assert.ok(signerAddArgs("api", hmacForm, true).includes("--keep-place"));
  // A value that starts with a dash stays one argument.
  assert.ok(signerAddArgs("api", { ...hmacForm, canonical: "-x" }).includes("--canonical=-x"));
});

test("a JWT signer's arguments leave out the HMAC flags, which the CLI refuses with --jwt", () => {
  const f: SignerForm = {
    ...hmacForm,
    kind: "jwt",
    keyFrom: "file",
    key: "/keys/api.pem",
    keyEncoding: "base64",
    wrap: "Bearer {{signature}}",
    claims: '{"sub":"admin"}',
    ttl: "300",
    kid: "k1",
    resign: true,
    headers: "",
  };
  for (const jwtAlg of JWT_ALGS) {
    assert.deepEqual(signerAddArgs("api", { ...f, jwtAlg }), [
      "auth", "sign", "add", "--secret-file=/keys/api.pem", "--secret-encoding=base64",
      "--origin=https://api.test", "--origin=https://b.test", "--to=header:X-Signature", "--wrap=Bearer {{signature}}",
      `--jwt=${jwtAlg}`, '--claims={"sub":"admin"}', "--ttl=300", "--kid=k1", "--resign", "--", "api", "hm",
    ]);
  }
  // The CLI's defaults stand for what's left empty, and --wrap is for a header.
  assert.deepEqual(signerAddArgs("api", { ...EMPTY_SIGNER, kind: "jwt", name: "t", key: "K", origins: "https://a.test", toKind: "query", toName: "sig", wrap: "x{{signature}}" }), [
    "auth", "sign", "add", "--secret-env=K", "--origin=https://a.test", "--to=query:sig", "--jwt=HS256", "--", "api", "t",
  ]);
});

test("editing a signer from auth show gives back the same arguments", () => {
  const hmac: Signer = {
    name: "hm",
    key: { env: "API_SECRET" },
    key_encoding: "hex",
    origins: ["https://api.test", "https://b.test"],
    to: { header: "X-Signature" },
    format: "sig={{signature}}",
    headers: [["X-Timestamp", "{{timestamp}}"], ["X-Nonce", "{{nonce}}"]],
    kind: "hmac",
    alg: "sha512",
    canonical: "{{path}}\\n{{body_sha256}}",
    output: "base64url",
  };
  assert.deepEqual(signerAddArgs("api", signerForm(hmac)), [
    "auth", "sign", "add", "--secret-env=API_SECRET", "--secret-encoding=hex", "--origin=https://api.test", "--origin=https://b.test",
    "--to=header:X-Signature", "--wrap=sig={{signature}}", "--set-header=X-Timestamp: {{timestamp}}", "--set-header=X-Nonce: {{nonce}}",
    "--canonical={{path}}\\n{{body_sha256}}", "--hash=sha512", "--output=base64url", "--", "api", "hm",
  ]);
  const jwt: Signer = {
    name: "tok",
    key: { file: "/keys/api.pem" },
    origins: ["https://api.test"],
    to: { query: "token" },
    kind: "jwt",
    alg: "RS256",
    claims: '{"sub":"{{nonce}}"}',
    ttl: 60,
    kid: "k1",
    resign: true,
  };
  assert.deepEqual(signerAddArgs("api", signerForm(jwt)), [
    "auth", "sign", "add", "--secret-file=/keys/api.pem", "--origin=https://api.test", "--to=query:token",
    "--jwt=RS256", '--claims={"sub":"{{nonce}}"}', "--ttl=60", "--kid=k1", "--resign", "--", "api", "tok",
  ]);
  // The JWT header carries a kid as written.
  assert.ok(signerAddArgs("api", signerForm({ ...jwt, kid: " k1 " })).includes("--kid= k1 "));
  assert.deepEqual(signerProblems(signerForm(hmac), []), []);
  assert.deepEqual(signerProblems(signerForm(jwt), []), []);
  assert.equal(signerLabel(hmac), "HMAC-SHA512 (base64url) → header X-Signature · key in $API_SECRET");
  assert.equal(signerLabel(jwt), "JWT RS256, re-signed → query token · key in /keys/api.pem");
});

test("a signer that can't be saved says why, without repeating a key pasted in", () => {
  assert.deepEqual(signerProblems(hmacForm, []), []);
  const key = "s3cret key/value+=";
  const problems = signerProblems({ ...hmacForm, key }, []);
  assert.deepEqual(problems, ["Give the name of the environment variable that holds the key, not the key."]);
  assert.ok(!problems.join().includes(key));
  assert.deepEqual(signerProblems({ ...hmacForm, keyFrom: "file", key: "keys/api.pem" }, []), ["Give the full path of the file that holds the key."]);
  assert.deepEqual(signerProblems({ ...hmacForm, keyFrom: "file", key: "C:\\keys\\api.pem" }, []), []);
  assert.deepEqual(signerProblems(hmacForm, ["hm"]), ['A signer named "hm" already exists.']);
  assert.deepEqual(
    signerProblems({ ...EMPTY_SIGNER, name: "a b", key: "K", wrap: "Bearer", headers: "no colon" }, []),
    [
      "Name the signer with letters, digits, '_', '-' and '.'.",
      "Name at least one origin it may sign for.",
      "Name the header the value goes in.",
      "The header format needs {{signature}} once.",
      "Write each header to set as NAME: TEMPLATE.",
      "Say what to sign.",
    ],
  );
  const jwt = { ...hmacForm, kind: "jwt" as const, canonical: "" };
  assert.deepEqual(signerProblems(jwt, []), []);
  assert.deepEqual(signerProblems({ ...jwt, ttl: "5m" }, []), ["Give the JWT's lifetime in whole seconds."]);
});

const login: MacroDetail = {
  name: "login",
  steps: [
    { target: "https://app.test", request: "GET /form HTTP/1.1\r\nHost: app.test\r\n\r\n", history_id: 3, extract: [{ var: "csrf", from: "input", expr: "csrf" }] },
    { target: "https://app.test:8443", request: "POST https://app.test:8443/login HTTP/1.1\r\n\r\n", extract: [] },
  ],
};

test("a macro opens in the editor as it is, and saving it unchanged runs nothing", () => {
  const start = macroEditor(login);
  assert.deepEqual(
    start.steps.map((s) => s.line),
    ["GET https://app.test/form", "POST https://app.test:8443/login"],
  );
  assert.deepEqual(start.extract, [{ key: "step1", var: "csrf", from: "input", expr: "csrf" }]);
  assert.equal(macroEditArgs("app", "login", start, start.steps, start.extract, "r1"), null);
  assert.equal(stepLine({ target: "http://a.test/", request: "GET /x HTTP/1.1" }), "GET http://a.test/x");
});

test("an edited macro says every step and extractor, an extractor following its step", () => {
  const start = macroEditor(login);
  const added: EditorStep = { key: "h42", kind: "history", id: 42, line: "GET https://app.test/next" };
  // Steps swapped and one added from Traffic: the extractor moves with step 1, now step 2.
  const steps = [start.steps[1], start.steps[0], added];
  assert.deepEqual(macroEditArgs("app", "-login", start, steps, start.extract, "r1")?.args, [
    "auth",
    "macro",
    "edit",
    "--step=step:2",
    "--step=step:1",
    "--step=42",
    "--extract=2:csrf=input:csrf",
    "--if-revision=r1",
    "--",
    "app",
    "-login",
  ]);
  // No extractors left is said as such.
  assert.deepEqual(macroEditArgs("app", "login", start, start.steps, []), {
    args: ["auth", "macro", "edit", "--step=step:1", "--step=step:2", "--no-extract", "--", "app", "login"],
    requestFiles: [],
  });
});

const decode = (b: Uint8Array) => new TextDecoder().decode(b);

test("an edited step's request goes in a staged file, to its origin, with its extractors", () => {
  const start = macroEditor(login);
  const was = { target: login.steps[0].target, request: login.steps[0].request };
  // Opened and saved unchanged, a step stays the macro's own.
  assert.equal(editedStep(start.steps[0], was, was), start.steps[0]);
  const edited = editedStep(start.steps[1], { target: "https://app.test:8443", request: "POST /login HTTP/1.1\nHost: app.test:8443\n\ncsrf={{csrf}}" }, {
    target: login.steps[1].target,
    request: login.steps[1].request,
  });
  assert.deepEqual(edited, {
    key: "step2",
    kind: "text",
    target: "https://app.test:8443",
    request: "POST /login HTTP/1.1\nHost: app.test:8443\n\ncsrf={{csrf}}",
    line: "POST https://app.test:8443/login",
  });
  const pasted: EditorStep = editedStep({ key: "text1", kind: "text", target: "", request: "", line: "" }, { target: "http://127.0.0.1:8000", request: "GET /ü HTTP/1.1\n\n" }, null);
  const call = macroEditArgs("app", "login", start, [start.steps[0], edited, pasted], start.extract, "r1");
  assert.deepEqual(call?.args, [
    "auth",
    "macro",
    "edit",
    "--step=step:1",
    "--step=https://app.test:8443=@request:0",
    "--step=http://127.0.0.1:8000=@request:1",
    "--extract=1:csrf=input:csrf",
    "--if-revision=r1",
    "--",
    "app",
    "login",
  ]);
  assert.deepEqual(call?.requestFiles.map(decode), [edited.kind === "text" && edited.request, "GET /ü HTTP/1.1\n\n"]);
  // An extractor on an edited step stays on it.
  const onEdited = [{ key: "step2", var: "tok", from: "json" as const, expr: "token" }];
  assert.ok(macroEditArgs("app", "login", start, [start.steps[0], edited], onEdited)?.args.includes("--extract=2:tok=json:token"));
  // A new macro takes pasted requests too.
  assert.deepEqual(macroAddArgs("app", "m", [pasted], []).args, ["auth", "macro", "add", "--step=http://127.0.0.1:8000=@request:0", "--", "app", "m"]);
});

test("a renamed macro says --rename, and only when the name changed", () => {
  const start = macroEditor(login);
  assert.equal(macroEditArgs("app", "login", start, start.steps, start.extract, "r1", " login "), null);
  assert.deepEqual(macroEditArgs("app", "login", start, start.steps, start.extract, "r1", " signin ")?.args, [
    "auth",
    "macro",
    "edit",
    "--step=step:1",
    "--step=step:2",
    "--extract=1:csrf=input:csrf",
    "--rename=signin",
    "--if-revision=r1",
    "--",
    "app",
    "login",
  ]);
  assert.equal(macroEditProblem(start.steps, start.extract, " "), "Give the macro a name.");
});

test("a pasted request's origin comes from its URL or Host, and a bad one says why", () => {
  assert.equal(inferOrigin("GET /x HTTP/1.1\r\nhost: App.Test:8443\r\n\r\nHost: other"), "https://app.test:8443");
  assert.equal(inferOrigin("GET /x HTTP/1.1\nHost: 127.0.0.1:80\n", "http"), "http://127.0.0.1");
  assert.equal(inferOrigin("POST http://a.test:81/login HTTP/1.1\n\n"), "http://a.test:81");
  assert.equal(inferOrigin("GET /x HTTP/1.1\n\nHost: body.test"), "");
  assert.equal(stepTextProblem({ target: "https://app.test", request: "GET / HTTP/1.1\nHost: app.test\n\n" }), null);
  assert.deepEqual(
    [" HTTPS://App.Test:443/ ", "http://a.test:8080", "https://app.test/path", "app.test"].map(cleanOrigin),
    ["https://app.test", "http://a.test:8080", "https://app.test/path", "app.test"],
  );
  for (const target of ["", "app.test", "ftp://app.test", "https://app.test/path", "https://app.test?x=1", "https://App.test", "https://u@app.test"])
    assert.match(stepTextProblem({ target, request: "GET / HTTP/1.1\n\n" }) ?? "", /origin/, target);
  for (const request of ["", "Host: app.test", "GET /\n\n", "GET / HTTP/1.1 extra"])
    assert.match(stepTextProblem({ target: "https://app.test", request }) ?? "", /request line/, request);
});

test("a step can use the values earlier steps extract, and {{name}} goes at the caret", () => {
  const steps = ["a", "b", "c"].map((k): EditorStep => ({ key: k, kind: "kept", n: 1, line: "" }));
  const extract = [
    { key: "a", var: "csrf" },
    { key: "b", var: "tok" },
    { key: "a", var: " csrf " },
    { key: "c", var: "late" },
  ];
  assert.deepEqual(varsBefore(steps, extract, "a"), ["username", "password"]);
  assert.deepEqual(varsBefore(steps, extract, "c"), ["csrf", "tok", "username", "password"]);
  // A new step goes last: every step is before it.
  assert.deepEqual(varsBefore(steps, extract, null), ["csrf", "tok", "late", "username", "password"]);
  // Offsets count CRLF as one; a body that kept CRLF keeps it.
  const value = "POST / HTTP/1.1\r\nHost: a\r\n\r\nx=1\r\ny=";
  const at = "POST / HTTP/1.1\nHost: a\n\nx=1\ny=".length;
  assert.deepEqual(insertVar(value, at, at, "csrf"), { value: "POST / HTTP/1.1\nHost: a\n\nx=1\r\ny={{csrf}}", caret: at + 8 });
  // A selection is replaced.
  assert.deepEqual(insertVar("GET /?t=old HTTP/1.1", 8, 11, "tok"), { value: "GET /?t={{tok}} HTTP/1.1", caret: 15 });
});

test("an edited macro that can't be saved says why", () => {
  const start = macroEditor(login);
  assert.equal(macroEditProblem([], []), "A macro needs at least one step.");
  assert.equal(macroEditProblem([start.steps[1]], start.extract), "An extractor is on a step that was taken out.");
  assert.equal(macroEditProblem(start.steps, [{ ...start.extract[0], var: " " }]), "Give each extractor a variable and what to look for, or take it out.");
  assert.equal(macroEditProblem(start.steps, start.extract), null);
});
