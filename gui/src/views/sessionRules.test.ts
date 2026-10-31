import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_SIGNER,
  HMAC_HASHES,
  JWT_ALGS,
  actionLabel,
  actionSpec,
  macroAddArgs,
  parseParams,
  ruleAddArgs,
  ruleProblems,
  signerAddArgs,
  signerForm,
  signerLabel,
  signerProblems,
  type Action,
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
    macroAddArgs("app", " login ", [12, 15], [
      { step: 1, var: "csrf", from: "input", expr: "csrf" },
      { step: 2, var: "tok", from: "regex", expr: '-"t":"([^"]+)"' },
      { step: 2, var: " ", from: "json", expr: "ignored" },
    ]),
    ["auth", "macro", "add", "--step=12", "--step=15", "--extract=1:csrf=input:csrf", '--extract=2:tok=regex:-"t":"([^"]+)"', "--", "app", "login"],
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
