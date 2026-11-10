import { test } from "node:test";
import assert from "node:assert/strict";
import { TOTP_ENV, finishCall, logsIn, modeText, passkeyLine, startArgs } from "./recordLogin.ts";

test("a recording starts with a virtual authenticator only when a passkey is asked for", () => {
  assert.deepEqual(startArgs("https://app.test/login", { passkey: false }), ["auth", "record", "start", "--", "https://app.test/login"]);
  assert.deepEqual(startArgs("https://app.test/", { passkey: true }), ["auth", "record", "start", "--passkey", "--", "https://app.test/"]);
  // The profile's own passkeys, to record a sign-in with one.
  assert.deepEqual(startArgs("https://app.test/", { passkey: true, passkeysFrom: "app" }), [
    "auth",
    "record",
    "start",
    "--passkeys-from=app",
    "--",
    "https://app.test/",
  ]);
  assert.deepEqual(startArgs("https://app.test/", { passkey: false, passkeysFrom: "app" }), ["auth", "record", "start", "--", "https://app.test/"]);
});

test("a TOTP secret goes in the environment, never in the arguments", () => {
  const secret = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ";
  const call = finishCall("app", { save: true, totpSecret: ` ${secret} `, passwordEnv: " APP_PW " });
  assert.deepEqual(call.args, ["auth", "record", "finish", "--save", "--password-env=APP_PW", "--", "app"]);
  assert.deepEqual(call.env, { [TOTP_ENV]: secret });
  assert.ok(!call.args.join(" ").includes("GEZDGNBV"));
  // A preview, with nothing typed: no flags and no environment.
  assert.deepEqual(finishCall("-odd", { save: false, totpSecret: "  " }), { args: ["auth", "record", "finish", "--", "-odd"] });
  assert.deepEqual(finishCall("app", { save: false, inBrowser: true }).args, ["auth", "record", "finish", "--in-browser", "--", "app"]);
});

test("each mode says what happens when the session ends", () => {
  assert.match(modeText("replay"), /log in by itself/);
  assert.match(modeText("browser"), /replaying your steps in a browser/);
  assert.match(modeText("session"), /Record again when it expires/);
  assert.deepEqual([logsIn("replay"), logsIn("browser"), logsIn("session")], [true, true, false]);
});

test("a passkey is described without its key", () => {
  assert.equal(passkeyLine({ rp_id: "app.test", credential_id: "aWQ=", user_name: "carol", sign_count: 3 }), "carol at app.test · used 3 times");
  assert.equal(passkeyLine({ rp_id: "app.test", credential_id: "aWQ=", user_name: null, sign_count: 1 }), "app.test · used 1 time");
});
