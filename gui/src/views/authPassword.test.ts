import { test } from "node:test";
import assert from "node:assert/strict";
import { passwordArgs, type PasswordForm } from "./authPassword.ts";

const form = (over: Partial<PasswordForm>): PasswordForm => ({ passwordMode: "literal", passwordEnv: "", password: "", passwordStored: false, ...over });

test("an edited profile's stored password is kept when the field is left empty", () => {
  assert.deepEqual(passwordArgs(form({ passwordStored: true })), ["--keep-password"]);
  // A new one typed replaces it, and goes in the environment, so no flag (--keep-password would conflict).
  assert.deepEqual(passwordArgs(form({ passwordStored: true, password: "s3cret" })), []);
  assert.deepEqual(passwordArgs(form({ password: "s3cret" })), []);
  assert.deepEqual(passwordArgs(form({})), [], "a new profile with no password has none to keep");
});

test("choosing a variable or no password replaces a stored one", () => {
  assert.deepEqual(passwordArgs(form({ passwordStored: true, passwordMode: "env", passwordEnv: " APP_PW " })), ["--password-env=APP_PW"]);
  assert.deepEqual(passwordArgs(form({ passwordMode: "env", passwordEnv: "  " })), []);
  // No variable named yet: a stored password isn't dropped for that.
  assert.deepEqual(passwordArgs(form({ passwordStored: true, passwordMode: "env", passwordEnv: "" })), ["--keep-password"]);
  assert.deepEqual(passwordArgs(form({ passwordStored: true, passwordMode: "none" })), []);
});
