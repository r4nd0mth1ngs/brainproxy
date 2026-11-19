import { test } from "node:test";
import assert from "node:assert/strict";
import { requestFileArg, withRequestFile } from "./requestFiles.ts";

test("a race's and a macro step's placeholders take their files", () => {
  const args = ["auth", "macro", "edit", "--step=step:1", "--step=https://app.test:8443=@request:1", "--step=@request:0", "--", "app", "m"];
  assert.equal(requestFileArg(args, 0), 5);
  assert.equal(requestFileArg(args, 1), 4);
  assert.equal(withRequestFile(args[4], 1, "/t/1.http"), "--step=https://app.test:8443=/t/1.http");
  assert.equal(withRequestFile(args[5], 0, "/t/0.http"), "--step=/t/0.http");
  assert.equal(requestFileArg(["send", "--also=@request:0"], 0), 1);
  assert.equal(withRequestFile("--also=@request:0", 0, "/t/0.http"), "--also=/t/0.http");
});

test("a placeholder in any other argument, or for another file, is not one", () => {
  for (const arg of ["--stepx=@request:0", "--extract=1:a=regex:@request:0", "--also=x=@request:0", "--step=@request:10", "@request:0"])
    assert.equal(requestFileArg([arg], 0), -1, arg);
});
