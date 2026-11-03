import { test } from "node:test";
import assert from "node:assert/strict";
import { inOrder } from "./usePoll.ts";

const deferred = <T>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => ((resolve = res), (reject = rej)));
  return { promise, resolve, reject };
};
const settle = () => new Promise((r) => setTimeout(r, 0));

test("a slow older poll doesn't undo a newer answer", async () => {
  const got: string[] = [];
  const accept = inOrder<string>((v) => got.push(v));
  const older = deferred<string>();
  const newer = deferred<string>();
  accept(older.promise);
  accept(newer.promise);
  // A job's status: the newer poll sees it completed, then the older one lands saying running.
  newer.resolve("completed");
  await settle();
  older.resolve("running");
  await settle();
  assert.deepEqual(got, ["completed"]);
});

test("polls that settle in order are all applied, and a failed one changes nothing", async () => {
  const got: number[] = [];
  const accept = inOrder<number>((v) => got.push(v));
  const a = deferred<number>();
  const b = deferred<number>();
  const c = deferred<number>();
  accept(a.promise);
  accept(b.promise);
  accept(c.promise);
  a.resolve(1);
  await settle();
  c.reject(new Error("busy"));
  await settle();
  // The newest failed, so the one before it is still the latest answer.
  b.resolve(2);
  await settle();
  assert.deepEqual(got, [1, 2]);
});
