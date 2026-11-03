import { test } from "node:test";
import assert from "node:assert/strict";
import { onCloseRequested, type QuitSteps } from "./quit.ts";

/** The steps with every answer given, recording what ran in order. */
function steps(o: { temp: boolean; sending: boolean; sends?: boolean; discard?: boolean }) {
  const trace: string[] = [];
  const s: QuitSteps = {
    temp: o.temp,
    sending: () => o.sending,
    preventDefault: () => void trace.push("held open"),
    askSends: async () => (trace.push("asked sends"), o.sends ?? true),
    askDiscard: async () => (trace.push("asked discard"), o.discard ?? true),
    stopSends: async () => void trace.push("sends stopped"),
    leave: async () => void trace.push("left"),
    destroy: async () => void trace.push("destroyed"),
  };
  return { s, trace };
}

test("nothing to ask: the project is left and the window closes by itself", async () => {
  const { s, trace } = steps({ temp: false, sending: false });
  await onCloseRequested(s);
  assert.deepEqual(trace, ["left"]);
});

test("sends running: they're stopped only after the user agrees", async () => {
  const yes = steps({ temp: false, sending: true });
  await onCloseRequested(yes.s);
  assert.deepEqual(yes.trace, ["held open", "asked sends", "sends stopped", "left", "destroyed"]);
  const no = steps({ temp: false, sending: true, sends: false });
  await onCloseRequested(no.s);
  assert.deepEqual(no.trace, ["held open", "asked sends"]);
});

test("a temporary project with sends: declining the discard keeps the sends running", async () => {
  const no = steps({ temp: true, sending: true, discard: false });
  await onCloseRequested(no.s);
  assert.deepEqual(no.trace, ["held open", "asked sends", "asked discard"]);
  const yes = steps({ temp: true, sending: true });
  await onCloseRequested(yes.s);
  assert.deepEqual(yes.trace, ["held open", "asked sends", "asked discard", "sends stopped", "left", "destroyed"]);
});

test("a temporary project without sends asks only about the discard", async () => {
  const { s, trace } = steps({ temp: true, sending: false });
  await onCloseRequested(s);
  assert.deepEqual(trace, ["held open", "asked discard", "sends stopped", "left", "destroyed"]);
});
