import { test } from "node:test";
import assert from "node:assert/strict";
import type { Rule } from "./matchReplace.ts";
import { presetArgs, presetLabel, presetNote, presetState, sameRule, type Preset } from "./rulePresets.ts";

const HTML = "^\\s*text/html\\s*(;|$)";
const body: Rule = { id: 0, location: "response-body", pattern: "(?is-u)<script\\b.*?</script>", replace: "", enabled: true, comment: "preset remove-scripts: remove script elements", content_type: HTML };
const csp: Rule = { id: 0, location: "response-header", pattern: "", replace: "script-src 'none'", enabled: true, name: "Content-Security-Policy", action: "add", content_type: HTML };
const scripts: Preset = { name: "remove-scripts", title: "Remove all JavaScript", description: "…", rules: [body, csp] };

test("a saved rule is a preset's whatever its id, comment, origin and state", () => {
  const saved = { ...body, id: 4, enabled: false, comment: "mine", origin: "gui", applies_to: ["proxy"] };
  assert.ok(sameRule(saved, body));
  // Defaults said or left out are the same.
  assert.ok(sameRule({ ...csp, matcher: "regex", replacer: "text" }, csp));
  assert.ok(!sameRule({ ...body, host: "^a$" }, body));
  assert.ok(!sameRule({ ...body, content_type: undefined }, body));
  assert.ok(!sameRule({ ...body, applies_to: ["proxy", "send"] }, body));
  assert.ok(!sameRule({ ...csp, action: "set" }, csp));
  assert.ok(!sameRule({ ...body, pattern: body.pattern + " " }, body));
});

test("the picker says whether a preset is added already", () => {
  assert.deepEqual(presetState(scripts, []), { have: "none", off: [] });
  assert.equal(presetLabel(scripts, []), "Remove all JavaScript");
  const one = [{ ...body, id: 3 }];
  assert.equal(presetLabel(scripts, one), "Remove all JavaScript (partly added)");
  const both = [...one, { ...csp, id: 7 }];
  assert.equal(presetLabel(scripts, both), "Remove all JavaScript (added)");
  const off = [...one, { ...csp, id: 7, enabled: false }];
  assert.deepEqual(presetState(scripts, off), { have: "all", off: [7] });
  assert.equal(presetLabel(scripts, off), "Remove all JavaScript (added, partly switched off)");
  const allOff = [
    { ...body, id: 3, enabled: false },
    { ...csp, id: 7, enabled: false },
  ];
  assert.equal(presetLabel(scripts, allOff), "Remove all JavaScript (added, switched off)");
});

test("adding a preset is one command, and what it did is said", () => {
  assert.deepEqual(presetArgs("remove-scripts"), ["rules", "presets", "add", "remove-scripts"]);
  const saved = [
    { ...body, id: 3 },
    { ...csp, id: 7, enabled: false },
  ];
  assert.equal(presetNote(scripts, { rules: saved, added: [3, 7], existing: [] }), "Remove all JavaScript: added 2 rules.");
  assert.equal(presetNote(scripts, { rules: saved, added: [3], existing: [7] }), "Remove all JavaScript: added 1 rule; the rest were here already; switched off: #7, which the table's On box turns on.");
  assert.equal(presetNote(scripts, { rules: saved, added: [], existing: [3] }), "Remove all JavaScript: its rules are here already.");
});
