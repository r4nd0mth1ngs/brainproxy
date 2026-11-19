import { test } from "node:test";
import assert from "node:assert/strict";
import { BASE_PICKER, cvssCommand, extraMetrics, METRICS, metricsOf, START_VECTOR, vectorOf, vectorProblem, withMetric } from "./cvss.ts";

const FULL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

test("a whole base vector, or nothing, is taken", () => {
  assert.equal(vectorProblem(FULL), "");
  assert.equal(vectorProblem(`  ${FULL}  `), "");
  assert.equal(vectorProblem(""), "");
  assert.equal(vectorProblem("   "), "");
  assert.equal(vectorProblem(START_VECTOR), "");
  // Threat and environmental metrics, in any order, X included.
  assert.equal(vectorProblem(`${FULL}/E:P/MAV:X/U:Amber/CR:H`), "");
  assert.equal(vectorProblem("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N"), "");
});

test("each refusal says what the CLI would say", () => {
  assert.match(vectorProblem("AV:N/AC:L"), /starts with CVSS:4\.0\//);
  assert.match(vectorProblem("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), /CVSS 3/);
  assert.equal(vectorProblem(FULL.replace("/SA:N", "")), "The base metric SA is missing");
  assert.equal(vectorProblem(`${FULL}/`), '"" is not METRIC:VALUE');
  assert.equal(vectorProblem(`${FULL}/XX:Y`), "Unknown metric XX");
  assert.equal(vectorProblem(FULL.replace("AV:N", "AV:Q")), "AV takes N, A, L, P, not Q");
  assert.equal(vectorProblem(`${FULL}/AV:L`), "AV is given twice");
  // Values are case-sensitive, as in the CLI.
  assert.equal(vectorProblem(FULL.replace("AV:N", "AV:n")), "AV takes N, A, L, P, not n");
  assert.equal(vectorProblem(FULL.replace("CVSS:4.0", "cvss:4.0")), "A CVSS 4.0 vector starts with CVSS:4.0/");
});

test("the picker reads the well-formed metrics of a vector being typed", () => {
  const m = metricsOf("CVSS:4.0/AV:L/AC:Q/PR:H/junk/");
  assert.deepEqual([...m], [["AV", "L"], ["PR", "H"]]);
  assert.equal(metricsOf("not a vector").size, 0);
  // The first of a metric given twice, as the vector reads.
  assert.equal(metricsOf(`${FULL}/AV:P`).get("AV"), "N");
});

test("vectors come out in the specification's order, without X", () => {
  const m = new Map([["SA", "N"], ["E", "X"], ["AV", "P"], ["U", "Red"]]);
  assert.equal(vectorOf(m), "CVSS:4.0/AV:P/SA:N/U:Red");
});

test("picking a metric keeps the others and fills in missing base metrics", () => {
  assert.equal(withMetric("", "VC", "H"), START_VECTOR.replace("VC:N", "VC:H"));
  assert.equal(withMetric(`${FULL}/E:P`, "AV", "L"), FULL.replace("AV:N", "AV:L") + "/E:P");
  assert.equal(vectorProblem(withMetric("CVSS:4.0/AV:A", "UI", "P")), "");
  assert.equal(withMetric("CVSS:4.0/AV:A", "UI", "P"), "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
});

test("metrics beyond the base ones are listed, so the dialog says the picker keeps them", () => {
  assert.deepEqual(extraMetrics(`${FULL}/E:P/MAV:X/CR:H`), ["E:P", "CR:H"]);
  assert.deepEqual(extraMetrics(FULL), []);
});

test("the picker offers each base metric with the values the CLI takes", () => {
  assert.deepEqual(
    BASE_PICKER.map((p) => p.metric),
    METRICS.slice(0, 11).map(([m]) => m),
  );
  for (const p of BASE_PICKER) {
    const values = METRICS.find(([m]) => m === p.metric)![1];
    assert.deepEqual(p.values.map(([v]) => v).sort(), [...values].sort(), p.metric);
  }
});

test("the CVSS command passes the vector after --, trimmed; empty removes the rating", () => {
  assert.deepEqual(cvssCommand(4, ` ${FULL} `), ["findings", "issue", "cvss", "4", "--", FULL]);
  assert.deepEqual(cvssCommand(4, ""), ["findings", "issue", "cvss", "4", "--", ""]);
});
