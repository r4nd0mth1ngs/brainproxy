import { test } from "node:test";
import assert from "node:assert/strict";
import { canFilter, filterAddArgs, filterAddedNote, filterDraftFor, filterDraftProblem, filterRating, filterRemoveArgs, filterRemovedNote, filtersSummary, filterWhere, type FilterDraft } from "./alertFilter.ts";
import { ratedLine, ratedTitle, ratingOf } from "./findingRating.ts";

const finding = { alert_ref: "10038", host: "app.test", url: "https://app.test/static/app.js?v=3", param: "" };

test("a filter starts from the finding, with no rating picked yet", () => {
  assert.deepEqual(filterDraftFor(finding), {
    alert: "10038",
    host: "app.test:443",
    pathPrefix: "/static/app.js",
    urlRegex: "",
    param: "",
    paramRegex: "",
    risk: "",
    confidence: "",
    reason: "",
  });
  // The path as the CLI matches it, and the parameter.
  const d = filterDraftFor({ ...finding, url: "http://127.0.0.1:3000/a;jsessionid=1/b?q=1", host: "127.0.0.1", param: "q" });
  assert.deepEqual([d.host, d.pathPrefix, d.param], ["127.0.0.1:3000", "/a/b", "q"]);
});

const ready: FilterDraft = { ...filterDraftFor(finding), risk: "info", reason: "served by the CDN" };

test("a draft says what it still needs before the CLI is asked", () => {
  assert.equal(filterDraftProblem(ready), null);
  // Any host, and a confidence alone, are fine.
  assert.equal(filterDraftProblem({ ...ready, host: " ", risk: "", confidence: "low" }), null);
  assert.match(filterDraftProblem({ ...ready, risk: "" })!, /risk and\/or confidence/);
  assert.match(filterDraftProblem({ ...ready, reason: " " })!, /reason/);
  assert.match(filterDraftProblem({ ...ready, alert: "" })!, /alert/);
  assert.match(filterDraftProblem({ ...ready, host: "app.test/x" })!, /host/);
  assert.match(filterDraftProblem({ ...ready, pathPrefix: "static" })!, /starts with \//);
  assert.match(filterDraftProblem({ ...ready, pathPrefix: "/a?x=1" })!, /URL regex/);
  assert.match(filterDraftProblem({ ...ready, urlRegex: "a".repeat(1001) })!, /1000/);
});

test("the CLI gets each part given as --flag=value, and nothing for what matches any", () => {
  assert.deepEqual(filterAddArgs({ ...ready, host: "", pathPrefix: "" }), ["findings", "filter", "add", "--alert=10038", "--risk=info", "--reason=served by the CDN"]);
  assert.deepEqual(
    filterAddArgs({ ...ready, pathPrefix: "/café/", urlRegex: " -\\.js$ ", param: " id ", paramRegex: "^x-", confidence: "low", reason: " -internal " }),
    [
      "findings",
      "filter",
      "add",
      "--alert=10038",
      "--host=app.test:443",
      "--path-prefix=/caf%C3%A9/",
      "--url-regex=-\\.js$",
      "--param=id",
      "--param-regex=^x-",
      "--risk=info",
      "--confidence=low",
      "--reason=-internal",
    ],
  );
  assert.deepEqual(filterRemoveArgs(4, false), ["findings", "filter", "remove", "4"]);
  assert.deepEqual(filterRemoveArgs(4, true), ["findings", "filter", "remove", "4", "--unrate"]);
});

test("the list says where each filter applies and what it gives", () => {
  const f = { host: null, port: null, path_prefix: "", url_regex: null, param: null, param_regex: null };
  assert.equal(filterWhere(f), "any host");
  assert.equal(filterWhere({ ...f, path_prefix: "/static/", url_regex: "\\.js$" }), "any host, /static/ · URL ~ \\.js$");
  assert.equal(filterWhere({ ...f, host: "app.test", port: 8443, param: "id", param_regex: "^x" }), "app.test:8443 · parameter id · parameter ~ ^x");
  assert.equal(filterWhere({ ...f, host: "::1", port: 3000 }), "[::1]:3000");
  assert.equal(filterRating({ risk: "info", confidence: null }), "risk info");
  assert.equal(filterRating({ risk: "high", confidence: "low" }), "risk high, confidence low");
  assert.equal(filterRating({ risk: null, confidence: "low" }), "confidence low");
  assert.match(filtersSummary([]), /^No alert filters yet/);
  assert.match(filtersSummary([{ holds: 2 }, { holds: 1 }]), /^3 findings have a rating from these filters/);
  assert.match(filtersSummary([{ holds: 1 }]), /^1 finding has a rating/);
});

test("adding and removing say what happened, and why the finding it came from kept its rating", () => {
  assert.equal(filterAddedNote(2, 3), "Alert filter 2 added: it re-rated 3 findings.");
  assert.match(filterAddedNote(2, 0), /^Alert filter 2 added\. No open finding nobody rated matched it yet/);
  assert.equal(filterAddedNote(2, 1, { id: 7, state: "open", rated_origin: "cli", rated_by: 2 }), "Alert filter 2 added: it re-rated 1 finding.");
  assert.match(filterAddedNote(2, 0, { id: 7, state: "open", rated_origin: "gui", rated_by: null }), /#7 keeps its rating: it has a person's rating/);
  assert.match(filterAddedNote(2, 0, { id: 7, state: "open", rated_origin: "gui", rated_by: 1 }), /filter 1 rated it first/);
  assert.match(filterAddedNote(2, 0, { id: 7, state: "accepted_risk" }), /it is accepted risk/);
  assert.match(filterAddedNote(2, 0, { id: 7, state: "open" }), /doesn't match it/);
  assert.equal(filterRemovedNote(3, 2, true, 2), "Alert filter 3 removed: 2 findings have the scanner's rating again.");
  assert.equal(filterRemovedNote(3, 1, true, 1), "Alert filter 3 removed: 1 finding has the scanner's rating again.");
  assert.equal(filterRemovedNote(3, 0, false, 0), "Alert filter 3 removed.");
  assert.equal(filterRemovedNote(3, 0, false, 1), "Alert filter 3 removed. The finding it rated keeps its rating.");
  assert.equal(filterRemovedNote(3, 0, false, 4), "Alert filter 3 removed. The 4 findings it rated keep its rating.");
});

test("a finding a filter rated says which filter, in the detail and the list", () => {
  const shown = { rated_origin: "cli", rated_reason: "internal", rated_at: null, scanner_risk: "medium" as const, scanner_confidence: "high", rated_by: 5 };
  const r = ratingOf(shown)!;
  assert.equal(r.filter, 5);
  assert.equal(ratedLine(r), "Rated by filter 5 (added by a person from the command line): internal. The scanner said medium risk, high confidence.");
  assert.equal(ratedTitle({ risk: "info", confidence: "high" }, r), "Rated info risk, high confidence by filter 5; the scanner said medium risk, high confidence. internal");
  // A person's own rating has no filter.
  assert.equal(ratingOf({ ...shown, rated_by: null })!.filter, undefined);
  assert.match(ratedLine({ ...r, filter: null }), /^Rated by a person/);
  assert.equal(canFilter({ source: "passive", state: "open" }), true);
  assert.equal(canFilter({ source: "manual", state: "open" }), false);
  assert.equal(canFilter({ source: "active", state: "removed" }), false);
});
