import test from "node:test";
import assert from "node:assert/strict";
import { fixStateFromCondition, normaliseSeverity, isLowConfidence } from "../src/vuln/classify.mjs";

test("'Package less than X' means a fix exists in X", () =>
  assert.deepEqual(fixStateFromCondition("Package less than 6.12.100-1"), { fixState: "fix-available-not-applied", fixedVersion: "6.12.100-1", recognised: true }));
test("'Package default status' means no fix exists", () =>
  assert.deepEqual(fixStateFromCondition("Package default status"), { fixState: "no-fix-exists", fixedVersion: null, recognised: true }));
for (const c of ["Package less than or equal to 1.2", "", null, "something new", "Package less than 1.0 or more"]) {
  test(`condition '${c}' is unknown and unrecognised`, () =>
    assert.deepEqual(fixStateFromCondition(c), { fixState: "unknown", fixedVersion: null, recognised: false }));
}
test("severity is normalised; odd values are unknown", () =>
  assert.deepEqual(["Critical", "HIGH", "medium", "Low", "-", "", undefined].map(normaliseSeverity), ["critical", "high", "medium", "low", "unknown", "unknown", "unknown"]));
test("vendor-tracker matches are confident; NVD, under-evaluation and missing source are not", () =>
  assert.deepEqual([{ source: "Debian Security Tracker" }, { source: "National Vulnerability Database" }, { source: "Canonical Security Tracker", underEvaluation: true }, {}].map(isLowConfidence), [false, true, true, true]));
