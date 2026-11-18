import test from "node:test";
import assert from "node:assert/strict";
import { classifyMatch } from "../src/images/classify.mjs";

const m = (over = {}) => ({ id: "GHSA-aaaa-bbbb-cccc", relatedCves: ["CVE-2026-1001"], severity: "High", cvss: 7.5, fixState: "fixed", fixVersions: ["1.2", "1.3"],
  pkg: { name: "openssl", version: "1.1", type: "apk", purl: "pkg:apk/openssl@1.1" }, matchType: "exact-direct-match", ...over });

test("a GHSA match joins on its related CVE and keeps the GHSA as an alias", () => {
  assert.deepEqual(classifyMatch(m()), { cve: "CVE-2026-1001", aliases: ["GHSA-aaaa-bbbb-cccc"], severity: "high", cvss: 7.5, fixState: "fix-available-not-applied", fixedVersion: "1.2", lowConfidence: false, recognised: true });
});
test("a CVE id is used directly; without any CVE the advisory id stands", () => {
  assert.equal(classifyMatch(m({ id: "CVE-2026-2", relatedCves: [] })).cve, "CVE-2026-2");
  assert.deepEqual([classifyMatch(m({ relatedCves: [] })).cve, classifyMatch(m({ relatedCves: [] })).aliases], ["GHSA-aaaa-bbbb-cccc", []]);
});
test("fix states map to the engine's vocabulary; anything unrecognised is unknown", () => {
  assert.deepEqual(["fixed", "not-fixed", "wont-fix", "unknown", "", undefined].map((s) => classifyMatch(m({ fixState: s })).fixState),
    ["fix-available-not-applied", "no-fix-exists", "no-fix-exists", "unknown", "unknown", "unknown"]);
  assert.equal(classifyMatch(m({ fixState: "fixed", fixVersions: [] })).fixedVersion, null);
  assert.equal(classifyMatch(m({ fixState: "unknown" })).recognised, false);
});
test("severities are normalised; negligible counts as low", () => {
  assert.deepEqual(["Critical", "High", "Medium", "Low", "Negligible", "Unknown", null].map((s) => classifyMatch(m({ severity: s })).severity), ["critical", "high", "medium", "low", "low", "unknown", "unknown"]);
});
test("CPE-only matches are low confidence", () => {
  assert.equal(classifyMatch(m({ matchType: "cpe-match" })).lowConfidence, true);
  assert.equal(classifyMatch(m({ matchType: "exact-indirect-match" })).lowConfidence, false);
});
