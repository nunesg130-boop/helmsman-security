import test from "node:test";
import assert from "node:assert/strict";
import { postureScore, SCORE_RULES } from "../src/vuln/score.mjs";

const FIX = "fix-available-not-applied";
let n = 0;
const f = (extra = {}) => ({ assetKey: "a1", cve: `CVE-2026-${String(++n).padStart(4, "0")}`, pkg: { name: "p", version: "1" }, severity: "high", fixState: FIX, lowConfidence: false, accepted: null,
  urgent: false, possiblyUrgent: false, exposure: "host", possibleExposure: null, gate: null, ...extra });
const OK = { findingsStale: false, kevStale: false, exposureStatus: "ok" };
const COVER = { inScope: 22, withoutFreshCoverage: 0 };
const score = (findings, { coverage = COVER, freshness = OK } = {}) => postureScore({ findings, coverage, freshness });

test("rules are versioned and a clean lab scores 100 in both scenarios", () => {
  assert.equal(SCORE_RULES, 1);
  const s = score([]);
  assert.deepEqual([s.version, s.state, s.confirmed, s.pessimistic, s.incompleteReasons, s.deductions], [1, "scored", 100, 100, [], []]);
});
test("weights: urgent 10, high or critical with a fix 3, medium with a fix 0.5, everything else 0", () => {
  assert.equal(score([f({ urgent: true })]).confirmed, 90);
  assert.equal(score([f()]).confirmed, 97);
  assert.equal(score([f({ severity: "critical" })]).confirmed, 97);
  assert.equal(score([f({ severity: "medium" })]).confirmed, 99.5);
  assert.equal(score([f({ severity: "low" })]).confirmed, 100);
  assert.equal(score([f({ fixState: "no-fix-exists" })]).confirmed, 100);
  assert.equal(score([f({ severity: "medium", fixState: "unknown" })]).confirmed, 100);
});
test("accepted and low-confidence findings count in neither scenario", () => {
  const s = score([f({ urgent: true, accepted: { id: 1, reason: "r" } }), f({ lowConfidence: true, possiblyUrgent: true })]);
  assert.deepEqual([s.confirmed, s.pessimistic], [100, 100]);
});
test("a finding costing 3 that is possibly urgent lowers the pessimistic score by exactly 7 more", () => {
  const s = score([f({ possiblyUrgent: true })]);
  assert.deepEqual([s.confirmed, s.pessimistic], [97, 90]);
  assert.deepEqual(s.deductions.map((d) => [d.scenario, d.points]), [["pessimistic", 7], ["confirmed", 3]]);
});
test("unknown urgency and heuristic-only exposure affect only the pessimistic score", () => {
  assert.deepEqual([score([f({ urgent: null, severity: "low" })]).confirmed, score([f({ urgent: null, severity: "low" })]).pessimistic], [100, 90]);
  assert.deepEqual([score([f({ possiblyUrgent: true, possibleExposure: "service", severity: "low" })]).confirmed, score([f({ possiblyUrgent: true, possibleExposure: "service", severity: "low" })]).pessimistic], [100, 90]);
});
test("the per-asset cap of 25 applies to both scenarios, and the floor is 0", () => {
  const many = Array.from({ length: 6 }, () => f({ urgent: true }));
  assert.deepEqual([score(many).confirmed, score(many).pessimistic], [75, 75]);
  const possible = Array.from({ length: 6 }, () => f({ possiblyUrgent: true }));
  assert.deepEqual([score(possible).confirmed, score(possible).pessimistic], [82, 75]);
  const two = [...many, ...Array.from({ length: 6 }, () => f({ urgent: true, assetKey: "a2" }))];
  assert.equal(score(two).confirmed, 50);
  const everywhere = Array.from({ length: 30 }, (_, i) => f({ urgent: true, assetKey: `m${i % 6}` }));
  assert.equal(score(everywhere).confirmed, 0);
});
test("pessimistic is never above confirmed", () => {
  const mix = [f({ urgent: true }), f({ possiblyUrgent: true }), f({ urgent: null }), f({ severity: "medium" }), f({ assetKey: "a2", possiblyUrgent: true, severity: "low" })];
  const s = score(mix);
  assert.ok(s.pessimistic <= s.confirmed, JSON.stringify(s));
  assert.deepEqual([s.confirmed, s.pessimistic], [83.5, 65]);
});
test("the result doesn't depend on input order", () => {
  const mix = [f({ urgent: true }), f({ possiblyUrgent: true }), f({ assetKey: "a2" }), f({ assetKey: "a3", severity: "medium" }), f({ assetKey: "a2", urgent: null })];
  assert.deepEqual(score([...mix].reverse()), score(mix));
});
test("deductions are grouped by asset, scenario and reason, largest first, each listing its CVEs", () => {
  const s = score([f({ assetKey: "b", cve: "CVE-1" }), f({ assetKey: "b", cve: "CVE-2" }), f({ assetKey: "a", cve: "CVE-3", urgent: true }), f({ assetKey: "a", cve: "CVE-4", severity: "medium" })]);
  assert.deepEqual(s.deductions, [
    { assetKey: "a", scenario: "confirmed", reason: "urgent", points: 10, cves: ["CVE-3"], findings: 1 },
    { assetKey: "b", scenario: "confirmed", reason: "high or critical, fix available", points: 6, cves: ["CVE-1", "CVE-2"], findings: 2 },
    { assetKey: "a", scenario: "confirmed", reason: "medium, fix available", points: 0.5, cves: ["CVE-4"], findings: 1 }
  ]);
});
test("a long CVE list is cut to 20 with the full count kept", () => {
  const s = score(Array.from({ length: 30 }, () => f()));
  assert.deepEqual([s.deductions[0].cves.length, s.deductions[0].findings, s.deductions[0].points], [20, 30, 90]);
});
test("each incomplete condition alone gives no numbers, with its reason", () => {
  const cases = [
    [{ freshness: { ...OK, findingsStale: true } }, /vulnerability findings/u],
    [{ freshness: { ...OK, kevStale: true } }, /KEV/u],
    [{ freshness: { ...OK, exposureStatus: "missing" } }, /exposure map is missing/u],
    [{ freshness: { ...OK, exposureStatus: "failed" } }, /exposure map is failed/u],
    [{ freshness: { ...OK, exposureStatus: "stale" } }, /exposure map is stale/u],
    [{ coverage: { inScope: 22, withoutFreshCoverage: 5 } }, /5 of 22 machines \(22\.7 %\)/u],
    [{ coverage: { inScope: 0, withoutFreshCoverage: 0 } }, /no machines/u]
  ];
  for (const [opts, reason] of cases) {
    const s = score([f({ urgent: true })], opts);
    assert.deepEqual([s.state, s.confirmed, s.pessimistic, s.incompleteReasons.length], ["incomplete", null, null, 1], JSON.stringify(opts));
    assert.match(s.incompleteReasons[0], reason);
  }
  const both = score([], { freshness: { findingsStale: true, kevStale: true, exposureStatus: "ok" } });
  assert.equal(both.incompleteReasons.length, 2);
});
test("1 uncovered machine of 22 is scored; 5 of 22 is incomplete; exactly 20 % is scored", () => {
  assert.equal(score([], { coverage: { inScope: 22, withoutFreshCoverage: 1 } }).state, "scored");
  assert.equal(score([], { coverage: { inScope: 22, withoutFreshCoverage: 5 } }).state, "incomplete");
  assert.equal(score([], { coverage: { inScope: 20, withoutFreshCoverage: 4 } }).state, "scored");
  assert.deepEqual(score([], { coverage: { inScope: 22, withoutFreshCoverage: 1 } }).coverage, { inScope: 22, withoutFreshCoverage: 1 });
});
test("what is uncertain is counted", () => {
  const s = score([f({ urgent: null, exposure: "unknown" }), f({ gate: "unknown", possibleExposure: "service", possiblyUrgent: true }), f({ possibleExposure: "gated" }), f({ urgent: null, lowConfidence: true })]);
  assert.deepEqual(s.unknowns, { urgencyUnknown: 1, exposureUnknown: 1, gateUnknown: 1, heuristic: 2 });
});
