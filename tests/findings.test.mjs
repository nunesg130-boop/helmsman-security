import test from "node:test";
import assert from "node:assert/strict";
import { openDb, SCHEMA_VERSION } from "../src/db.mjs";
import { FindingStore } from "../src/vuln/findings.mjs";

const f = (cve, over = {}) => ({ assetKey: "pve:guest:100", cve, pkg: { name: "openssl", version: "3.0-1", arch: "amd64", type: "deb" }, severity: "high", cvss: 7.5, fixState: "fix-available-not-applied", fixedVersion: "3.0-2", lowConfidence: false, condition: "Package less than 3.0-2", recognisedCondition: true, detectedAt: 500, ...over });
const pick = (i) => ({ kev: i.kev, epss: i.epss, threatDataStale: i.threatDataStale });
const fresh = (tenant = "t") => new FindingStore(openDb(":memory:"), tenant);
const AGE = { now: 1005, maxFeedAgeMs: 10 };
const kevRows = (n, extra = []) => [...extra, ...Array.from({ length: n }, (_, i) => ({ cve: `CVE-K-${i}`, dateAdded: "2026-01-01", ransomware: false }))];

test("the findings tables exist from schema version 2 on", () => assert.ok(SCHEMA_VERSION >= 2));

test("replaceSource keeps first_seen for a finding that persists and drops ones that vanished", () => {
  const s = fresh();
  assert.equal(s.replaceSource("wazuh", [f("CVE-1"), f("CVE-2")], 1000), 2);
  s.replaceSource("wazuh", [f("CVE-1")], 2000);
  const { items, total } = s.list({}, { now: 2000, maxFeedAgeMs: 1 });
  assert.equal(total, 1);
  assert.deepEqual([items[0].cve, items[0].firstSeenAt, items[0].lastConfirmedAt], ["CVE-1", 1000, 2000]);
  assert.deepEqual(items[0].pkg, { name: "openssl", version: "3.0-1", arch: "amd64", type: "deb" });
});

test("replacing one source leaves another source's findings alone", () => {
  const s = fresh();
  s.replaceSource("wazuh", [f("CVE-1")], 1000);
  s.replaceSource("grype", [f("CVE-9")], 1000);
  s.replaceSource("wazuh", [], 2000);
  assert.deepEqual(s.list({}, AGE).items.map((i) => i.cve), ["CVE-9"]);
});

test("kev and epss are null and flagged stale when the feeds are missing or old", () => {
  const s = fresh();
  s.replaceSource("wazuh", [f("CVE-1")], 1000);
  assert.deepEqual(pick(s.list({}, { now: 1000, maxFeedAgeMs: 10 }).items[0]), { kev: null, epss: null, threatDataStale: true });
  s.replaceKev(kevRows(1, [{ cve: "CVE-1", dateAdded: "2026-01-01", ransomware: false }]), 1000);
  s.replaceEpss([{ cve: "CVE-1", score: 0.42, percentile: 0.9 }], 1000);
  assert.deepEqual(pick(s.list({}, AGE).items[0]), { kev: true, epss: 0.42, threatDataStale: false });
  assert.deepEqual(pick(s.list({}, { now: 2000, maxFeedAgeMs: 10 }).items[0]), { kev: null, epss: null, threatDataStale: true });
});

test("a fresh KEV feed that doesn't list the CVE reads kev:false, not null", () => {
  const s = fresh();
  s.replaceSource("wazuh", [f("CVE-1")], 1000);
  s.replaceKev(kevRows(2), 1000);
  s.replaceEpss([{ cve: "CVE-0", score: 0.1, percentile: 0.1 }], 1000);
  assert.deepEqual(pick(s.list({}, AGE).items[0]), { kev: false, epss: null, threatDataStale: false });
});

test("filters, ordering (KEV first, then CVSS) and paging", () => {
  const s = fresh();
  s.replaceSource("wazuh", [f("CVE-1", { cvss: 9.8, severity: "critical" }), f("CVE-2", { cvss: 5, severity: "medium", fixState: "no-fix-exists", fixedVersion: null }), f("CVE-3", { assetKey: "pve:guest:201" })], 1000);
  s.replaceKev(kevRows(1, [{ cve: "CVE-2", dateAdded: "2026-01-01", ransomware: true }]), 1000);
  s.replaceEpss([{ cve: "CVE-1", score: 0.5, percentile: 0.5 }], 1000);
  assert.deepEqual(s.list({}, AGE).items.map((i) => i.cve), ["CVE-2", "CVE-1", "CVE-3"]);
  assert.deepEqual(s.list({ assetKey: "pve:guest:201" }, AGE).items.map((i) => i.cve), ["CVE-3"]);
  assert.deepEqual(s.list({ kev: true }, AGE).items.map((i) => i.cve), ["CVE-2"]);
  assert.deepEqual(s.list({ fixState: "no-fix-exists" }, AGE).items.map((i) => i.cve), ["CVE-2"]);
  assert.deepEqual(s.list({ severity: "critical" }, AGE).items.map((i) => i.cve), ["CVE-1"]);
  const page = s.list({ limit: 1, offset: 1 }, AGE);
  assert.deepEqual([page.items.map((i) => i.cve), page.total], [["CVE-1"], 3]);
});

test("a kev filter with stale feeds returns nothing rather than guessing", () => {
  const s = fresh();
  s.replaceSource("wazuh", [f("CVE-1")], 1000);
  assert.equal(s.list({ kev: false }, { now: 1000, maxFeedAgeMs: 10 }).total, 0);
});

test("one tenant cannot see another tenant's findings, kev or epss", () => {
  const db = openDb(":memory:");
  const a = new FindingStore(db, "a");
  const b = new FindingStore(db, "b");
  a.replaceSource("wazuh", [f("CVE-1")], 1000);
  a.replaceKev(kevRows(1, [{ cve: "CVE-1", dateAdded: "2026-01-01", ransomware: false }]), 1000);
  assert.equal(b.list({}, AGE).total, 0);
  assert.equal(b.feed("kev"), null);
  b.replaceSource("wazuh", [f("CVE-1")], 1000);
  assert.equal(b.list({}, AGE).items[0].kev, null);
});

test("summaryByAsset counts severities, fix states and KEV per asset", () => {
  const s = fresh();
  s.replaceSource("wazuh", [
    f("CVE-1", { severity: "critical" }), f("CVE-2"), f("CVE-3", { severity: "medium", fixState: "no-fix-exists" }),
    f("CVE-4", { severity: "unknown", fixState: "unknown", recognisedCondition: false, lowConfidence: true }), f("CVE-5", { assetKey: "pve:guest:201", severity: "low" })
  ], 1000);
  s.replaceKev(kevRows(1, [{ cve: "CVE-2", dateAdded: "2026-01-01", ransomware: false }]), 1000);
  s.replaceEpss([{ cve: "CVE-1", score: 0.5, percentile: 0.5 }], 1000);
  const rows = s.summaryByAsset(AGE);
  assert.deepEqual(rows.find((r) => r.assetKey === "pve:guest:100"), { assetKey: "pve:guest:100", total: 4, critical: 1, high: 1, medium: 1, low: 0, unknownSeverity: 1, fixAvailable: 2, noFix: 1, fixUnknown: 1, kev: 1, lowConfidence: 1, unrecognisedCondition: 1, hostFindings: 4, imageFindings: 0 });
  assert.equal(s.summaryByAsset({ now: 5000, maxFeedAgeMs: 10 })[0].kev, null);
});

test("a failed replaceEpss (bad row) leaves the previous table intact", () => {
  const s = fresh();
  s.replaceEpss([{ cve: "CVE-1", score: 0.42, percentile: 0.9 }], 1000);
  assert.throws(() => s.replaceEpss([{ cve: "CVE-2", score: 0.1, percentile: 0.1 }, { cve: null, score: 0.1, percentile: 0.1 }], 2000));
  assert.deepEqual(s.feed("epss"), { fetchedAt: 1000, count: 1 });
  s.replaceSource("wazuh", [f("CVE-1")], 1000);
  s.replaceKev(kevRows(1), 1000);
  assert.equal(s.list({}, AGE).items[0].epss, 0.42);
});
