import test from "node:test";
import assert from "node:assert/strict";
import { annotateFindings, acceptanceContext, readExposureMap, currentFindingContext } from "../src/vuln/annotate.mjs";
import { HoldStore } from "../src/holds.mjs";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { FindingStore } from "../src/vuln/findings.mjs";
import { memoryStore, putOk } from "./helpers/stores.mjs";

const NOW = 50_000_000;
const FIX = "fix-available-not-applied";
const MAP = {
  services: [{ hostname: "jellyprox.jellofin.com", path: null, gate: "none", upstream: "192.168.0.7:8096", assetKey: "pve:guest:100", process: "jellyfin", exposure: "internet" }],
  machines: [{ assetKey: "pve:guest:100", name: "Jelly-Arr", exposure: "internet", role: "app", services: [0] }, { assetKey: "pve:guest:110", name: "pihole", exposure: "lan", role: null, services: [] }],
  problems: [], sources: { caddy: "ok", cloudflare: "ok", router: "declared" }
};
const finding = (extra = {}) => ({ assetKey: "pve:guest:100", cve: "CVE-2026-0001", pkg: { name: "jellyfin", version: "10.9" }, severity: "high", fixState: FIX, lowConfidence: false, kev: false, ...extra });
const holds = () => new HoldStore(openDb(":memory:"), "default");

test("findings gain exposure, urgency and acceptance fields", () => {
  const [a] = annotateFindings([finding()], { map: MAP, holds: holds(), now: NOW });
  assert.deepEqual([a.exposure, a.exposureBasis, a.possibleExposure, a.gate, a.via, a.urgent, a.possiblyUrgent, a.accepted], ["host", "route", "service", "none", "jellyprox.jellofin.com", false, true, null]);
  assert.equal(typeof a.urgencyWhy, "string");
  assert.equal(annotateFindings([finding({ assetKey: "pve:guest:110", kev: true })], { map: MAP, holds: holds(), now: NOW })[0].urgent, false);
});
test("without an exposure map every finding's exposure and urgency are unknown, never 'not urgent'", () => {
  const [a] = annotateFindings([finding({ kev: true })], { map: null, holds: holds(), now: NOW });
  assert.deepEqual([a.exposure, a.exposureBasis, a.urgent, a.possiblyUrgent], ["unknown", "unknown", null, true]);
});
test("a machine the map doesn't know is unknown", () => {
  assert.equal(annotateFindings([finding({ assetKey: "wazuh:agent:099" })], { map: MAP, holds: holds(), now: NOW })[0].exposure, "unknown");
});
test("an accepted finding is marked and not urgent; the acceptance stops when exposure rises", () => {
  const h = holds();
  const kernel = finding({ pkg: { name: "openssl", version: "3.0" }, kev: true });
  const [before] = annotateFindings([kernel], { map: MAP, holds: h, now: NOW });
  assert.equal(before.urgent, true);
  const id = h.add({ kind: "acceptance", assetKey: kernel.assetKey, checkId: kernel.cve, product: "openssl", version: "3.0", reason: "isolated", context: acceptanceContext(before) }, NOW);
  const [after] = annotateFindings([kernel], { map: MAP, holds: h, now: NOW });
  assert.deepEqual([after.accepted, after.urgent, after.possiblyUrgent], [{ id, reason: "isolated" }, false, false]);
  const entry = { ...MAP, machines: [{ ...MAP.machines[0], role: "gate" }] };
  assert.equal(annotateFindings([kernel], { map: entry, holds: h, now: NOW })[0].accepted, null, "host → service ends it");
  assert.equal(annotateFindings([kernel], { map: null, holds: h, now: NOW })[0].accepted, null, "unknown exposure ends it");
});
test("the acceptance context records the worst reading: a possible 'service' counts as service", () => {
  const [a] = annotateFindings([finding()], { map: MAP, holds: holds(), now: NOW });
  assert.deepEqual(acceptanceContext(a), { kev: false, exposure: "service", gate: "none" });
  const [plain] = annotateFindings([finding({ pkg: { name: "openssl", version: "3" } })], { map: MAP, holds: holds(), now: NOW });
  assert.deepEqual(acceptanceContext(plain), { kev: false, exposure: "host", gate: null });
});
test("readExposureMap gives the map only while fresh and after a successful run", () => {
  const s = memoryStore();
  assert.deepEqual(readExposureMap(s, NOW), { map: null, status: "missing" });
  putOk(s, "exposure", [{ assetKey: "_global", kind: "exposure.map", value: MAP }], NOW);
  assert.equal(readExposureMap(s, NOW).status, "ok");
  assert.equal(readExposureMap(s, NOW).map.services.length, 1);
  assert.deepEqual(readExposureMap(s, NOW + 3 * 3600_000), { map: null, status: "stale" });
  const id = s.beginRun("exposure", NOW); s.finishRun(id, "failed", { error: "x" }, NOW);
  assert.deepEqual(readExposureMap(s, NOW), { map: null, status: "failed" });
});

test("currentFindingContext reads a stored finding's situation, or null when there is no such finding", () => {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const findings = new FindingStore(db, "default");
  const h = new HoldStore(db, "default");
  findings.replaceSource("wazuh", [{ assetKey: "pve:guest:100", cve: "CVE-2026-0001", pkg: { name: "jellyfin", version: "10.9", arch: "amd64" }, severity: "high", fixState: FIX }], NOW);
  findings.replaceKev([{ cve: "CVE-2026-0001" }], NOW);
  putOk(store, "exposure", [{ assetKey: "_global", kind: "exposure.map", value: MAP }], NOW);
  const ctx = (q) => currentFindingContext(q, { findings, store, holds: h, now: NOW, maxFeedAgeMs: 86400_000 });
  assert.deepEqual(ctx({ assetKey: "pve:guest:100", cve: "CVE-2026-0001", pkg: "jellyfin", version: "10.9" }), { kev: true, exposure: "service", gate: "none" });
  assert.equal(ctx({ assetKey: "pve:guest:100", cve: "CVE-2026-0001", pkg: "jellyfin", version: "11" }), null);
  assert.equal(ctx({ assetKey: "pve:guest:100", cve: "CVE-2026-0002", pkg: "jellyfin", version: "10.9" }), null);
  assert.equal(ctx({ assetKey: "pve:guest:101", cve: "CVE-2026-0001", pkg: "jellyfin", version: "10.9" }), null);
});
