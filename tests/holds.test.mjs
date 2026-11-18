import test from "node:test";
import assert from "node:assert/strict";
import { openDb } from "../src/db.mjs";
import { HoldStore } from "../src/holds.mjs";

const NOW = 1_000_000;
const fresh = () => openDb(":memory:");

test("hold matches only the exact version", () => {
  const h = new HoldStore(fresh(), "t");
  h.add({ kind: "hold", assetKey: "pve:guest:109", product: "debian", version: "11.8", reason: "migrating" }, NOW);
  assert.equal(h.activeHold("pve:guest:109", "debian", "11.8", NOW).reason, "migrating");
  assert.equal(h.activeHold("pve:guest:109", "debian", "11.9", NOW), null);
  assert.equal(h.activeHold("pve:guest:110", "debian", "11.8", NOW), null);
});

test("expired hold is inactive but still listed", () => {
  const h = new HoldStore(fresh(), "t");
  h.add({ kind: "hold", assetKey: "a", product: "p", version: "1", reason: "r", expiresAt: NOW - 1 }, NOW - 100);
  assert.equal(h.activeHold("a", "p", "1", NOW), null);
  assert.equal(h.list(NOW)[0].expired, true);
});

test("exclusion applies to one check on one asset", () => {
  const h = new HoldStore(fresh(), "t");
  const id = h.add({ kind: "exclusion", assetKey: "pve:guest:152", checkId: "backup_jobs", reason: "intentionally not backed up" }, NOW);
  assert.equal(h.activeExclusion("pve:guest:152", "backup_jobs", NOW).reason, "intentionally not backed up");
  assert.equal(h.activeExclusion("pve:guest:152", "disk_health", NOW), null);
  h.remove(id);
  assert.equal(h.activeExclusion("pve:guest:152", "backup_jobs", NOW), null);
});

test("reason is required", () => {
  const h = new HoldStore(fresh(), "t");
  assert.throws(() => h.add({ kind: "exclusion", assetKey: "a", checkId: "c", reason: "  " }, NOW), TypeError);
});

test("an exclusion needs a check id and a hold needs product and version", () => {
  const h = new HoldStore(fresh(), "t");
  assert.throws(() => h.add({ kind: "exclusion", assetKey: "a", reason: "r" }, NOW), TypeError);
  assert.throws(() => h.add({ kind: "hold", assetKey: "a", product: "p", reason: "r" }, NOW), TypeError);
});

test("tenant isolation", () => {
  const db = fresh();
  new HoldStore(db, "a").add({ kind: "exclusion", assetKey: "x", checkId: "c", reason: "r" }, NOW);
  assert.equal(new HoldStore(db, "b").activeExclusion("x", "c", NOW), null);
  assert.equal(new HoldStore(db, "b").list(NOW).length, 0);
});

test("a whole-machine exclusion (check '*') applies to every check on that asset only", () => {
  const h = new HoldStore(fresh(), "t");
  h.add({ kind: "exclusion", assetKey: "pve:guest:300", checkId: "*", reason: "test VM" }, NOW);
  assert.equal(h.activeExclusion("pve:guest:300", "agent_present", NOW).reason, "test VM");
  assert.equal(h.activeExclusion("pve:guest:300", "os_eol", NOW).reason, "test VM");
  assert.equal(h.activeExclusion("pve:guest:301", "agent_present", NOW), null);
});

test("a per-check exclusion's reason wins over a whole-machine one", () => {
  const h = new HoldStore(fresh(), "t");
  h.add({ kind: "exclusion", assetKey: "a", checkId: "*", reason: "appliance" }, NOW);
  h.add({ kind: "exclusion", assetKey: "a", checkId: "backup_jobs", reason: "backed up by HA itself" }, NOW);
  assert.equal(h.activeExclusion("a", "backup_jobs", NOW).reason, "backed up by HA itself");
  assert.equal(h.activeExclusion("a", "os_eol", NOW).reason, "appliance");
});

test("an expired whole-machine exclusion stops applying", () => {
  const h = new HoldStore(fresh(), "t");
  h.add({ kind: "exclusion", assetKey: "a", checkId: "*", reason: "r", expiresAt: NOW - 1 }, NOW - 100);
  assert.equal(h.activeExclusion("a", "os_eol", NOW), null);
});

const store = () => new HoldStore(fresh(), "default");
const CVE = "CVE-2026-0001";
const acceptance = (h, context = { kev: false, exposure: "host", gate: "authentik" }, extra = {}) =>
  h.add({ kind: "acceptance", assetKey: "pve:guest:100", checkId: CVE, product: "jellyfin", version: "10.9", reason: "patch window Friday", context, ...extra }, NOW);
const accepted = (h, ctx = {}, { version = "10.9", pkg = "jellyfin", cve = CVE, asset = "pve:guest:100", now = NOW } = {}) =>
  h.activeAcceptance(asset, cve, pkg, version, { kev: false, exposure: "host", gate: "authentik", ...ctx }, now);

test("an acceptance matches exactly one asset, CVE, package and version", () => {
  const h = store();
  const id = acceptance(h);
  assert.deepEqual(accepted(h), { id, reason: "patch window Friday" });
  assert.equal(accepted(h, {}, { version: "10.10" }), null, "a new version is a new decision");
  assert.equal(accepted(h, {}, { pkg: "jellyfin-web" }), null);
  assert.equal(accepted(h, {}, { cve: "CVE-2026-0002" }), null);
  assert.equal(accepted(h, {}, { asset: "pve:guest:101" }), null);
});
test("an acceptance ends when the finding becomes known-exploited, or when that can't be told", () => {
  const h = store();
  acceptance(h);
  assert.equal(accepted(h, { kev: true }), null);
  assert.equal(accepted(h, { kev: null }), null, "an out-of-date KEV list is read as the less safe case");
  const known = store();
  acceptance(known, { kev: true, exposure: "host", gate: null });
  assert.ok(accepted(known, { kev: true, gate: null }), "accepted while already known-exploited");
  assert.ok(accepted(known, { kev: null, gate: null }));
});
test("an acceptance ends when exposure rises, not when it falls", () => {
  const h = store();
  acceptance(h, { kev: false, exposure: "gated", gate: "authentik" });
  assert.ok(accepted(h, { exposure: "gated" }));
  assert.ok(accepted(h, { exposure: "none" }));
  for (const exposure of ["host", "service", "unknown"]) assert.equal(accepted(h, { exposure }), null, exposure);
  const lan = store();
  acceptance(lan, { kev: false, exposure: "none", gate: null });
  assert.equal(accepted(lan, { exposure: "gated", gate: "authentik" }), null);
});
test("an acceptance ends when a verified gate becomes none or unknown, e.g. a new ungated entry path", () => {
  const h = store();
  acceptance(h, { kev: false, exposure: "service", gate: "verified-mixed" });
  assert.ok(accepted(h, { exposure: "service", gate: "authentik" }), "still verified");
  assert.equal(accepted(h, { exposure: "service", gate: "unknown" }), null);
  assert.equal(accepted(h, { exposure: "service", gate: "none" }), null);
  const open = store();
  acceptance(open, { kev: false, exposure: "service", gate: "none" });
  assert.ok(accepted(open, { exposure: "service", gate: "none" }), "accepted with no gate: nothing to lose");
});
test("an expired acceptance stops applying but stays listed with its context", () => {
  const h = store();
  acceptance(h, undefined, { expiresAt: NOW + 1000 });
  assert.ok(accepted(h));
  assert.equal(accepted(h, {}, { now: NOW + 2000 }), null);
  const [row] = h.list(NOW + 2000);
  assert.deepEqual([row.kind, row.checkId, row.product, row.version, row.expired, row.context], ["acceptance", CVE, "jellyfin", "10.9", true, { kev: false, exposure: "host", gate: "authentik" }]);
});
test("an acceptance needs a CVE, package, version, reason and a complete context", () => {
  const h = store();
  const base = { kind: "acceptance", assetKey: "a", checkId: CVE, product: "p", version: "1", reason: "r", context: { kev: false, exposure: "host", gate: null } };
  assert.ok(h.add(base, NOW));
  for (const broken of [{ checkId: null }, { product: null }, { version: null }, { reason: " " }, { context: null }, { context: { kev: false } }, { context: { kev: "no", exposure: "host", gate: null } }, { context: { kev: false, exposure: "everywhere", gate: null } }]) {
    assert.throws(() => h.add({ ...base, ...broken }, NOW), TypeError, JSON.stringify(broken));
  }
});
test("acceptanceLookup answers many findings from one read", () => {
  const h = store();
  acceptance(h);
  const lookup = h.acceptanceLookup(NOW);
  assert.ok(lookup("pve:guest:100", CVE, "jellyfin", "10.9", { kev: false, exposure: "host", gate: "authentik" }));
  assert.equal(lookup("pve:guest:100", CVE, "jellyfin", "10.9", { kev: true, exposure: "host", gate: "authentik" }), null);
});
