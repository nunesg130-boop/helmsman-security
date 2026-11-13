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
