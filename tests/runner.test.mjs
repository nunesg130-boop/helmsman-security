import test from "node:test";
import assert from "node:assert/strict";
import { runCheck, evidenceKey, formatAge } from "../src/checks/runner.mjs";
import { result } from "../src/states.mjs";
import { memoryStore, putOk, noHolds } from "./helpers/stores.mjs";

const NOW = 10_000_000;
const host = { assetKey: "pve:node:norco", class: "host", name: "norco", sources: { pve: { node: "norco" }, wazuh: { id: "001" } } };
const alwaysOk = { id: "t", title: "T", requires: ["pve.time"], appliesTo: () => true, evaluate: () => result("ok", "fine") };
const ctx = (store, extra = {}) => ({ store, holds: noHolds, config: {}, now: NOW, ...extra });

test("evidenceKey routes wazuh kinds to the linked agent", () => {
  assert.equal(evidenceKey(host, "wazuh.os"), "wazuh:agent:001");
  assert.equal(evidenceKey(host, "pve.time"), "pve:node:norco");
  assert.equal(evidenceKey({ ...host, sources: {} }, "wazuh.os"), null);
});

test("not applicable comes first", () => {
  const r = runCheck({ ...alwaysOk, appliesTo: () => false }, host, ctx(memoryStore()));
  assert.equal(r.state, "not_applicable");
  assert.match(r.reason, /host/u);
});

test("an active exclusion gives excluded with its reason", () => {
  const holds = { ...noHolds, activeExclusion: () => ({ reason: "intentionally not backed up" }) };
  const r = runCheck(alwaysOk, host, ctx(memoryStore(), { holds }));
  assert.deepEqual([r.state, r.reason], ["excluded", "intentionally not backed up"]);
});

test("evaluate cannot return ok when a required kind is missing", () => {
  const r = runCheck(alwaysOk, host, ctx(memoryStore()));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /no pve\.time evidence/u);
});

test("missing agent makes wazuh evidence missing", () => {
  const r = runCheck({ ...alwaysOk, requires: ["wazuh.os"] }, { ...host, sources: {} }, ctx(memoryStore()));
  assert.equal(r.state, "unknown");
});

test("stale evidence is unknown with its age", () => {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: "pve:node:norco", kind: "pve.time", value: {} }], NOW - 3 * 3600_000);
  const r = runCheck(alwaysOk, host, ctx(s));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /pve\.time last confirmed 3 h ago/u);
});

test("future-dated evidence is unknown", () => {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: "pve:node:norco", kind: "pve.time", value: {} }], NOW + 10 * 60_000);
  const r = runCheck(alwaysOk, host, ctx(s));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /future/u);
});

test("a failing collector makes its evidence unknown even when fresh", () => {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: "pve:node:norco", kind: "pve.time", value: {} }], NOW - 60_000);
  const run = s.beginRun("proxmox", NOW - 1000);
  s.finishRun(run, "failed", { error: "auth: 401" }, NOW - 500);
  const r = runCheck(alwaysOk, host, ctx(s));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /proxmox collection failing: auth: 401/u);
});

test("several unusable kinds join their reasons", () => {
  const r = runCheck({ ...alwaysOk, requires: ["pve.time", "pve.disks"] }, host, ctx(memoryStore()));
  assert.match(r.reason, /no pve\.time evidence; no pve\.disks evidence/u);
});

test("evaluate that throws is unknown", () => {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: "pve:node:norco", kind: "pve.time", value: {} }], NOW);
  const r = runCheck({ ...alwaysOk, evaluate: () => { throw new Error("bad shape"); } }, host, ctx(s));
  assert.deepEqual([r.state, r.reason], ["unknown", "check error: bad shape"]);
});

test("ok attaches evidence refs", () => {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: "pve:node:norco", kind: "pve.time", value: {} }], NOW - 1000);
  const r = runCheck(alwaysOk, host, ctx(s));
  assert.equal(r.state, "ok");
  assert.deepEqual(r.evidence, [{ assetKey: "pve:node:norco", kind: "pve.time", source: "proxmox", collectedAt: NOW - 1000 }]);
});

test("formatAge is human readable", () => {
  assert.equal(formatAge(30_000), "30 s");
  assert.equal(formatAge(5 * 60_000), "5 min");
  assert.equal(formatAge(3 * 3600_000), "3 h");
  assert.equal(formatAge(2 * 86400_000), "2 d");
});
