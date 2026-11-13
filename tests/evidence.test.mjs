import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { runCollector } from "../src/collect.mjs";

const db = () => openDb(join(mkdtempSync(join(tmpdir(), "hs-ev-")), "e.db"));
const item = (value, collectedAt = 1000) => ({ assetKey: "pve:node:norco", kind: "pve.time", source: "proxmox", value, collectedAt, staleAfterMs: 60000 });

test("tenant B cannot read tenant A evidence", () => {
  const d = db();
  const a = new EvidenceStore(d, "a");
  const run = a.beginRun("proxmox", 1000);
  a.put(run, item({ offsetSeconds: 1 }));
  a.finishRun(run, "ok", {}, 1001);
  assert.deepEqual(a.get("pve:node:norco", "pve.time").value, { offsetSeconds: 1 });
  assert.equal(new EvidenceStore(d, "b").get("pve:node:norco", "pve.time"), null);
  assert.equal(new EvidenceStore(d, "b").lastRun("proxmox"), null);
});

test("successful run replaces evidence atomically and records lastSuccessAt", async () => {
  const s = new EvidenceStore(db(), "t");
  let t = 1000;
  await runCollector(s, "proxmox", async () => ({ evidence: [item({ v: 1 })] }), { now: () => t, staleAfterMs: 60000 });
  t = 2000;
  const r = await runCollector(s, "proxmox", async () => ({ evidence: [item({ v: 2 }, 2000)], warnings: ["node main down"] }), { now: () => t, staleAfterMs: 60000 });
  assert.equal(r.status, "ok");
  assert.deepEqual(s.get("pve:node:norco", "pve.time").value, { v: 2 });
  const last = s.lastRun("proxmox");
  assert.equal(last.status, "ok");
  assert.equal(last.lastSuccessAt, 2000);
  assert.deepEqual(last.warnings, ["node main down"]);
});

test("failed run writes no evidence and keeps the previous value", async () => {
  const s = new EvidenceStore(db(), "t");
  await runCollector(s, "proxmox", async () => ({ evidence: [item({ v: 1 })] }), { now: () => 1000, staleAfterMs: 60000 });
  const r = await runCollector(s, "proxmox", async () => { throw new Error("boom PVEAPIToken=root@pam!x=secret-value"); }, { now: () => 2000, staleAfterMs: 60000 });
  assert.equal(r.status, "failed");
  assert.deepEqual(s.get("pve:node:norco", "pve.time").value, { v: 1 });
  const last = s.lastRun("proxmox");
  assert.equal(last.status, "failed");
  assert.equal(last.lastSuccessAt, 1000);
  assert.ok(!last.error.includes("secret-value"));
});

test("evidence input without staleAfterMs uses the collector default", async () => {
  const s = new EvidenceStore(db(), "t");
  const { staleAfterMs, ...rest } = item({ v: 1 });
  await runCollector(s, "proxmox", async () => ({ evidence: [rest] }), { now: () => 1000, staleAfterMs: 45000 });
  assert.equal(s.get("pve:node:norco", "pve.time").staleAfterMs, 45000);
});

test("failOpenRuns marks running rows failed", () => {
  const s = new EvidenceStore(db(), "t");
  s.beginRun("wazuh", 1000);
  assert.equal(s.failOpenRuns(5000), 1);
  const last = s.lastRun("wazuh");
  assert.equal(last.status, "failed");
  assert.match(last.error, /interrupted/u);
});
