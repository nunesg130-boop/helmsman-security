import test from "node:test";
import assert from "node:assert/strict";
import { vulnCycle } from "../src/vuln/cycle.mjs";
import { FindingStore } from "../src/vuln/findings.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { openDb } from "../src/db.mjs";
import { putOk } from "./helpers/stores.mjs";

const NOW = 50_000_000;
const AGE = { now: NOW, maxFeedAgeMs: 1 };
const rec = (agentId, cve) => ({ agentId, agentName: "x", cve, pkg: { name: "openssl", version: "3.0-1", arch: "amd64", type: "deb" }, severity: "high", cvss: 7.5, fixState: "fix-available-not-applied", fixedVersion: "3.0-2", lowConfidence: false, condition: "Package less than 3.0-2", recognisedCondition: true, detectedAt: NOW - 5000 });
const result = (records) => {
  const agents = new Map();
  for (const r of records) agents.set(r.agentId, (agents.get(r.agentId) ?? 0) + 1);
  return { records, total: records.length, agents };
};
function setup() {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "t");
  const findings = new FindingStore(db, "t");
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('t', 'pve:guest:100', 'guest', 'Jelly-Arr', ?, ?)").run(JSON.stringify({ pve: { vmid: 100 }, wazuh: { id: "010" } }), NOW);
  putOk(store, "wazuh", [{ assetKey: "_inventory", kind: "inventory.wazuh", value: { agents: [{ id: "010", name: "Jellyfin" }, { id: "000", name: "wazuh" }, { id: "022", name: "Management-VM" }] } }], NOW);
  const cycle = (indexer, extra = {}) => vulnCycle({ db, tenantId: "t", store, findings, indexer, config: {}, now: () => NOW, ...extra });
  return { db, store, findings, cycle };
}
const indexerOf = (records) => ({ vulnerabilities: async () => result(records) });

test("records are filed under the linked Proxmox asset, else under the agent", async () => {
  const { findings, cycle } = setup();
  assert.equal((await cycle(indexerOf([rec("010", "CVE-1"), rec("022", "CVE-2"), rec("099", "CVE-3")]))).status, "ok");
  const byCve = Object.fromEntries(findings.list({}, AGE).items.map((i) => [i.cve, i.assetKey]));
  assert.deepEqual(byCve, { "CVE-1": "pve:guest:100", "CVE-2": "wazuh:agent:022", "CVE-3": "wazuh:agent:099" });
});

test("every known agent gets scan evidence, with zero for agents the indexer has nothing on", async () => {
  const { store, cycle } = setup();
  await cycle(indexerOf([rec("010", "CVE-1"), rec("010", "CVE-2"), rec("099", "CVE-3")]));
  assert.deepEqual(store.get("wazuh:agent:010", "wazuh.vulnscan").value, { count: 2, newestDetectedAt: NOW - 5000 });
  assert.deepEqual(store.get("wazuh:agent:000", "wazuh.vulnscan").value, { count: 0, newestDetectedAt: null });
  assert.deepEqual(store.get("wazuh:agent:099", "wazuh.vulnscan").value.count, 1);
  assert.equal(store.get("wazuh:agent:010", "wazuh.vulnscan").source, "wazuh-vulns");
  assert.equal(store.get("_inventory", "inventory.wazuh-vulns").value.total, 3);
});

test("a failed indexer read writes no findings and leaves the previous ones in place", async () => {
  const { store, findings, cycle } = setup();
  await cycle(indexerOf([rec("010", "CVE-1")]));
  const r = await cycle({ vulnerabilities: async () => { throw Object.assign(new Error("indexer returned 9 of 10 vulnerability records"), { code: "parse" }); } });
  assert.equal(r.status, "failed");
  assert.deepEqual(findings.list({}, AGE).items.map((i) => i.cve), ["CVE-1"]);
  assert.match(store.lastRun("wazuh-vulns").error, /9 of 10/u);
});

test("findings a later run no longer reports are removed", async () => {
  const { findings, cycle } = setup();
  await cycle(indexerOf([rec("010", "CVE-1"), rec("010", "CVE-2")]));
  await cycle(indexerOf([rec("010", "CVE-2")]));
  assert.deepEqual(findings.list({}, AGE).items.map((i) => i.cve), ["CVE-2"]);
});

test("the password never reaches the stored error", async () => {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "t");
  await vulnCycle({ db, tenantId: "t", store, findings: new FindingStore(db, "t"), config: {}, now: () => NOW, secrets: ["ix-secret"],
    indexer: { vulnerabilities: async () => { throw new Error("bad login ix-secret"); } } });
  assert.ok(!store.lastRun("wazuh-vulns").error.includes("ix-secret"));
});

test("a read that finishes after the deadline writes nothing, even later", async () => {
  const { store, findings, cycle } = setup();
  const slow = { vulnerabilities: () => new Promise((resolve) => setTimeout(() => resolve(result([rec("010", "CVE-LATE")])), 60)) };
  assert.equal((await cycle(slow, { deadlineMs: 10 })).status, "failed");
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(findings.list({}, AGE).total, 0);
  assert.equal(store.get("wazuh:agent:010", "wazuh.vulnscan"), null);
});

test("findings and their evidence are stored together or not at all", async () => {
  const { db, store, findings, cycle } = setup();
  await cycle(indexerOf([rec("010", "CVE-1")]));
  db.exec("CREATE TRIGGER block_evidence BEFORE INSERT ON evidence WHEN NEW.kind = 'wazuh.vulnscan' BEGIN SELECT RAISE(ABORT, 'disk full'); END;");
  db.exec("CREATE TRIGGER block_evidence_u BEFORE UPDATE ON evidence WHEN NEW.kind = 'wazuh.vulnscan' BEGIN SELECT RAISE(ABORT, 'disk full'); END;");
  assert.equal((await cycle(indexerOf([rec("010", "CVE-2")]))).status, "failed");
  assert.deepEqual(findings.list({}, AGE).items.map((i) => i.cve), ["CVE-1"]);
  assert.match(store.lastRun("wazuh-vulns").error, /could not store/u);
});

test("when two asset rows claim an agent, the machine seen most recently wins over a stale one", async () => {
  const { db, findings, cycle } = setup();
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('t', 'pve:guest:999', 'guest', 'old', ?, ?)").run(JSON.stringify({ wazuh: { id: "010" } }), NOW - 86400_000);
  await cycle(indexerOf([rec("010", "CVE-1")]));
  assert.equal(findings.list({}, AGE).items[0].assetKey, "pve:guest:100");
});
