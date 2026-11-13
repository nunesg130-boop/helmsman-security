import test from "node:test";
import assert from "node:assert/strict";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { HoldStore } from "../src/holds.mjs";
import { LedgerStore, evaluateAll } from "../src/ledger.mjs";
import { CHECKS } from "../src/checks/index.mjs";
import { collectionCycle, eolCycle } from "../src/cycle.mjs";
import { collectProxmox } from "../src/collectors/proxmox.mjs";
import { collectWazuh } from "../src/collectors/wazuh.mjs";
import { createWazuh414 } from "../src/collectors/wazuh414.mjs";
import { collectEolDataset } from "../src/collectors/eol-dataset.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";
import { proxmoxRoutes, T } from "./fixtures/proxmox-fixture.mjs";
import { wazuhRoutes } from "./fixtures/wazuh-fixture.mjs";
import { readFileSync } from "node:fs";

test("CHECKS has 11 unique ids including collector_coverage", () => {
  assert.equal(CHECKS.length, 11);
  assert.equal(new Set(CHECKS.map((c) => c.id)).size, 11);
  assert.ok(CHECKS.some((c) => c.id === "collector_coverage"));
});

test("ambiguous asset yields unknown on every applicable check", () => {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "t");
  const rows = evaluateAll({ store, holds: new HoldStore(db, "t"), assets: [{ assetKey: "pve:guest:1", class: "guest", name: "a", sources: { pve: { vmid: 1 } }, ambiguous: true, ambiguousReason: "2 Wazuh agents share this MAC" }], config: {}, now: 1 });
  const applicable = rows.filter((r) => r.state !== "not_applicable");
  assert.ok(applicable.length >= 2);
  assert.ok(applicable.every((r) => r.state === "unknown" && r.reason === "2 Wazuh agents share this MAC"));
});

test("last_ok_at survives a turn to unknown and state_since only moves on change", () => {
  const db = openDb(":memory:");
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('t','a','host','a','{}',100)").run();
  const l = new LedgerStore(db, "t");
  const row = (state) => ({ assetKey: "a", checkId: "c", state, reason: state, evidence: [], roaming: false });
  l.write([row("ok")], 100);
  l.write([row("ok")], 200);
  assert.equal(l.forAsset("a")[0].stateSince, 100);
  l.write([row("unknown")], 300);
  const r = l.forAsset("a")[0];
  assert.deepEqual([r.state, r.lastOkAt, r.stateSince], ["unknown", 200, 300]);
});

test("roaming unknowns are counted separately", () => {
  const db = openDb(":memory:");
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('t','r','roaming','legion','{}',1), ('t','h','host','norco','{}',1)").run();
  const l = new LedgerStore(db, "t");
  l.write([
    { assetKey: "r", checkId: "agent_connected", state: "unknown", reason: "away", evidence: [], roaming: true },
    { assetKey: "h", checkId: "disk_health", state: "unknown", reason: "x", evidence: [], roaming: false },
    { assetKey: "h", checkId: "clock_drift", state: "issue", reason: "y", evidence: [], roaming: false }
  ], 1);
  assert.deepEqual(l.counts(), { ok: 0, issue: 1, unknown: 1, not_applicable: 0, excluded: 0, roamingAway: 1 });
  assert.equal(l.unknowns().length, 2);
  assert.equal(l.issues()[0].assetName, "norco");
});

const NOW = T * 1000;
async function labCycle() {
  const pve = await startFixtureServer(proxmoxRoutes());
  const wz = await startFixtureServer(wazuhRoutes({
    "/agents": { data: { affected_items: [
      { id: "001", name: "norco", ip: "192.168.0.10", status: "active", lastKeepAlive: "2027-01-15T08:00:00Z" },
      { id: "003", name: "docker", ip: "192.168.0.109", status: "disconnected", lastKeepAlive: "2027-01-15T05:00:00Z" },
      { id: "010", name: "legion", ip: "192.168.0.50", status: "disconnected", lastKeepAlive: "2027-01-10T08:00:00Z" }
    ], total_affected_items: 3 } },
    "/syscollector/003/netiface": { data: { affected_items: [{ mac: "bc:24:11:aa:00:01" }], total_affected_items: 1 } },
    ...Object.fromEntries(["os", "packages", "hotfixes", "ports", "processes", "hardware"].map((t) => [`/syscollector/003/${t}`, { data: { affected_items: [], total_affected_items: 0 } }]))
  }));
  const http = createHttp({ allowHosts: ["127.0.0.1"] });
  const db = openDb(":memory:");
  const tenantId = "default";
  const store = new EvidenceStore(db, tenantId);
  const holds = new HoldStore(db, tenantId);
  const ledger = new LedgerStore(db, tenantId);
  const config = {
    thresholds: { collectMinutes: 15, staleFactor: 3, eolMaxAgeDays: 7 },
    proxmox: { backupStorage: "backups" },
    assets: { roaming: ["legion"], appliances: [] },
    network: [{ name: "er605", ip: "192.168.0.1" }],
    docker: []
  };
  const sources = {
    proxmox: () => collectProxmox({ http, cfg: { baseUrl: pve.url, tokenId: "t@pam!x", certSha256: pve.certSha256, backupStorage: "backups" }, secret: "s", now: () => NOW }),
    wazuh: () => collectWazuh({ adapter: createWazuh414({ http, baseUrl: wz.url, user: "u", password: "p", certSha256: wz.certSha256 }), now: () => NOW })
  };
  const fixture = (slug) => JSON.parse(readFileSync(new URL(`./fixtures/eol/${slug}.json`, import.meta.url)));
  try {
    await eolCycle({ store, config, now: () => NOW, fetchEol: () => collectEolDataset({ fetchJson: async (u) => fixture(u.split("/").pop()), products: ["debian", "proxmox-ve", "fedora", "docker-engine", "ubuntu", "macos"], now: () => NOW, maxAgeMs: 7 * 86400_000 }) });
    const summary = await collectionCycle({ db, tenantId, store, holds, ledger, config, sources, now: () => NOW });
    return { summary, ledger, db };
  } finally { await pve.close(); await wz.close(); }
}

test("end-to-end cycle with fixture servers yields ok, issue and unknown", async () => {
  const { summary, ledger } = await labCycle();
  const c = ledger.counts();
  assert.ok(c.ok > 0, JSON.stringify(c));
  assert.ok(c.issue > 0, JSON.stringify(c));
  assert.ok(c.unknown > 0, JSON.stringify(c));
  assert.ok(c.roamingAway > 0, "roaming laptop checks are counted apart from unknowns");
  assert.deepEqual(summary.collectors, { proxmox: "ok", wazuh: "ok" });
});

test("agent evidence attaches to the linked Proxmox guest", async () => {
  const { ledger } = await labCycle();
  const agent = ledger.forAsset("pve:guest:109").find((r) => r.checkId === "agent_connected");
  assert.equal(agent.state, "issue");
  assert.match(agent.reason, /disconnected/u);
});

test("router from config appears as unknown with a no-collector reason", async () => {
  const { ledger } = await labCycle();
  const r = ledger.forAsset("net:er605").find((x) => x.checkId === "collector_coverage");
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /no collector for this device yet/u);
});
