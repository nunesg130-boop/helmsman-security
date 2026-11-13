// Final-review fixes: each test reproduces a reviewer finding.
import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import https from "node:https";
import { createHttp } from "../../src/http.mjs";
import { runCollector } from "../../src/collect.mjs";
import { runCheck } from "../../src/checks/runner.mjs";
import { evaluateAll } from "../../src/ledger.mjs";
import { CHECKS } from "../../src/checks/index.mjs";
import { agentPresent } from "../../src/checks/agent.mjs";
import { diskHealth } from "../../src/checks/disk.mjs";
import { backupJobs } from "../../src/checks/backup.mjs";
import { pendingReboot } from "../../src/checks/reboot.mjs";
import { collectProxmox } from "../../src/collectors/proxmox.mjs";
import { collectWazuh } from "../../src/collectors/wazuh.mjs";
import { createWazuh414 } from "../../src/collectors/wazuh414.mjs";
import { openDb } from "../../src/db.mjs";
import { EvidenceStore } from "../../src/evidence.mjs";
import { LedgerStore } from "../../src/ledger.mjs";
import { HoldStore } from "../../src/holds.mjs";
import { CredentialStore, createSecretBox } from "../../src/secrets.mjs";
import { createPublicServer } from "../../src/api/public.mjs";
import { memoryStore, putOk, noHolds } from "../helpers/stores.mjs";
import { startFixtureServer } from "../helpers/fixture-server.mjs";
import { proxmoxRoutes, T } from "../fixtures/proxmox-fixture.mjs";
import { wazuhRoutes, page } from "../fixtures/wazuh-fixture.mjs";

// C1 ----------------------------------------------------------------------
test("C1: a server that accepts TCP but never finishes TLS times out", { timeout: 3000 }, async () => {
  const srv = net.createServer(() => {}); // accept, never speak
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const http = createHttp({ allowHosts: ["127.0.0.1"] });
    const t0 = Date.now();
    await assert.rejects(http.fetchJson(`https://127.0.0.1:${srv.address().port}/x`, { certSha256: "00".repeat(32), timeoutMs: 200 }), (e) => e.code === "timeout");
    assert.ok(Date.now() - t0 < 2000);
  } finally { srv.close(); }
});

test("C1: a trickling server hits the overall deadline", { timeout: 3000 }, async () => {
  const srv = await startFixtureServer({});
  const { createServer } = await import("node:https");
  const key = readFileSync(new URL("../fixtures/tls/key.pem", import.meta.url));
  const cert = readFileSync(new URL("../fixtures/tls/cert.pem", import.meta.url));
  const slow = createServer({ key, cert }, (req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    const iv = setInterval(() => res.write(" "), 50);
    req.on("close", () => clearInterval(iv));
  });
  await new Promise((r) => slow.listen(0, "127.0.0.1", r));
  try {
    const http = createHttp({ allowHosts: ["127.0.0.1"] });
    await assert.rejects(http.fetchJson(`https://127.0.0.1:${slow.address().port}/x`, { certSha256: srv.certSha256, timeoutMs: 200, deadlineMs: 600 }), (e) => e.code === "timeout");
  } finally { slow.closeAllConnections(); slow.close(); await srv.close(); }
});

test("C1: a collector that never returns fails at its deadline", { timeout: 3000 }, async () => {
  const store = memoryStore();
  const r = await runCollector(store, "proxmox", () => new Promise(() => {}), { now: Date.now, staleAfterMs: 1000, deadlineMs: 100 });
  assert.equal(r.status, "failed");
  assert.match(store.lastRun("proxmox").error, /did not finish within/u);
});

async function apiWithOldLedger() {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const credentials = new CredentialStore(db, "default", createSecretBox(randomBytes(32)));
  credentials.set("api.readToken", "tok", 1);
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('default','pve:guest:1','guest','g','{}',?)").run(Date.now());
  new LedgerStore(db, "default").write([{ assetKey: "pve:guest:1", checkId: "disk_health", state: "ok", reason: "fine", evidence: [], roaming: false }], Date.now() - 3 * 3600_000);
  const tls = { key: readFileSync(new URL("../fixtures/tls/key.pem", import.meta.url)), cert: readFileSync(new URL("../fixtures/tls/cert.pem", import.meta.url)) };
  return createPublicServer({ db, tenantId: "default", store, credentials, tls, host: "127.0.0.1", port: 0, version: "t", staleAfterMs: 45 * 60_000 });
}
const get = (port, path) => new Promise((resolve, reject) => {
  https.get({ host: "127.0.0.1", port, path, rejectUnauthorized: false, headers: { authorization: "Bearer tok" } }, (res) => {
    let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolve(JSON.parse(b)));
  }).on("error", reject);
});

test("C1: ledger rows not re-evaluated recently are served as unknown, and health says the engine stalled", { timeout: 3000 }, async () => {
  const srv = await apiWithOldLedger();
  try {
    const s = await get(srv.port, "/api/v1/summary");
    assert.equal(s.counts.ok, 0);
    assert.equal(s.counts.unknown, 1);
    assert.ok(s.engine.lastCycleAt > 0);
    const u = await get(srv.port, "/api/v1/unknowns");
    assert.match(u.items[0].reason, /not re-evaluated since/u);
    const h = await get(srv.port, "/api/v1/health");
    assert.equal(h.ok, false);
    assert.match(h.reason, /stalled/u);
  } finally { await srv.close(); }
});

// I1 ----------------------------------------------------------------------
test("I1: a guest with no agent reads unknown (not not_applicable) on host checks", () => {
  const db = openDb(":memory:");
  const rows = evaluateAll({ store: new EvidenceStore(db, "t"), holds: new HoldStore(db, "t"), assets: [{ assetKey: "pve:guest:5", class: "guest", name: "x", sources: { pve: { vmid: 5, type: "qemu" } } }], config: {}, now: 1 });
  for (const id of ["agent_connected", "os_eol", "software_eol", "pending_reboot"]) {
    const r = rows.find((x) => x.checkId === id);
    assert.equal(r.state, "unknown", `${id}: ${r.state} ${r.reason}`);
    assert.match(r.reason, /no Wazuh agent installed/u);
  }
});

test("I1: an appliance reads unknown with 'no agent possible'", () => {
  const db = openDb(":memory:");
  const rows = evaluateAll({ store: new EvidenceStore(db, "t"), holds: new HoldStore(db, "t"), assets: [{ assetKey: "pve:guest:102", class: "appliance", name: "haos", sources: { pve: { vmid: 102, type: "qemu" } } }], config: {}, now: 1 });
  const r = rows.find((x) => x.checkId === "os_eol");
  assert.deepEqual([r.state, r.reason], ["unknown", "no agent possible"]);
});

test("I1: an ambiguous guest is unknown on every host check", () => {
  const db = openDb(":memory:");
  const rows = evaluateAll({ store: new EvidenceStore(db, "t"), holds: new HoldStore(db, "t"), assets: [{ assetKey: "pve:guest:1", class: "guest", name: "a", sources: { pve: { vmid: 1, type: "qemu" } }, ambiguous: true, ambiguousReason: "two agents" }], config: {}, now: 1 });
  assert.ok(rows.filter((r) => r.state === "unknown").length >= 6);
});

// re-graded Minor 8 ---------------------------------------------------------
test("M8: pending_reboot does not apply to LXC containers", () => {
  const r = runCheck(pendingReboot, { assetKey: "pve:guest:114", class: "guest", name: "ollama", sources: { pve: { vmid: 114, type: "lxc" }, wazuh: { id: "9" } } }, { store: memoryStore(), holds: noHolds, config: {}, now: 1 });
  assert.deepEqual([r.state, r.reason], ["not_applicable", "containers run on the host's kernel"]);
});

// I2 ----------------------------------------------------------------------
test("I2: agent_present is unknown once the inventory it relies on is stale", () => {
  const s = memoryStore();
  const NOW = 100 * 86400_000;
  putOk(s, "proxmox", [{ assetKey: "_inventory", kind: "inventory.proxmox", value: {} }], NOW - 30 * 86400_000);
  putOk(s, "wazuh", [{ assetKey: "_inventory", kind: "inventory.wazuh", value: {} }], NOW - 30 * 86400_000);
  const r = runCheck(agentPresent, { assetKey: "pve:guest:105", class: "guest", name: "x", sources: { pve: { vmid: 105 }, wazuh: { id: "4" } } }, { store: s, holds: noHolds, config: {}, now: NOW });
  assert.equal(r.state, "unknown");
});

test("I2: agent_present is ok with fresh inventory", () => {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: "_inventory", kind: "inventory.proxmox", value: {} }], 1000);
  putOk(s, "wazuh", [{ assetKey: "_inventory", kind: "inventory.wazuh", value: {} }], 1000);
  const r = runCheck(agentPresent, { assetKey: "pve:guest:105", class: "guest", name: "x", sources: { pve: { vmid: 105 }, wazuh: { id: "4" } } }, { store: s, holds: noHolds, config: {}, now: 2000 });
  assert.equal(r.state, "ok");
});

// I3 + I4 -----------------------------------------------------------------
async function pveCollect(over) {
  const srv = await startFixtureServer(proxmoxRoutes(over));
  try {
    return await collectProxmox({ http: createHttp({ allowHosts: ["127.0.0.1"] }), cfg: { baseUrl: srv.url, tokenId: "x@pam!y", certSha256: srv.certSha256, backupStorage: "backups" }, secret: "s", now: () => T * 1000 });
  } finally { await srv.close(); }
}
const backupsOf = (out, vmid) => out.evidence.find((e) => e.assetKey === `pve:guest:${vmid}` && e.kind === "pve.backups")?.value;

test("I3: guests on a node whose task list can't be read get no backup evidence", async () => {
  const out = await pveCollect({ "/api2/json/nodes/norco/tasks": () => [500, {}] });
  assert.equal(backupsOf(out, 109), undefined);
  assert.ok(backupsOf(out, 100));
});

test("I4: a job-level task is not attributed when several jobs cover the node", async () => {
  const jobs = { data: [{ id: "daily", enabled: 1, all: 1, storage: "backups" }, { id: "weekly", enabled: 1, vmid: "200", storage: "backups" }] };
  const out = await pveCollect({ "/api2/json/cluster/backup": jobs, "/api2/json/nodes/main/tasks": { data: [{ type: "vzdump", id: "", status: "OK", endtime: T - 100 }] } });
  const b = backupsOf(out, 100);
  assert.equal(b.lastTask, null);
  assert.equal(b.lastTaskAttribution, "ambiguous");
});

test("I4: the backup check says when the last job result couldn't be attributed", () => {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: "pve:guest:100", kind: "pve.backups", value: { coveredByJob: true, newestBackupAt: 1_000_000 - 3600_000, lastTask: null, lastTaskAttribution: "ambiguous" } }], 1_000_000);
  const r = runCheck(backupJobs, { assetKey: "pve:guest:100", class: "guest", name: "x", sources: { pve: { vmid: 100 } } }, { store: s, holds: noHolds, config: {}, now: 1_000_000 });
  assert.equal(r.state, "ok");
  assert.match(r.reason, /last job result not attributable/u);
});

// I5 ----------------------------------------------------------------------
test("I5: an SSD that doesn't report wear is unknown; numeric strings parse", () => {
  const node = { assetKey: "pve:node:n", class: "host", name: "n", sources: { pve: { node: "n" } } };
  const run = (disks) => { const s = memoryStore(); putOk(s, "proxmox", [{ assetKey: "pve:node:n", kind: "pve.disks", value: disks }], 1); return runCheck(diskHealth, node, { store: s, holds: noHolds, config: {}, now: 1 }); };
  assert.equal(run([{ devpath: "/dev/nvme0n1", health: "PASSED", wearout: "N/A", type: "nvme" }]).state, "unknown");
  assert.equal(run([{ devpath: "/dev/sda", health: "PASSED", wearout: "N/A", type: "hdd" }]).state, "ok");
  assert.equal(run([{ devpath: "/dev/sda", health: "PASSED", wearout: "5", type: "ssd" }]).state, "issue");
});

// I6 ----------------------------------------------------------------------
test("I6: inventory from an active agent is dated at its last syscollector scan", async () => {
  const old = "2026-10-01T00:00:00Z";
  const routes = wazuhRoutes({ "/syscollector/001/packages": page([{ name: "bash", version: "5", scan: { id: 0, time: old } }]) });
  const srv = await startFixtureServer(routes);
  try {
    const adapter = createWazuh414({ http: createHttp({ allowHosts: ["127.0.0.1"] }), baseUrl: srv.url, user: "u", password: "p", certSha256: srv.certSha256 });
    const out = await collectWazuh({ adapter, now: () => Date.parse("2026-11-12T12:00:00Z") });
    const pk = out.evidence.find((e) => e.assetKey === "wazuh:agent:001" && e.kind === "wazuh.packages");
    assert.equal(pk.collectedAt, Date.parse(old));
  } finally { await srv.close(); }
});

test("I6/M1: a future-dated keepalive does not make inventory fresh", async () => {
  const routes = wazuhRoutes();
  routes["/agents"].data.affected_items[2].lastKeepAlive = "2030-01-01T00:00:00Z";
  const srv = await startFixtureServer(routes);
  try {
    const adapter = createWazuh414({ http: createHttp({ allowHosts: ["127.0.0.1"] }), baseUrl: srv.url, user: "u", password: "p", certSha256: srv.certSha256 });
    const now = Date.parse("2026-11-12T12:00:00Z");
    const out = await collectWazuh({ adapter, now: () => now });
    const pk = out.evidence.find((e) => e.assetKey === "wazuh:agent:010" && e.kind === "wazuh.packages");
    assert.ok(pk.collectedAt < now - 86400_000, "disconnected agent with future keepalive must not be dated now");
  } finally { await srv.close(); }
});

// I7 ----------------------------------------------------------------------
test("I7: asset detail marks old ports and containers as stale with their time", async () => {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const credentials = new CredentialStore(db, "default", createSecretBox(randomBytes(32)));
  credentials.set("api.readToken", "tok", 1);
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('default','pve:guest:109','guest','docker','{\"wazuh\":{\"id\":\"3\"}}',1)").run();
  putOk(store, "docker", [{ assetKey: "pve:guest:109", kind: "docker.containers", value: [{ name: "sonarr" }], staleAfterMs: 60_000 }], Date.now() - 86400_000);
  const tls = { key: readFileSync(new URL("../fixtures/tls/key.pem", import.meta.url)), cert: readFileSync(new URL("../fixtures/tls/cert.pem", import.meta.url)) };
  const srv = await createPublicServer({ db, tenantId: "default", store, credentials, tls, host: "127.0.0.1", port: 0, version: "t", staleAfterMs: 45 * 60_000 });
  try {
    const d = await get(srv.port, `/api/v1/assets/${encodeURIComponent("pve:guest:109")}`);
    assert.equal(d.containers.stale, true);
    assert.ok(d.containers.collectedAt > 0);
    assert.deepEqual(d.containers.items, [{ name: "sonarr" }]);
    assert.equal(d.ports.collectedAt, null);
  } finally { await srv.close(); }
});
