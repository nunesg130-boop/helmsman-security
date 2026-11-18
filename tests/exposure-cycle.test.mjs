import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { openDb, SCHEMA_VERSION } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { HoldStore } from "../src/holds.mjs";
import { LedgerStore } from "../src/ledger.mjs";
import { collectionCycle } from "../src/cycle.mjs";
import { declaredRouter } from "../src/exposure/cycle.mjs";

const NOW = 1_800_000_000_000;
const live = JSON.parse(readFileSync(new URL("./fixtures/caddy-shape-live.json", import.meta.url), "utf8"));
const CONFIG = {
  thresholds: {}, assets: {}, docker: [],
  network: [{ name: "er605", ip: "192.168.0.1", portForwards: [{ wanPort: 80, lanIp: "192.168.0.105", lanPort: 80, protocol: "tcp" }, { wanPort: 443, lanIp: "192.168.0.105", lanPort: 443, protocol: "tcp" }], upnp: false, dmz: false, ipv6Inbound: false }, { name: "switch" }],
  exposure: { caddy: { url: "http://192.168.0.105:2020/shape.json", assetKey: "pve:guest:105", address: "192.168.0.105", maxAgeMinutes: 30, trustedClientIpHeaders: ["Cf-Connecting-Ip"] },
    cloudflare: { accountId: "a", zoneId: "z", tunnelIds: ["t"], assetKey: "pve:guest:108", connectorAddress: "192.168.0.108" }, expectedPrivate: [] }
};
const guests = [[105, "caddy", "192.168.0.105"], [108, "cloudflared", "192.168.0.108"], [100, "Jelly-Arr", "192.168.0.7"], [110, "pihole", "192.168.0.2"],
  [109, "docker-apps", "192.168.0.109"], [116, "helmsec", "192.168.0.116"], [104, "seerr", "192.168.0.104"], [122, "wizarr", "192.168.0.122"], [107, "sure", "192.168.0.107"], [125, "wyl", "192.168.0.125"]].map(([vmid, name, ip]) => ({ vmid, name, node: "norco", type: "lxc", macs: [], ips: [ip] }));
const SOURCES = {
  proxmox: async () => ({ evidence: [], inventory: { nodes: [{ name: "norco", ip: "192.168.0.10" }], guests } }),
  wazuh: async () => ({ evidence: [], inventory: { agents: [{ id: "007", name: "docker-auth", ip: "192.168.0.213", macs: [], status: "active" }] } }),
  caddy: async () => ({ evidence: [{ assetKey: "pve:guest:105", kind: "caddy.shape", value: { version: 2, generatedAt: NOW, servers: live.servers }, collectedAt: NOW }] }),
  cloudflare: async () => ({ evidence: [
    { assetKey: "pve:guest:108", kind: "cloudflare.tunnel", value: { tunnels: [] } },
    { assetKey: "pve:guest:108", kind: "cloudflare.access", value: { apps: [] } },
    { assetKey: "pve:guest:108", kind: "cloudflare.dns", value: { names: ["jellyprox.jellofin.com"] } }] })
};
async function cycle({ sources = SOURCES, config = CONFIG } = {}) {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const ledger = new LedgerStore(db, "default");
  const summary = await collectionCycle({ db, tenantId: "default", store, holds: new HoldStore(db, "default"), ledger, config, sources, now: () => NOW });
  const map = store.get("_global", "exposure.map");
  return { summary, store, ledger, map: map?.value, machine: (key) => map?.value.machines.find((m) => m.assetKey === key) };
}

test("the cycle stores an exposure map built from the Caddy shape, Cloudflare and the declared router", async () => {
  const { summary, map, machine, store } = await cycle();
  assert.equal(summary.collectors.exposure, "ok");
  assert.equal(store.get("_global", "exposure.map").source, "exposure");
  assert.deepEqual(map.sources, { caddy: "ok", cloudflare: "ok", router: "declared", inventory: "ok" });
  const jelly = map.services.find((s) => s.hostname === "jellyprox.jellofin.com");
  assert.deepEqual([jelly.exposure, jelly.assetKey, jelly.publicDns], ["internet", "pve:guest:100", true]);
  assert.deepEqual([machine("pve:guest:100").exposure, machine("pve:guest:100").role, machine("pve:guest:100").name], ["internet", "app", "Jelly-Arr"]);
  assert.deepEqual([machine("pve:guest:105").role, machine("pve:guest:110").exposure], ["entry", "lan"]);
  assert.equal(machine("wazuh:agent:007").role, "gate", "an agent's own address places it too");
  assert.deepEqual(map.router, { portForwards: 2, upnp: false, dmz: false, ipv6Inbound: false });
});
test("a failing Caddy collection still yields a map, with everything behind Caddy unknown", async () => {
  const { map, machine } = await cycle({ sources: { ...SOURCES, caddy: async () => { throw Object.assign(new Error("Caddy shape is 90 min old"), { code: "parse" }); } } });
  assert.equal(map.sources.caddy, "failed");
  assert.equal(machine("pve:guest:100").exposure, "unknown");
  assert.equal(machine("pve:guest:110").exposure, "unknown");
});
test("missing Cloudflare evidence is reported as missing, and nothing is lan", async () => {
  const { cloudflare, ...rest } = SOURCES;
  const { map, machine } = await cycle({ sources: rest });
  assert.equal(map.sources.cloudflare, "missing");
  assert.equal(machine("pve:guest:110").exposure, "unknown");
});
test("without an exposure section in the config, no exposure run happens", async () => {
  const { summary, store, map } = await cycle({ config: { ...CONFIG, exposure: null } });
  assert.equal(summary.collectors.exposure, undefined);
  assert.equal(store.lastRun("exposure"), null);
  assert.equal(map, undefined);
});
test("declaredRouter merges the network entries and keeps undeclared facts as null", () => {
  assert.deepEqual(declaredRouter(CONFIG.network), { portForwards: CONFIG.network[0].portForwards, upnp: false, dmz: false, ipv6Inbound: false });
  assert.deepEqual(declaredRouter([{ name: "er605" }]), { portForwards: null, upnp: null, dmz: null, ipv6Inbound: null });
  assert.equal(declaredRouter([{ name: "a", upnp: false }, { name: "b", upnp: true }]).upnp, true);
  assert.equal(declaredRouter([{ name: "a", dmz: "192.168.0.50" }]).dmz, "192.168.0.50");
});
test("the router's coverage reason says what is declared and what isn't", async () => {
  const { ledger } = await cycle();
  const r = ledger.forAsset("net:er605").find((x) => x.checkId === "collector_coverage");
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /declared, not verified: 2 port forwards, UPnP off, DMZ off, inbound IPv6 off/u);
  const partial = await cycle({ config: { ...CONFIG, network: [{ name: "er605", upnp: false }] } });
  assert.match(partial.ledger.forAsset("net:er605").find((x) => x.checkId === "collector_coverage").reason, /declared, not verified: UPnP off; not declared: port forwards, DMZ, inbound IPv6/u);
  assert.match(partial.ledger.forAsset("net:er605").find((x) => x.checkId === "collector_coverage").reason, /no collector for this device yet/u);
});
test("a version 2 database migrates to version 3 with its holds kept, and accepts acceptances", () => {
  const file = join(mkdtempSync(join(tmpdir(), "hs-mig3-")), "engine.db");
  openDb(file).close();
  const raw = new DatabaseSync(file);
  raw.exec(`DROP TABLE holds;
    CREATE TABLE holds (id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('hold','exclusion')), asset_key TEXT NOT NULL, check_id TEXT, product TEXT, version TEXT,
      reason TEXT NOT NULL CHECK (length(trim(reason)) > 0), expires_at INTEGER, created_at INTEGER NOT NULL);
    INSERT INTO holds (id, tenant_id, kind, asset_key, check_id, reason, expires_at, created_at) VALUES (7, 'default', 'exclusion', 'pve:guest:1', '*', 'lab toy', 99, 5);
    PRAGMA user_version = 2;`);
  raw.close();
  const db = openDb(file);
  assert.equal(SCHEMA_VERSION, 3);
  assert.equal(db.prepare("PRAGMA user_version").get().user_version, 3);
  assert.deepEqual({ ...db.prepare("SELECT id, kind, asset_key, check_id, reason, expires_at, created_at, context_json FROM holds").get() },
    { id: 7, kind: "exclusion", asset_key: "pve:guest:1", check_id: "*", reason: "lab toy", expires_at: 99, created_at: 5, context_json: null });
  db.prepare("INSERT INTO holds (tenant_id, kind, asset_key, check_id, product, version, reason, created_at, context_json) VALUES ('default','acceptance','a','CVE-1','p','1','ok',1,'{}')").run();
  assert.throws(() => db.prepare("INSERT INTO holds (tenant_id, kind, asset_key, reason, created_at) VALUES ('default','other','a','x',1)").run());
  db.close();
});
test("when the Proxmox inventory stops refreshing, the map says so and nothing is lan", async () => {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const args = { db, tenantId: "default", store, holds: new HoldStore(db, "default"), ledger: new LedgerStore(db, "default"), config: CONFIG };
  await collectionCycle({ ...args, sources: SOURCES, now: () => NOW });
  const later = NOW + 15 * 60_000;
  const fresh = (kind) => async () => { const out = await SOURCES[kind](); return { ...out, evidence: (out.evidence ?? []).map((e) => ({ ...e, collectedAt: later, value: e.kind === "caddy.shape" ? { ...e.value, generatedAt: later } : e.value })) }; };
  await collectionCycle({ ...args, sources: { ...SOURCES, caddy: fresh("caddy"), cloudflare: fresh("cloudflare"), proxmox: async () => { throw new Error("401"); } }, now: () => later });
  const map = store.get("_global", "exposure.map").value;
  assert.equal(map.sources.inventory, "failed");
  assert.equal(map.machines.find((m) => m.assetKey === "pve:guest:110").exposure, "unknown");
});
test("a declared address places a machine the inventory has no address for", async () => {
  const haos = { vmid: 102, name: "haos", node: "norco", type: "qemu", macs: [], ips: [] };
  const sources = { ...SOURCES, proxmox: async () => ({ evidence: [], inventory: { nodes: [{ name: "norco", ip: "192.168.0.10" }], guests: [...guests, haos] } }),
    cloudflare: async () => ({ evidence: [
      { assetKey: "pve:guest:108", kind: "cloudflare.tunnel", value: { tunnels: [{ id: "t", ingress: [{ hostname: "haos.jellofin.com", path: null, service: "http://192.168.0.197:8123", catchAll: false, hostHeader: null, jwtRequired: false, audTags: 0 }] }] } },
      { assetKey: "pve:guest:108", kind: "cloudflare.access", value: { apps: [] } },
      { assetKey: "pve:guest:108", kind: "cloudflare.dns", value: { names: [] } }] }) };
  const without = await cycle({ sources });
  assert.equal(without.map.services.find((s) => s.hostname === "haos.jellofin.com").assetKey, null);
  assert.equal(without.machine("pve:guest:110").exposure, "unknown", "an unplaced public route blocks lan everywhere");
  const declared = await cycle({ sources, config: { ...CONFIG, assets: { addresses: { "pve:guest:102": ["192.168.0.197"] } } } });
  assert.equal(declared.map.services.find((s) => s.hostname === "haos.jellofin.com").assetKey, "pve:guest:102");
  assert.deepEqual([declared.machine("pve:guest:102").exposure, declared.machine("pve:guest:110").exposure], ["internet", "lan"]);
  assert.deepEqual(declared.map.declaredAddresses, { "pve:guest:102": ["192.168.0.197"] });
});
