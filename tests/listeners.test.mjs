import test from "node:test";
import assert from "node:assert/strict";
import { listenerEvidence, isListening, listenerMatch } from "../src/exposure/listeners.mjs";
import { collectWazuh } from "../src/collectors/wazuh.mjs";
import { collectDocker } from "../src/collectors/docker.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";
import { memoryStore, putOk } from "./helpers/stores.mjs";

const NOW = 50_000_000;
const AGENT = "wazuh:agent:010";
const plain = { assetKey: "pve:guest:100", class: "guest", name: "Jelly-Arr", sources: { wazuh: { id: "010" } } };
const dockerAsset = { ...plain, sources: { wazuh: { id: "010" }, docker: { name: "jelly" } } };
const row = (localIp, localPort, protocol = "tcp", process = "jellyfin") => ({ protocol, localIp, localPort, process, pid: 1 });
const container = (name, state, ports) => ({ name, image: "x", imageId: "y", state, status: "", ports });
const pub = (publicPort, ip = "0.0.0.0", type = "tcp") => ({ privatePort: 80, publicPort, type, ip });

// Builds a store. Options let a test remove or spoil one piece at a time.
function build({ rows = [row("0.0.0.0", 8096)], status = "active", meta = true, metaValue, metaSeparateRun = false, portsAt = NOW, packages = ["bash"], containers, containersMeta = true, containersAt = NOW } = {}) {
  const s = memoryStore();
  const wazuh = [{ assetKey: AGENT, kind: "wazuh.agent", value: { id: "010", status } }];
  if (packages) wazuh.push({ assetKey: AGENT, kind: "wazuh.packages", value: { items: packages.map((name) => ({ name, version: "1" })), scanned: true } });
  putOk(s, "wazuh", wazuh, NOW);
  const metaItem = { assetKey: AGENT, kind: "wazuh.ports.meta", value: metaValue ?? { complete: true, rows: rows?.length ?? 0, total: rows?.length ?? 0, pages: 1 } };
  if (rows) putOk(s, "wazuh", [{ assetKey: AGENT, kind: "wazuh.ports", value: rows }, ...(meta && !metaSeparateRun ? [metaItem] : [])], portsAt);
  if (meta && metaSeparateRun) putOk(s, "wazuh", [metaItem], portsAt);
  if (containers) putOk(s, "docker", [{ assetKey: plain.assetKey, kind: "docker.containers", value: containers }, ...(containersMeta ? [{ assetKey: plain.assetKey, kind: "docker.containers.meta", value: { complete: true, rows: containers.length, all: true } }] : [])], containersAt);
  return s;
}
const target = { ip: "192.168.0.7", port: 8096, protocol: "tcp" };
const listening = (opts, asset = plain, t = target) => isListening(t, listenerEvidence(asset, build(opts), NOW));

test("wildcard and exact binds count; loopback doesn't", () => {
  assert.equal(listening({ rows: [row("0.0.0.0", 8096)] }), true);
  assert.equal(listening({ rows: [row("::", 8096, "tcp6")] }), true);
  assert.equal(listening({ rows: [row("192.168.0.7", 8096)] }), true);
  assert.equal(listening({ rows: [row("127.0.0.1", 8096)] }), false);
  assert.equal(listening({ rows: [row("::1", 8096, "tcp6")] }), false);
  assert.equal(listening({ rows: [row("192.168.0.99", 8096)] }), false);
  assert.equal(listening({ rows: [row("0.0.0.0", 8096, "udp")] }), false);
  assert.equal(listening({ rows: [row("0.0.0.0", 9000)] }), false);
});
test("a positive match names the process", () => {
  assert.deepEqual(listenerMatch(target, listenerEvidence(plain, build(), NOW)), { listening: true, process: "jellyfin", container: null });
});
test("stale ports evidence is null, even for a match", () => {
  assert.equal(listening({ portsAt: NOW - 3 * 3600_000 }), null);
  assert.equal(listening({ rows: [row("127.0.0.1", 8096)], portsAt: NOW - 3 * 3600_000 }), null);
});
test("an empty port inventory is null: it can't be told apart from 'not scanned yet'", () => {
  assert.equal(listening({ rows: [] }), null);
  assert.equal(listening({ rows: null }), null);
});
test("a negative needs completeness metadata from the same run, with rows equal to the total", () => {
  const miss = [row("127.0.0.1", 8096)];
  assert.equal(listening({ rows: miss }), false);
  assert.equal(listening({ rows: miss, meta: false }), null, "missing");
  assert.equal(listening({ rows: miss, metaSeparateRun: true }), null, "from a different run");
  assert.equal(listening({ rows: miss, metaValue: { complete: true, rows: 1, total: 4, pages: 1 } }), null, "rows !== total");
  assert.equal(listening({ rows: miss, metaValue: { complete: false, rows: 1, total: 1, pages: 1 } }), null, "not complete");
  assert.equal(listening({ rows: miss, metaValue: { complete: true, rows: 5, total: 5, pages: 1 } }), null, "meta describes other rows");
  assert.equal(listening({ rows: miss, status: "disconnected" }), null, "agent not active");
});
test("a positive match doesn't need completeness, only freshness", () => {
  assert.equal(listening({ meta: false }), true);
});
test("on a machine with a container runtime but no Docker gate, no match is null", () => {
  assert.equal(listening({ rows: [row("127.0.0.1", 8096)], packages: ["docker-ce"] }), null);
  assert.equal(listening({ rows: [row("127.0.0.1", 8096)], packages: ["containerd"] }), null);
  assert.equal(listening({ rows: [row("127.0.0.1", 8096)], packages: null }), null, "unknown whether Docker is installed");
  assert.equal(listenerEvidence(plain, build({ packages: ["podman"] }), NOW).dockerHost, "unmonitored");
  assert.equal(listenerEvidence(plain, build(), NOW).dockerHost, "no");
});
test("a running container publishing the port counts; a stopped one doesn't", () => {
  const none = [row("0.0.0.0", 22, "tcp", "sshd")];
  assert.deepEqual(listenerMatch(target, listenerEvidence(dockerAsset, build({ rows: none, containers: [container("jellyfin", "running", [pub(8096)])] }), NOW)), { listening: true, process: null, container: "jellyfin" });
  assert.equal(listening({ rows: none, containers: [container("jellyfin", "exited", [pub(8096)])] }, dockerAsset), false);
  assert.equal(listening({ rows: none, containers: [container("jellyfin", "running", [pub(8096, "127.0.0.1")])] }, dockerAsset), false);
  assert.equal(listening({ rows: none, containers: [container("jellyfin", "running", [pub(8096, "0.0.0.0", "udp")])] }, dockerAsset), false);
});
test("on a configured Docker host a negative needs fresh, complete container evidence", () => {
  const none = [row("0.0.0.0", 22, "tcp", "sshd")];
  assert.equal(listenerEvidence(dockerAsset, build(), NOW).dockerHost, "configured");
  assert.equal(listening({ rows: none, containers: [] }, dockerAsset), false);
  assert.equal(listening({ rows: none }, dockerAsset), null, "no container evidence");
  assert.equal(listening({ rows: none, containers: [], containersMeta: false }, dockerAsset), null, "no completeness record");
  assert.equal(listening({ rows: none, containers: [], containersAt: NOW - 3 * 3600_000 }, dockerAsset), null, "stale");
});
test("a machine without an agent has no listener evidence", () => {
  const ev = listenerEvidence({ assetKey: "pve:guest:1", class: "guest", name: "x", sources: {} }, build(), NOW);
  assert.equal(isListening(target, ev), null);
});

const agentOf = (overrides) => ({
  listAgents: async () => [{ id: "010", name: "j", ip: "192.168.0.7", status: "active", lastKeepAlive: 900 }],
  netiface: async () => ({ macs: [] }), os: async () => ({ platform: "debian" }), packages: async () => ({ items: [], scanned: false }),
  hardware: async () => null, ports: async () => [row("0.0.0.0", 8096)], ...overrides
});
test("the Wazuh collector records completeness only after a full read", async () => {
  const kinds = async (adapter) => (await collectWazuh({ adapter, now: () => 1000 })).evidence.filter((e) => e.kind.startsWith("wazuh.ports"));
  const full = await kinds(agentOf({ tableMeta: () => ({ rows: 1, total: 1, pages: 1 }) }));
  assert.deepEqual(full.map((e) => [e.kind, e.value.complete ?? null, e.collectedAt]), [["wazuh.ports", null, 1000], ["wazuh.ports.meta", true, 1000]]);
  assert.deepEqual(full[1].value, { complete: true, rows: 1, total: 1, pages: 1 });
  for (const meta of [{ rows: 1, total: 3, pages: 1 }, { rows: 1, total: null, pages: 1 }, null]) {
    assert.deepEqual((await kinds(agentOf({ tableMeta: () => meta }))).map((e) => e.kind), ["wazuh.ports"]);
  }
  assert.deepEqual((await kinds(agentOf({}))).map((e) => e.kind), ["wazuh.ports"], "an adapter that can't say gets no completeness record");
});
test("the Docker collector records completeness only for a well-formed list", async () => {
  const run = async (body) => {
    const srv = await startFixtureServer({ "/containers/json": body, "/version": { Version: "27", ApiVersion: "1.47" } }, { tls: false });
    try { return await collectDocker({ http: createHttp({ allowHttpHosts: ["127.0.0.1"] }), hosts: [{ name: "d", baseUrl: srv.url, assetKey: "pve:guest:109" }], now: () => 1000 }); } finally { await srv.close(); }
  };
  const good = await run([{ Names: ["/a"], State: "running", Ports: [] }]);
  assert.deepEqual(good.evidence.find((e) => e.kind === "docker.containers.meta").value, { complete: true, rows: 1, all: true });
  const bad = await run({ message: "not a list" });
  assert.deepEqual(bad.evidence, []);
  assert.match(bad.warnings[0], /docker host d/u);
});
