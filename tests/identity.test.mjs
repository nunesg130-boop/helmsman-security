import test from "node:test";
import assert from "node:assert/strict";
import { linkAssets } from "../src/identity.mjs";

const MAC1 = "BC:24:11:AA:00:01";
const guest = (vmid, name, macs = [], ips = []) => ({ vmid, type: "lxc", name, node: "norco", macs, ips });
const agent = (id, name, macs = [], ip = "", status = "active") => ({ id, name, ip, macs, status });
const base = { nodes: [], guests: [], agents: [], dockerHosts: [], manualLinks: [], classes: { roaming: [], appliances: [] } };
const byKey = (out, key) => out.assets.find((a) => a.assetKey === key);

test("MAC match links guest to agent (case-insensitive)", () => {
  const out = linkAssets({ ...base, guests: [guest(109, "docker", [MAC1])], agents: [agent("003", "docker", [MAC1.toLowerCase()])] });
  const a = byKey(out, "pve:guest:109");
  assert.equal(a.class, "guest");
  assert.deepEqual(a.sources.wazuh, { id: "003" });
  assert.equal(a.linkMethod, "mac");
  assert.equal(byKey(out, "wazuh:agent:003"), undefined);
});

test("re-enrolled agent with same MAC is ambiguous", () => {
  const out = linkAssets({ ...base, guests: [guest(109, "docker", [MAC1])], agents: [agent("003", "docker", [MAC1], "", "disconnected"), agent("007", "docker", [MAC1])] });
  const a = byKey(out, "pve:guest:109");
  assert.equal(a.ambiguous, true);
  assert.equal(a.sources.wazuh, undefined);
  assert.match(out.ambiguous[0].reason, /2 Wazuh agents share this MAC; remove the old agent in Wazuh or set a manual link/u);
});

test("never_connected duplicate is ignored", () => {
  const out = linkAssets({ ...base, guests: [guest(109, "docker", [MAC1])], agents: [agent("003", "docker", [MAC1], "", "never_connected"), agent("007", "docker", [MAC1])] });
  assert.deepEqual(byKey(out, "pve:guest:109").sources.wazuh, { id: "007" });
});

test("IP plus short hostname links when MAC does not", () => {
  const out = linkAssets({ ...base, guests: [guest(150, "mgmt", [], ["192.168.0.200"])], agents: [agent("004", "MGMT.jellofin.local", [], "192.168.0.200")] });
  const a = byKey(out, "pve:guest:150");
  assert.deepEqual(a.sources.wazuh, { id: "004" });
  assert.equal(a.linkMethod, "ip_hostname");
});

test("IP without matching hostname does not link", () => {
  const out = linkAssets({ ...base, guests: [guest(150, "mgmt", [], ["192.168.0.200"])], agents: [agent("004", "other", [], "192.168.0.200")] });
  assert.equal(byKey(out, "pve:guest:150").sources.wazuh, undefined);
  assert.ok(byKey(out, "wazuh:agent:004"));
});

test("nodes link by IP and name", () => {
  const out = linkAssets({ ...base, nodes: [{ name: "norco", ip: "192.168.0.10" }], agents: [agent("001", "norco", [], "192.168.0.10")] });
  const a = byKey(out, "pve:node:norco");
  assert.equal(a.class, "host");
  assert.deepEqual(a.sources, { pve: { node: "norco" }, wazuh: { id: "001" } });
});

test("manual link overrides ambiguity", () => {
  const out = linkAssets({ ...base, guests: [guest(109, "docker", [MAC1])], agents: [agent("003", "docker", [MAC1], "", "disconnected"), agent("007", "docker", [MAC1])], manualLinks: [{ assetKey: "pve:guest:109", source: "wazuh", sourceId: "007" }] });
  const a = byKey(out, "pve:guest:109");
  assert.deepEqual(a.sources.wazuh, { id: "007" });
  assert.equal(a.linkMethod, "manual");
  assert.equal(out.ambiguous.length, 0);
  assert.ok(byKey(out, "wazuh:agent:003"), "unclaimed old agent stays visible");
});

test("two assets claiming one agent are both ambiguous", () => {
  const out = linkAssets({ ...base, guests: [guest(1, "a", [MAC1]), guest(2, "b", [MAC1])], agents: [agent("003", "x", [MAC1])] });
  assert.equal(byKey(out, "pve:guest:1").ambiguous, true);
  assert.equal(byKey(out, "pve:guest:2").ambiguous, true);
  assert.equal(out.ambiguous.length, 2);
});

test("unlinked roaming agent becomes a roaming asset", () => {
  const out = linkAssets({ ...base, agents: [agent("010", "legion")], classes: { roaming: ["legion"], appliances: [] } });
  const a = byKey(out, "wazuh:agent:010");
  assert.equal(a.class, "roaming");
  assert.deepEqual(a.sources, { wazuh: { id: "010" } });
});

test("configured appliance guest is class appliance", () => {
  const out = linkAssets({ ...base, guests: [guest(102, "haos")], classes: { roaming: [], appliances: ["haos"] } });
  assert.equal(byKey(out, "pve:guest:102").class, "appliance");
});

test("docker host attaches to its configured asset", () => {
  const out = linkAssets({ ...base, guests: [guest(109, "docker")], dockerHosts: [{ name: "docker-vm", assetKey: "pve:guest:109" }] });
  assert.deepEqual(byKey(out, "pve:guest:109").sources.docker, { name: "docker-vm" });
});
