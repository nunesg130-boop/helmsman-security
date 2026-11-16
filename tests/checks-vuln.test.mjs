import test from "node:test";
import assert from "node:assert/strict";
import { vulnCoverageHost } from "../src/checks/vuln.mjs";
import { CHECKS } from "../src/checks/index.mjs";
import { runCheck } from "../src/checks/runner.mjs";
import { HoldStore } from "../src/holds.mjs";
import { memoryStore, putOk, noHolds } from "./helpers/stores.mjs";

const NOW = 50_000_000;
const CONFIG = { wazuh: { baseUrl: "https://w:55000", user: "u", indexer: { baseUrl: "https://w:9200", user: "ro", certSha256: "ab" } } };
const asset = { assetKey: "pve:guest:100", class: "guest", name: "Jelly-Arr", sources: { pve: { vmid: 100 }, wazuh: { id: "010" } } };
function store({ status = "active", scan = { count: 9256, newestDetectedAt: NOW - 1000 }, scanAt = NOW } = {}) {
  const s = memoryStore();
  putOk(s, "wazuh", [
    { assetKey: "wazuh:agent:010", kind: "wazuh.agent", value: { id: "010", name: "Jellyfin", status, lastKeepAlive: NOW } },
    { assetKey: "wazuh:agent:010", kind: "wazuh.packages", value: { items: [{ name: "x", version: "1" }], scanned: true } }
  ], NOW);
  if (scan) putOk(s, "wazuh-vulns", [{ assetKey: "wazuh:agent:010", kind: "wazuh.vulnscan", value: scan }], scanAt);
  return s;
}
const run = (s, a = asset, config = CONFIG, holds = noHolds) => runCheck(vulnCoverageHost, a, { store: s, holds, config, now: NOW });

test("the check is registered", () => assert.ok(CHECKS.includes(vulnCoverageHost)));
test("an agent with records gets ok with its count", () => {
  const r = run(store());
  assert.equal(r.state, "ok");
  assert.match(r.reason, /9256 known vulnerabilities on record/u);
});
test("an agent with no records is unknown, never ok", () => {
  const r = run(store({ scan: { count: 0, newestDetectedAt: null } }));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /can't tell 'clean' from 'not scanned'/u);
});
test("no vulnerability evidence yet is unknown", () => assert.equal(run(store({ scan: null })).state, "unknown"));
test("stale vulnerability evidence is unknown with its age", () => {
  const r = run(store({ scanAt: NOW - 4 * 3600_000 }));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /wazuh\.vulnscan last confirmed/u);
});
test("a failing vulnerability collection makes the machine unknown with the reason", () => {
  const s = store();
  const run2 = s.beginRun("wazuh-vulns", NOW);
  s.finishRun(run2, "failed", { error: "auth: HTTP 401" }, NOW);
  const r = run(s);
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /wazuh-vulns collection failing: auth: HTTP 401/u);
});
test("a disconnected agent's results are unknown", () => {
  const r = run(store({ status: "disconnected" }));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /agent is disconnected/u);
});
test("a machine without an agent is unknown", () => assert.match(run(store(), { ...asset, sources: { pve: {} } }).reason, /no Wazuh agent installed/u));
test("without an indexer configured the check is not_applicable", () => {
  const r = run(store(), asset, { wazuh: { baseUrl: "x", user: "u" } });
  assert.equal(r.state, "not_applicable");
  assert.match(r.reason, /vulnerability scanning not configured/u);
});
test("network devices are not_applicable", () => assert.equal(run(store(), { assetKey: "net:er605", class: "network", name: "er605", sources: {} }).state, "not_applicable"));
test("a whole-machine exclusion covers vuln_coverage_host", async () => {
  const { openDb } = await import("../src/db.mjs");
  const holds = new HoldStore(openDb(":memory:"), "default");
  holds.add({ kind: "exclusion", assetKey: asset.assetKey, checkId: "*", reason: "test VM" }, NOW);
  assert.equal(run(store(), asset, CONFIG, holds).state, "excluded");
});
