import test from "node:test";
import assert from "node:assert/strict";
import { agentConnected, agentPresent } from "../src/checks/agent.mjs";
import { runCheck } from "../src/checks/runner.mjs";
import { memoryStore, putOk, noHolds } from "./helpers/stores.mjs";

const NOW = 50_000_000;
const asset = (cls, wazuh = { id: "003" }) => ({ assetKey: "pve:guest:109", class: cls, name: "docker", sources: wazuh ? { pve: {}, wazuh } : { pve: {} } });
const withAgent = (status, lastKeepAlive = NOW - 3 * 3600_000) => {
  const s = memoryStore();
  putOk(s, "wazuh", [{ assetKey: "wazuh:agent:003", kind: "wazuh.agent", value: { id: "003", name: "docker", status, lastKeepAlive } }], NOW);
  return s;
};
const run = (check, a, store) => runCheck(check, a, { store, holds: noHolds, config: {}, now: NOW });

test("active agent is ok", () => assert.equal(run(agentConnected, asset("guest"), withAgent("active", NOW)).state, "ok"));

test("disconnected host agent is an issue with age", () => {
  const r = run(agentConnected, asset("host"), withAgent("disconnected"));
  assert.equal(r.state, "issue");
  assert.match(r.reason, /agent disconnected, last seen 3 h ago/u);
});

test("never connected agent is an issue", () => {
  assert.match(run(agentConnected, asset("guest"), withAgent("never_connected", null)).reason, /never_connected/u);
});

test("roaming agent away is unknown and flagged", () => {
  const r = run(agentConnected, asset("roaming"), withAgent("disconnected"));
  assert.equal(r.state, "unknown");
  assert.equal(r.roaming, true);
  assert.match(r.reason, /^away since /u);
});

test("agent_connected does not apply without an agent", () => {
  assert.equal(run(agentConnected, asset("guest", null), memoryStore()).state, "not_applicable");
});

test("guest without agent is an issue", () => {
  const r = run(agentPresent, asset("guest", null), memoryStore());
  assert.deepEqual([r.state, r.reason], ["issue", "no Wazuh agent installed"]);
});

test("guest with agent is ok", () => assert.equal(run(agentPresent, asset("guest"), memoryStore()).state, "ok"));

test("appliance is not_applicable with a clear reason", () => {
  const r = run(agentPresent, asset("appliance", null), memoryStore());
  assert.deepEqual([r.state, r.reason], ["not_applicable", "no agent possible"]);
});
