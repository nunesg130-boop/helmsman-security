import test from "node:test";
import assert from "node:assert/strict";
import { exposureRoutes, exposureGates, exposureExpectedPrivate } from "../src/checks/exposure.mjs";
import { CHECKS } from "../src/checks/index.mjs";
import { runCheck } from "../src/checks/runner.mjs";
import { memoryStore, putOk, noHolds } from "./helpers/stores.mjs";

const NOW = 50_000_000;
const CONFIG = { exposure: { caddy: { assetKey: "pve:guest:105" }, cloudflare: { assetKey: "pve:guest:108" }, expectedPrivate: ["vault.jellofin.com", "security.jellofin.com"] } };
const caddy = { assetKey: "pve:guest:105", class: "guest", name: "caddy", sources: {} };
const cloudflared = { assetKey: "pve:guest:108", class: "guest", name: "cloudflared", sources: {} };
const other = { assetKey: "pve:guest:100", class: "guest", name: "Jelly-Arr", sources: {} };
const svc = (hostname, extra = {}) => ({ hostname, path: null, paths: [{ entry: "forward", reachable: true, gate: "none", gateReason: null }], gate: "none", gateReason: null, upstream: "192.168.0.7:80", assetKey: "pve:guest:100", listening: null, exposure: "internet", ...extra });
const problem = (kind, origin, hostname = "a.jellofin.com", reason = "why") => ({ kind, origin, hostname, upstream: "192.168.0.7:80", assetKey: null, reason });
function run(check, asset, map, { at = NOW, fail = false, config = CONFIG } = {}) {
  const s = memoryStore();
  if (map) putOk(s, "exposure", [{ assetKey: "_global", kind: "exposure.map", value: { services: [], problems: [], machines: [], sources: { caddy: "ok", cloudflare: "ok", router: "declared" }, ...map } }], at);
  if (fail) { const id = s.beginRun("exposure", NOW); s.finishRun(id, "failed", { error: "boom" }, NOW); }
  return runCheck(check, asset, { store: s, holds: noHolds, config, now: NOW });
}

test("the three checks are registered and apply only to the entry machines", () => {
  for (const c of [exposureRoutes, exposureGates, exposureExpectedPrivate]) assert.ok(CHECKS.includes(c));
  assert.equal(run(exposureRoutes, other, {}).state, "not_applicable");
  assert.equal(run(exposureGates, cloudflared, {}).state, "not_applicable");
  assert.equal(run(exposureRoutes, caddy, {}, { config: {} }).state, "not_applicable");
});
test("exposure_routes is ok with the number of public hostnames", () => {
  const r = run(exposureRoutes, caddy, { services: [svc("a.jellofin.com"), svc("a.jellofin.com", { path: "/api/*" }), svc("b.jellofin.com"), svc("c.jellofin.com", { exposure: "lan", paths: [] })] });
  assert.deepEqual([r.state, r.reason], ["ok", "2 public hostnames, every route resolved"]);
});
test("exposure_routes lists route problems as an issue, each on the machine it came from", () => {
  const problems = [problem("dangling_route", "caddy"), problem("upstream_not_in_inventory", "caddy", "b.jellofin.com"), problem("upstream_unresolvable", "cloudflare", "c.jellofin.com"), problem("restriction_bypassed_by_tunnel", "cloudflare", "d.jellofin.com")];
  const onCaddy = run(exposureRoutes, caddy, { problems });
  assert.equal(onCaddy.state, "issue");
  assert.match(onCaddy.reason, /a\.jellofin\.com: why/u);
  assert.match(onCaddy.reason, /b\.jellofin\.com/u);
  assert.doesNotMatch(onCaddy.reason, /c\.jellofin\.com/u);
  const onTunnel = run(exposureRoutes, cloudflared, { problems });
  assert.equal(onTunnel.state, "issue");
  assert.match(onTunnel.reason, /c\.jellofin\.com/u);
  assert.match(onTunnel.reason, /d\.jellofin\.com/u);
});
test("a router forward to an unknown address shows as an issue on the entry proxy", () => {
  const r = run(exposureRoutes, caddy, { problems: [{ ...problem("upstream_not_in_inventory", "router", null, "the router forwards port 3389 to 192.168.0.77, an address no known machine has") }] });
  assert.equal(r.state, "issue");
  assert.match(r.reason, /3389/u);
  assert.equal(run(exposureRoutes, cloudflared, { problems: [problem("upstream_not_in_inventory", "router", null)] }).state, "ok");
});
test("exposure_routes is unknown when its source is unreadable or only unsupported conditions stand in the way", () => {
  assert.equal(run(exposureRoutes, caddy, { sources: { caddy: "stale", cloudflare: "ok", router: "declared" } }).state, "unknown");
  assert.equal(run(exposureRoutes, cloudflared, { sources: { caddy: "ok", cloudflare: "failed", router: "declared" } }).state, "unknown");
  assert.equal(run(exposureRoutes, cloudflared, { sources: { caddy: "failed", cloudflare: "ok", router: "declared" } }).state, "ok");
  const r = run(exposureRoutes, caddy, { problems: [problem("unsupported_condition", "caddy", "a.jellofin.com", "unsupported Caddy matcher: header")] });
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /unsupported Caddy matcher: header/u);
});
test("exposure_gates is unknown naming unverified gates, ok with the verified count otherwise", () => {
  const services = [svc("a.jellofin.com", { gate: "authentik" }), svc("b.jellofin.com", { gate: "verified-mixed" }), svc("c.jellofin.com")];
  assert.deepEqual([run(exposureGates, caddy, { services }).state, run(exposureGates, caddy, { services }).reason], ["ok", "2 gated routes verified"]);
  const r = run(exposureGates, caddy, { services: [...services, svc("d.jellofin.com", { gate: "unknown", gateReason: "handle_response doesn't match" })] });
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /d\.jellofin\.com/u);
  assert.equal(run(exposureGates, caddy, { services, sources: { caddy: "missing", cloudflare: "ok", router: "declared" } }).state, "unknown");
  assert.equal(run(exposureGates, caddy, { services: [svc("d.jellofin.com", { gate: "unknown", exposure: "lan" })] }).state, "ok", "a gate on a route nobody outside can reach doesn't matter");
});
test("exposure_expected_private names expected-private hostnames that are public or undetermined", () => {
  const pub = run(exposureExpectedPrivate, caddy, { services: [svc("vault.jellofin.com"), svc("security.jellofin.com", { exposure: "lan" })] });
  assert.equal(pub.state, "issue");
  assert.match(pub.reason, /vault\.jellofin\.com/u);
  assert.doesNotMatch(pub.reason, /security/u);
  const unk = run(exposureExpectedPrivate, caddy, { services: [svc("vault.jellofin.com", { exposure: "unknown" }), svc("security.jellofin.com", { exposure: "lan" })] });
  assert.equal(unk.state, "unknown");
  assert.match(unk.reason, /vault\.jellofin\.com/u);
  assert.equal(run(exposureExpectedPrivate, caddy, { services: [svc("vault.jellofin.com", { exposure: "lan" })] }).state, "ok");
  assert.equal(run(exposureExpectedPrivate, caddy, { services: [], sources: { caddy: "stale", cloudflare: "ok", router: "declared" } }).state, "unknown");
  assert.equal(run(exposureExpectedPrivate, caddy, { services: [] }, { config: { exposure: { ...CONFIG.exposure, expectedPrivate: [] } } }).state, "not_applicable");
});
test("a failed, stale or missing exposure map makes all three unknown", () => {
  for (const c of [exposureRoutes, exposureGates, exposureExpectedPrivate]) {
    assert.equal(run(c, caddy, {}, { fail: true }).state, "unknown", c.id);
    assert.equal(run(c, caddy, {}, { at: NOW - 3 * 3600_000 }).state, "unknown", c.id);
    assert.equal(run(c, caddy, null).state, "unknown", c.id);
  }
});
