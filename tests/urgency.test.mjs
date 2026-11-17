import test from "node:test";
import assert from "node:assert/strict";
import { findingExposure, urgency, URGENCY_RULES } from "../src/vuln/urgency.mjs";

const FIX = "fix-available-not-applied";
const u = (o) => urgency({ exposure: "service", possible: null, kev: false, severity: "high", fixState: FIX, lowConfidence: false, accepted: false, ...o });

test("rules are versioned", () => assert.equal(URGENCY_RULES, 1));

test("truth table: exposure x KEV x severity x fix state", () => {
  const rows = [
    // exposure, kev, severity, fixState, urgent
    ["service", true, "low", "no-fix-exists", true],
    ["service", false, "critical", FIX, true],
    ["service", false, "high", FIX, true],
    ["service", false, "high", "no-fix-exists", false],
    ["service", false, "high", "unknown", false],
    ["service", false, "medium", FIX, false],
    ["service", null, "high", FIX, true],
    ["service", null, "medium", FIX, null],
    ["gated", true, "low", "unknown", true],
    ["gated", false, "critical", FIX, false],
    ["gated", null, "critical", FIX, null],
    ["host", true, "medium", FIX, true],
    ["host", false, "critical", FIX, false],
    ["host", null, "critical", FIX, null],
    ["none", true, "critical", FIX, false],
    ["none", null, "critical", FIX, false],
    ["unknown", true, "critical", FIX, null],
    ["unknown", false, "low", "no-fix-exists", null]
  ];
  for (const [exposure, kev, severity, fixState, urgent] of rows) {
    assert.equal(u({ exposure, kev, severity, fixState }).urgent, urgent, JSON.stringify([exposure, kev, severity, fixState]));
  }
});
test("possibly urgent: what would be urgent if the uncertain part went the wrong way", () => {
  assert.equal(u({ exposure: "host", possible: "service" }).possiblyUrgent, true, "heuristic exposure");
  assert.equal(u({ exposure: "host", possible: "gated" }).possiblyUrgent, false);
  assert.equal(u({ exposure: "host", possible: null }).possiblyUrgent, false);
  assert.equal(u({ exposure: "unknown" }).possiblyUrgent, true, "unknown exposure read as service");
  assert.equal(u({ exposure: "unknown", severity: "low", fixState: "unknown" }).possiblyUrgent, false);
  assert.equal(u({ exposure: "host", kev: null }).possiblyUrgent, true, "unknown KEV read as listed");
  assert.equal(u({ exposure: "none", kev: null }).possiblyUrgent, false);
  assert.equal(u({ exposure: "service" }).possiblyUrgent, false, "already urgent");
});
test("low-confidence and accepted findings are never urgent or possibly urgent", () => {
  for (const o of [{ lowConfidence: true }, { accepted: true }]) {
    assert.deepEqual([u({ ...o, kev: true }).urgent, u({ ...o, kev: true }).possiblyUrgent], [false, false]);
    assert.deepEqual([u({ ...o, exposure: "unknown", kev: null }).urgent, u({ ...o, exposure: "unknown" }).possiblyUrgent], [false, false]);
  }
});
test("every answer explains itself", () => {
  assert.match(u({ kev: true }).why, /actively exploited \(KEV\)/u);
  assert.match(u({}).why, /fix is available/u);
  assert.match(u({ exposure: "unknown" }).why, /exposure/u);
  assert.match(u({ exposure: "host", kev: null }).why, /KEV list/u);
  assert.match(u({ accepted: true }).why, /accepted/u);
  assert.match(u({ lowConfidence: true }).why, /low confidence/u);
  assert.match(u({ exposure: "host", possible: "service" }).why, /may be the one serving/u);
});

// Machines and services as the exposure map stores them.
const svc = (extra = {}) => ({ hostname: "jellyprox.jellofin.com", path: null, gate: "none", upstream: "192.168.0.7:8096", assetKey: "pve:guest:100", process: "jellyfin", container: null, exposure: "internet", ...extra });
const app = (services = [0]) => ({ exposure: "internet", role: "app", services });
const f = (name) => ({ pkg: { name, version: "1" } });
const fe = (name, machine, services = [svc()]) => findingExposure(f(name), machine, services);

test("an unknown or missing machine gives unknown exposure; a lan machine none", () => {
  assert.deepEqual(fe("openssl", { exposure: "unknown", role: null, services: [] }), { exposure: "unknown", basis: "unknown", possible: null, gate: null, via: null });
  assert.deepEqual(fe("openssl", undefined), { exposure: "unknown", basis: "unknown", possible: null, gate: null, via: null });
  assert.deepEqual(fe("openssl", { exposure: "lan", role: null, services: [] }), { exposure: "none", basis: "route", possible: null, gate: null, via: null });
});
test("the entry machine and the gate are service-exposed as a whole", () => {
  assert.equal(fe("openssl", { exposure: "internet", role: "entry", services: [] }).exposure, "service");
  assert.deepEqual(fe("openssl", { exposure: "internet", role: "gate", services: [] }), { exposure: "service", basis: "route", possible: null, gate: "none", via: null });
});
test("a directly forwarded machine is host-exposed and possibly service-exposed", () => {
  assert.deepEqual(fe("openssh-server", { exposure: "internet", role: "direct", services: [] }), { exposure: "host", basis: "route", possible: "service", gate: null, via: null });
});
test("an app machine is host-exposed; a package matching the listening process is possibly service-exposed", () => {
  assert.deepEqual(fe("openssl", app()), { exposure: "host", basis: "route", possible: null, gate: null, via: null });
  assert.deepEqual(fe("jellyfin", app()), { exposure: "host", basis: "route", possible: "service", gate: "none", via: "jellyprox.jellofin.com" });
  assert.equal(fe("jellyfin-server", app()).possible, "service");
  assert.equal(fe("jellyfin-web", app()).possible, "service", "process name is a prefix");
  assert.equal(fe("Jellyfin", app(), [svc({ process: "JELLYFIN" })]).possible, "service");
  assert.equal(fe("jq", app(), [svc({ process: "j" })]).possible, null, "a one-letter process name matches nothing");
  assert.equal(fe("jellyfin", app(), [svc({ process: null })]).possible, null);
});
test("behind a verified gate the heuristic is 'gated'; behind none or unknown it is 'service'", () => {
  for (const gate of ["authentik", "cloudflare-access", "verified-mixed"]) assert.deepEqual([fe("jellyfin", app(), [svc({ gate })]).possible, fe("jellyfin", app(), [svc({ gate })]).gate], ["gated", gate]);
  assert.deepEqual([fe("jellyfin", app(), [svc({ gate: "unknown" })]).possible, fe("jellyfin", app(), [svc({ gate: "unknown" })]).gate], ["service", "unknown"]);
  assert.equal(fe("jellyfin", app(), [svc({ gate: "none" })]).possible, "service");
});
test("with several routes to the same process, the weakest gate decides", () => {
  const services = [svc({ gate: "authentik" }), svc({ hostname: "open.jellofin.com", gate: "none" })];
  assert.deepEqual([fe("jellyfin", app([0, 1]), services).possible, fe("jellyfin", app([0, 1]), services).via], ["service", "open.jellofin.com"]);
  const unknown = [svc({ gate: "authentik" }), svc({ hostname: "odd.jellofin.com", gate: "unknown" })];
  assert.equal(fe("jellyfin", app([0, 1]), unknown).gate, "unknown");
});
test("routes that aren't public, or belong to another machine, don't count", () => {
  assert.equal(fe("jellyfin", app(), [svc({ exposure: "lan" })]).possible, null);
  assert.equal(fe("jellyfin", app([]), [svc()]).possible, null);
});
test("kernel packages never get a heuristic upgrade", () => {
  assert.equal(fe("linux-image-6.12.57+deb13-amd64", app(), [svc({ process: "linux" })]).possible, null);
});

const judge = (name, machine, services, finding) => {
  const e = findingExposure(f(name), machine, services);
  return { ...e, ...urgency({ exposure: e.exposure, possible: e.possible, lowConfidence: false, accepted: false, ...finding }) };
};
test("Jelly-Arr: a kernel KEV is urgent; a high fixable openssl flaw without KEV is not, and not possibly", () => {
  assert.equal(judge("linux-image-6.1.0-31-amd64", app(), [svc()], { kev: true, severity: "high", fixState: FIX }).urgent, true);
  const openssl = judge("openssl", app(), [svc()], { kev: false, severity: "high", fixState: FIX });
  assert.deepEqual([openssl.urgent, openssl.possiblyUrgent], [false, false]);
});
test("Jelly-Arr: a high fixable flaw in the jellyfin package is possibly urgent, not confirmed", () => {
  const j = judge("jellyfin", app(), [svc()], { kev: false, severity: "high", fixState: FIX });
  assert.deepEqual([j.urgent, j.possiblyUrgent, j.possible], [false, true, "service"]);
});
test("the same package behind a verified gate is not possibly urgent unless KEV", () => {
  const gated = [svc({ gate: "authentik" })];
  assert.deepEqual([judge("jellyfin", app(), gated, { kev: false, severity: "high", fixState: FIX }).possiblyUrgent, judge("jellyfin", app(), gated, { kev: false, severity: "high", fixState: FIX }).possible], [false, "gated"]);
  assert.equal(judge("jellyfin", app(), gated, { kev: true, severity: "high", fixState: FIX }).urgent, true);
});
test("behind an unknown gate, or a protected tunnel plus an ungated forward, the heuristic is service, never gated", () => {
  assert.equal(judge("jellyfin", app(), [svc({ gate: "unknown" })], { kev: false, severity: "high", fixState: FIX }).possiblyUrgent, true);
  const mixedPaths = svc({ gate: "none", paths: [{ entry: "forward", reachable: true, gate: "none" }, { entry: "tunnel-direct", reachable: true, gate: "cloudflare-access" }] });
  assert.equal(judge("jellyfin", app(), [mixedPaths], { kev: false, severity: "high", fixState: FIX }).possible, "service");
});
test("docker-auth (the gate): a high fixable flaw is urgent", () => {
  assert.equal(judge("openssl", { exposure: "internet", role: "gate", services: [] }, [], { kev: false, severity: "high", fixState: FIX }).urgent, true);
});
test("a confirmed finding with only heuristic exposure is never suppressed; stale KEV gives null", () => {
  const j = judge("jellyfin", app(), [svc()], { kev: null, severity: "medium", fixState: "no-fix-exists" });
  assert.deepEqual([j.urgent, j.possiblyUrgent, j.exposure], [null, true, "host"]);
});
