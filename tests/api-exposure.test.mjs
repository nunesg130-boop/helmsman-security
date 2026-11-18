import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import https from "node:https";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { LedgerStore } from "../src/ledger.mjs";
import { HoldStore } from "../src/holds.mjs";
import { FindingStore } from "../src/vuln/findings.mjs";
import { CredentialStore, createSecretBox } from "../src/secrets.mjs";
import { createPublicServer } from "../src/api/public.mjs";

const tls = { key: readFileSync(new URL("./fixtures/tls/key.pem", import.meta.url)), cert: readFileSync(new URL("./fixtures/tls/cert.pem", import.meta.url)) };
const TOKEN = "read-token-abc";
const CF_TOKEN = "cf-secret-token-value";
const FIX = "fix-available-not-applied";
const svc = (hostname, assetKey, extra = {}) => ({ hostname, path: null, paths: [{ entry: "forward", reachable: true, gate: "none", gateReason: null }], gate: "none", gateReason: null, upstream: "192.168.0.7:8096", assetKey, container: null, process: "jellyfin", listening: true, exposure: "internet", publicDns: true, jwtRequired: null, reason: "reachable from the internet through: router forward → Caddy", ...extra });
const MAP = {
  services: [svc("jellyprox.jellofin.com", "pve:guest:100"), svc("odd.jellofin.com", "pve:guest:109", { gate: "unknown", gateReason: "a handle_response block doesn't match the verified Authentik pattern (forward path)", process: "paperless", upstream: "192.168.0.109:8000", listening: null })],
  machines: [
    { assetKey: "pve:guest:100", name: "Jelly-Arr", exposure: "internet", role: "app", services: [0], directForwards: [], reason: "serves jellyprox.jellofin.com" },
    { assetKey: "pve:guest:109", name: "docker-apps", exposure: "internet", role: "app", services: [1], directForwards: [], reason: "serves odd.jellofin.com" },
    { assetKey: "pve:guest:201", name: "docker-auth", exposure: "internet", role: "gate", services: [], directForwards: [], reason: "runs the login gate" },
    { assetKey: "pve:guest:110", name: "pihole", exposure: "lan", role: null, services: [], directForwards: [], reason: "no public route" }
  ],
  problems: [{ kind: "unverified_gate", origin: "caddy", hostname: "odd.jellofin.com", upstream: "192.168.0.109:8000", assetKey: "pve:guest:109", reason: "not verified" }],
  sources: { caddy: "ok", cloudflare: "ok", router: "declared" }, router: { portForwards: 2, upnp: false, dmz: false, ipv6Inbound: false },
  declaredAddresses: { "pve:guest:110": ["192.168.0.2"] }
};

async function setup({ map = MAP, mapAt = Date.now(), failExposure = false, kev = true, uncovered = 0, configured = true, imageRows = [] } = {}) {
  const now = Date.now();
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const holds = new HoldStore(db, "default");
  const credentials = new CredentialStore(db, "default", createSecretBox(randomBytes(32)));
  credentials.set("api.readToken", TOKEN, 1);
  credentials.set("cloudflare.apiToken", CF_TOKEN, 1);
  const names = { "pve:guest:100": "Jelly-Arr", "pve:guest:109": "docker-apps", "pve:guest:201": "docker-auth", "pve:guest:110": "pihole", "pve:guest:111": "extra" };
  for (const [key, name] of Object.entries(names)) db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('default', ?, 'guest', ?, '{}', ?)").run(key, name, now);
  new LedgerStore(db, "default").write([...Object.keys(names).map((assetKey, i) => ({ assetKey, checkId: "vuln_coverage_host", state: i < uncovered ? "unknown" : "ok", reason: "x", evidence: [], roaming: false })),
    ...imageRows.map(([assetKey, state]) => ({ assetKey, checkId: "vuln_coverage_images", state, reason: "x", evidence: [], roaming: false }))], now);
  const f = new FindingStore(db, "default");
  const mk = (assetKey, cve, name, over = {}) => ({ assetKey, cve, pkg: { name, version: "1.0", arch: "amd64", type: "deb" }, severity: "high", cvss: 7.5, fixState: FIX, fixedVersion: "1.1", lowConfidence: false, condition: "Package less than 1.1", recognisedCondition: true, detectedAt: 1, ...over });
  f.replaceSource("wazuh", [
    mk("pve:guest:100", "CVE-KERNEL", "linux-image-6.1.0-31-amd64"), // KEV on an app machine: urgent
    mk("pve:guest:100", "CVE-JELLY", "jellyfin"), // heuristic: possibly urgent
    mk("pve:guest:100", "CVE-SSL", "openssl"), // neither
    mk("pve:guest:109", "CVE-PAPER", "paperless", { severity: "medium" }),
    mk("pve:guest:201", "CVE-AUTH", "openssl"), // gate machine, high fixable: urgent
    mk("pve:guest:110", "CVE-LAN", "openssl", { severity: "critical" }),
    mk("wazuh:agent:099", "CVE-STRAY", "openssl")
  ], now);
  if (kev) f.replaceKev([{ cve: "CVE-KERNEL", dateAdded: "2026-01-01", ransomware: false }], now);
  f.replaceEpss([{ cve: "CVE-KERNEL", score: 0.9, percentile: 0.99 }], now);
  const r = store.beginRun("wazuh-vulns", now); store.finishRun(r, "ok", {}, now);
  if (map) { const e = store.beginRun("exposure", mapAt); store.put(e, { assetKey: "_global", kind: "exposure.map", source: "exposure", value: map, collectedAt: mapAt, staleAfterMs: 45 * 60_000 }); store.finishRun(e, "ok", {}, mapAt); }
  if (failExposure) { const e = store.beginRun("exposure", now); store.finishRun(e, "failed", { error: "boom" }, now); }
  const srv = await createPublicServer({ db, tenantId: "default", store, credentials, tls, host: "127.0.0.1", port: 0, version: "0.1.0", exposureConfigured: configured });
  return { srv, holds };
}
function req(port, path, { method = "GET", token = TOKEN } = {}) {
  return new Promise((resolve, reject) => {
    const r = https.request({ host: "127.0.0.1", port, path, method, rejectUnauthorized: false, headers: token ? { authorization: `Bearer ${token}` } : {} }, (res) => {
      let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolve({ status: res.statusCode, text: b, body: b ? JSON.parse(b) : null }));
    });
    r.on("error", reject); r.end();
  });
}
const using = async (opts, fn) => { const ctx = await setup(opts); try { await fn(ctx.srv.port, ctx); } finally { await ctx.srv.close(); } };
const byCve = (items) => Object.fromEntries(items.map((i) => [i.cve, i]));

test("findings carry exposure, gate, urgency and acceptance", () => using({}, async (port) => {
  const { body } = await req(port, "/api/v1/vulnerabilities");
  const f = byCve(body.items);
  assert.equal(body.exposureStatus, "ok");
  assert.deepEqual([f["CVE-KERNEL"].exposure, f["CVE-KERNEL"].exposureBasis, f["CVE-KERNEL"].urgent, f["CVE-KERNEL"].accepted], ["host", "route", true, null]);
  assert.deepEqual([f["CVE-JELLY"].urgent, f["CVE-JELLY"].possiblyUrgent, f["CVE-JELLY"].possibleExposure, f["CVE-JELLY"].via, f["CVE-JELLY"].gate], [false, true, "service", "jellyprox.jellofin.com", "none"]);
  assert.deepEqual([f["CVE-SSL"].urgent, f["CVE-SSL"].possiblyUrgent], [false, false]);
  assert.deepEqual([f["CVE-AUTH"].exposure, f["CVE-AUTH"].urgent], ["service", true]);
  assert.deepEqual([f["CVE-LAN"].exposure, f["CVE-LAN"].urgent], ["none", false]);
  assert.deepEqual([f["CVE-STRAY"].exposure, f["CVE-STRAY"].urgent, f["CVE-STRAY"].possiblyUrgent], ["unknown", null, true]);
  assert.equal(typeof f["CVE-KERNEL"].urgencyWhy, "string");
}));
test("an unknown gate is shown as unknown on the finding and in the exposure map", () => using({}, async (port) => {
  const f = byCve((await req(port, "/api/v1/vulnerabilities")).body.items);
  assert.deepEqual([f["CVE-PAPER"].gate, f["CVE-PAPER"].possibleExposure], ["unknown", "service"]);
  const ex = (await req(port, "/api/v1/exposure")).body;
  const odd = ex.services.find((s) => s.hostname === "odd.jellofin.com");
  assert.equal(odd.gate, "unknown");
  assert.match(odd.gateReason, /doesn't match the verified Authentik pattern/u);
}));
test("urgent and possiblyUrgent filters, with totals and paging over the filtered set", () => using({}, async (port) => {
  const urgent = (await req(port, "/api/v1/vulnerabilities?urgent=true")).body;
  assert.deepEqual([urgent.items.map((i) => i.cve).sort(), urgent.total], [["CVE-AUTH", "CVE-KERNEL"], 2]);
  assert.deepEqual((await req(port, "/api/v1/vulnerabilities?urgent=unknown")).body.items.map((i) => i.cve), ["CVE-STRAY"]);
  const possible = (await req(port, "/api/v1/vulnerabilities?possiblyUrgent=true")).body;
  assert.deepEqual(possible.items.map((i) => i.cve).sort(), ["CVE-JELLY", "CVE-STRAY"]);
  const paged = (await req(port, "/api/v1/vulnerabilities?urgent=true&limit=1&offset=1")).body;
  assert.deepEqual([paged.items.length, paged.total, paged.limit, paged.offset], [1, 2, 1, 1]);
  assert.deepEqual((await req(port, "/api/v1/vulnerabilities?urgent=true&asset=pve%3Aguest%3A201")).body.items.map((i) => i.cve), ["CVE-AUTH"]);
  assert.equal((await req(port, "/api/v1/vulnerabilities?urgent=maybe")).status, 400);
  assert.equal((await req(port, "/api/v1/vulnerabilities?possiblyUrgent=false")).status, 400);
}));
test("without a usable exposure map, urgent=true is refused and urgency reads as unknown", async () => {
  for (const opts of [{ map: null }, { mapAt: Date.now() - 3 * 3600_000 }, { failExposure: true }]) {
    await using(opts, async (port) => {
      const r = await req(port, "/api/v1/vulnerabilities?urgent=true");
      assert.equal(r.status, 409, JSON.stringify(opts));
      assert.match(r.body.error, /exposure map/u);
      const all = (await req(port, "/api/v1/vulnerabilities")).body;
      assert.notEqual(all.exposureStatus, "ok");
      assert.ok(all.items.every((i) => i.exposure === "unknown" && i.urgent === null));
      assert.equal((await req(port, "/api/v1/vulnerabilities?urgent=unknown")).body.total, 7);
    });
  }
});
test("an accepted finding is marked, stops being urgent, and leaves the urgent list", () => using({}, async (port, { holds }) => {
  const id = holds.add({ kind: "acceptance", assetKey: "pve:guest:201", checkId: "CVE-AUTH", product: "openssl", version: "1.0", reason: "isolated test box", context: { kev: false, exposure: "service", gate: "none" } }, Date.now());
  const f = byCve((await req(port, "/api/v1/vulnerabilities")).body.items);
  assert.deepEqual([f["CVE-AUTH"].accepted, f["CVE-AUTH"].urgent], [{ id, reason: "isolated test box" }, false]);
  assert.deepEqual((await req(port, "/api/v1/vulnerabilities?urgent=true")).body.items.map((i) => i.cve), ["CVE-KERNEL"]);
}));
test("GET /api/v1/exposure lists services, problems, sources and machines with names", () => using({}, async (port) => {
  const { status, body } = await req(port, "/api/v1/exposure");
  assert.equal(status, 200);
  assert.deepEqual([body.status, body.configured, body.services.length, body.problems.length], ["ok", true, 2, 1]);
  assert.deepEqual(body.sources, { caddy: "ok", cloudflare: "ok", router: "declared" });
  assert.ok(body.services.every((s) => "gate" in s && "gateReason" in s && "paths" in s));
  assert.equal(body.services[0].assetName, "Jelly-Arr");
  assert.deepEqual(body.machines.find((m) => m.assetKey === "pve:guest:201"), { assetKey: "pve:guest:201", assetName: "docker-auth", exposure: "internet", role: "gate", directForwards: [], reason: "runs the login gate" });
  assert.ok(body.collectedAt > 0);
  assert.deepEqual(body.declaredAddresses, [{ assetKey: "pve:guest:110", assetName: "pihole", ips: ["192.168.0.2"] }]);
}));
test("GET /api/v1/exposure without a usable map says so and gives no lists", async () => {
  await using({ map: null }, async (port) => {
    const { body } = await req(port, "/api/v1/exposure");
    assert.deepEqual([body.status, body.services, body.machines, body.problems, body.sources], ["missing", null, null, null, null]);
  });
  await using({ map: null, configured: false }, async (port) => assert.equal((await req(port, "/api/v1/exposure")).body.configured, false));
});
test("GET /api/v1/posture gives both scenarios, the rule versions and named deductions", () => using({}, async (port) => {
  const { status, body } = await req(port, "/api/v1/posture");
  assert.equal(status, 200);
  assert.deepEqual(body.rules, { urgency: 2, score: 1 });
  // Jelly-Arr: kernel 10 + jellyfin 3 + openssl 3 = 16 (pessimistic 23); docker-apps 0.5; docker-auth 10; pihole 3; stray 3 (pessimistic 10).
  assert.deepEqual([body.state, body.confirmed, body.pessimistic], ["scored", 67.5, 53.5]);
  assert.deepEqual(body.coverage, { inScope: 5, withoutFreshCoverage: 0 });
  assert.equal(body.deductions[0].assetName.length > 0, true);
  assert.deepEqual(body.unknowns, { urgencyUnknown: 1, exposureUnknown: 1, gateUnknown: 1, heuristic: 2 });
}));
test("the posture score is incomplete without the exposure map, a current KEV list, or enough coverage", async () => {
  await using({ map: null }, async (port) => {
    const { body } = await req(port, "/api/v1/posture");
    assert.deepEqual([body.state, body.confirmed, body.pessimistic], ["incomplete", null, null]);
    assert.match(body.incompleteReasons.join("; "), /exposure map is missing/u);
  });
  await using({ kev: false }, async (port) => assert.match((await req(port, "/api/v1/posture")).body.incompleteReasons.join("; "), /KEV/u));
  await using({ uncovered: 2 }, async (port) => assert.match((await req(port, "/api/v1/posture")).body.incompleteReasons.join("; "), /2 of 5 machines/u));
  await using({ uncovered: 1 }, async (port) => assert.equal((await req(port, "/api/v1/posture")).body.state, "scored"));
});
test("the new endpoints need the token, are GET-only, and never include the Cloudflare token", () => using({}, async (port) => {
  for (const path of ["/api/v1/exposure", "/api/v1/posture", "/api/v1/vulnerabilities?urgent=true", "/api/v1/summary"]) {
    assert.equal((await req(port, path, { token: null })).status, 401, path);
    assert.equal((await req(port, path, { method: "POST" })).status, 405, path);
    assert.ok(!(await req(port, path)).text.includes(CF_TOKEN), path);
  }
}));

// --- review fixes ---
test("a map whose own sources are unreadable doesn't support an urgent list or a score", async () => {
  await using({ map: { ...MAP, sources: { caddy: "failed", cloudflare: "ok", router: "declared", inventory: "ok" } } }, async (port) => {
    const r = await req(port, "/api/v1/vulnerabilities?urgent=true");
    assert.equal(r.status, 409);
    assert.match(r.body.error, /Caddy routes are failed/u);
    const p = (await req(port, "/api/v1/posture")).body;
    assert.equal(p.state, "incomplete");
    assert.match(p.incompleteReasons.join("; "), /Caddy routes are failed/u);
  });
});
test("an out-of-date KEV list refuses the urgent list instead of quietly leaving out KEV findings", () => using({ kev: false }, async (port) => {
  const r = await req(port, "/api/v1/vulnerabilities?urgent=true");
  assert.equal(r.status, 409);
  assert.match(r.body.error, /KEV/u);
}));

test("image coverage counts toward the score's coverage limit", async () => {
  await using({ imageRows: [["pve:guest:201", "unknown"], ["pve:guest:109", "unknown"], ["pve:guest:100", "ok"]] }, async (port) => {
    const p = (await req(port, "/api/v1/posture")).body;
    assert.deepEqual(p.coverage, { inScope: 8, withoutFreshCoverage: 2 });
    assert.equal(p.state, "incomplete");
  });
  await using({ imageRows: [["pve:guest:201", "not_applicable"], ["pve:guest:100", "ok"]] }, async (port) => assert.deepEqual((await req(port, "/api/v1/posture")).body.coverage, { inScope: 6, withoutFreshCoverage: 0 }));
});
