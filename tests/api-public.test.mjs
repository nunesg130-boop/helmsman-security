import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import https from "node:https";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { LedgerStore } from "../src/ledger.mjs";
import { CredentialStore, createSecretBox } from "../src/secrets.mjs";
import { createPublicServer } from "../src/api/public.mjs";

const tls = { key: readFileSync(new URL("./fixtures/tls/key.pem", import.meta.url)), cert: readFileSync(new URL("./fixtures/tls/cert.pem", import.meta.url)) };
const TOKEN = "read-token-abc";

async function setup() {
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const credentials = new CredentialStore(db, "default", createSecretBox(randomBytes(32)));
  credentials.set("api.readToken", TOKEN, 1);
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('default','pve:guest:109','guest','docker','{\"wazuh\":{\"id\":\"003\"}}',?), ('default','wazuh:agent:010','roaming','legion','{}',?)").run(Date.now(), Date.now());
  new LedgerStore(db, "default").write([
    { assetKey: "pve:guest:109", checkId: "agent_connected", state: "ok", reason: "agent connected", evidence: [], roaming: false },
    { assetKey: "pve:guest:109", checkId: "os_eol", state: "issue", reason: "debian 11 reached end of life", evidence: [], roaming: false },
    { assetKey: "pve:guest:109", checkId: "disk_health", state: "unknown", reason: "no pve.disks evidence", evidence: [], roaming: false },
    { assetKey: "wazuh:agent:010", checkId: "agent_connected", state: "unknown", reason: "away since x", evidence: [], roaming: true }
  ], Date.now());
  const run = store.beginRun("proxmox", 1);
  store.finishRun(run, "failed", { error: "auth: HTTP 401" }, 2);
  const w = store.beginRun("wazuh", 1);
  store.put(w, { assetKey: "wazuh:agent:003", kind: "wazuh.packages", source: "wazuh", value: { items: Array.from({ length: 5000 }, (_, i) => ({ name: `p${i}`, version: "1" })), scanned: true }, collectedAt: 1, staleAfterMs: 1 });
  store.finishRun(w, "ok", {}, 2);
  const srv = await createPublicServer({ db, tenantId: "default", store, credentials, tls, host: "127.0.0.1", port: 0, version: "0.1.0" });
  return srv;
}

function req(port, path, { method = "GET", token = TOKEN } = {}) {
  return new Promise((resolve, reject) => {
    const r = https.request({ host: "127.0.0.1", port, path, method, rejectUnauthorized: false, headers: token ? { authorization: `Bearer ${token}` } : {} }, (res) => {
      let b = "";
      res.on("data", (d) => { b += d; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: b ? JSON.parse(b) : null }));
    });
    r.on("error", reject);
    r.end();
  });
}

test("public API behaviour", async (t) => {
  const srv = await setup();
  t.after(() => srv.close());

  await t.test("POST is 405", async () => assert.equal((await req(srv.port, "/api/v1/summary", { method: "POST" })).status, 405));
  await t.test("missing token 401", async () => assert.equal((await req(srv.port, "/api/v1/summary", { token: null })).status, 401));
  await t.test("wrong token 401", async () => assert.equal((await req(srv.port, "/api/v1/summary", { token: "nope" })).status, 401));
  await t.test("unknown path 404", async () => assert.equal((await req(srv.port, "/api/v1/nothing")).status, 404));

  await t.test("health", async () => {
    const h = (await req(srv.port, "/api/v1/health")).body;
    assert.deepEqual([h.ok, h.version], [true, "0.1.0"]);
    assert.ok(h.lastCycleAt > 0);
  });

  await t.test("summary counts exclude roaming unknowns and show collector errors redacted", async () => {
    const r = await req(srv.port, "/api/v1/summary");
    assert.equal(r.headers["cache-control"], "no-store");
    assert.deepEqual(r.body.counts, { ok: 1, issue: 1, unknown: 1, not_applicable: 0, excluded: 0 });
    assert.equal(r.body.roamingAway, 1);
    const pve = r.body.collectors.find((c) => c.name === "proxmox");
    assert.deepEqual([pve.status, pve.lastError, pve.lastSuccessAt], ["failed", "auth: HTTP 401", null]);
  });

  await t.test("issues and unknowns list with asset names", async () => {
    const i = await req(srv.port, "/api/v1/issues");
    assert.deepEqual(i.body.items.map((x) => [x.assetName, x.checkId]), [["docker", "os_eol"]]);
    const u = await req(srv.port, "/api/v1/unknowns");
    assert.equal(u.body.total, 2);
    assert.ok(u.body.items.some((x) => x.roaming === true));
  });

  await t.test("pageSize capped at 200", async () => assert.equal((await req(srv.port, "/api/v1/unknowns?pageSize=5000")).body.pageSize, 200));

  await t.test("assets list with per-asset counts", async () => {
    const a = (await req(srv.port, "/api/v1/assets")).body.items.find((x) => x.assetKey === "pve:guest:109");
    assert.deepEqual(a.counts, { ok: 1, issue: 1, unknown: 1, not_applicable: 0, excluded: 0 });
  });

  await t.test("asset detail truncates 5000 packages to 2000", async () => {
    const d = (await req(srv.port, `/api/v1/assets/${encodeURIComponent("pve:guest:109")}`)).body;
    assert.equal(d.asset.name, "docker");
    assert.equal(d.checks.length, 3);
    assert.equal(d.software.length, 2000);
    assert.equal(d.softwareTruncated, true);
  });

  await t.test("unknown asset 404", async () => assert.equal((await req(srv.port, "/api/v1/assets/nope")).status, 404));
});

// --- vulnerabilities ---
async function vulnSetup({ feedsAt = Date.now(), runAt = Date.now(), failLast = false, epss = true, neverRun = false } = {}) {
  const { FindingStore } = await import("../src/vuln/findings.mjs");
  const db = openDb(":memory:");
  const store = new EvidenceStore(db, "default");
  const credentials = new CredentialStore(db, "default", createSecretBox(randomBytes(32)));
  credentials.set("api.readToken", TOKEN, 1);
  credentials.set("wazuh.indexerPassword", "ix-secret-value", 1);
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('default','pve:guest:100','guest','Jelly-Arr','{}',?)").run(Date.now());
  const f = new FindingStore(db, "default");
  const mk = (cve, over = {}) => ({ assetKey: "pve:guest:100", cve, pkg: { name: "openssl", version: "3.0-1", arch: "amd64", type: "deb" }, severity: "high", cvss: 7.5, fixState: "fix-available-not-applied", fixedVersion: "3.0-2", lowConfidence: false, condition: "Package less than 3.0-2", recognisedCondition: true, detectedAt: 1, ...over });
  f.replaceSource("wazuh", [mk("CVE-1", { severity: "critical", cvss: 9.8 }), mk("CVE-2"), mk("CVE-3", { assetKey: "wazuh:agent:099", fixState: "no-fix-exists", fixedVersion: null })], runAt);
  f.replaceKev([{ cve: "CVE-2", dateAdded: "2026-01-01", ransomware: false }], feedsAt);
  if (epss) f.replaceEpss([{ cve: "CVE-1", score: 0.9, percentile: 0.99 }], feedsAt);
  if (neverRun) {
    f.replaceSource("wazuh", [], runAt);
    const r0 = store.beginRun("wazuh-vulns", runAt);
    store.finishRun(r0, "failed", { error: "auth: HTTP 401" }, runAt);
  } else {
    const r = store.beginRun("wazuh-vulns", runAt);
    store.finishRun(r, "ok", {}, runAt);
  }
  if (failLast) { const r2 = store.beginRun("wazuh-vulns", Date.now()); store.finishRun(r2, "failed", { error: "auth: HTTP 401" }, Date.now()); }
  return createPublicServer({ db, tenantId: "default", store, credentials, tls, host: "127.0.0.1", port: 0, version: "0.1.0" });
}

test("GET /api/v1/vulnerabilities lists findings with names, KEV first, and filters", async () => {
  const srv = await vulnSetup();
  try {
    const all = await req(srv.port, "/api/v1/vulnerabilities");
    assert.equal(all.status, 200);
    assert.deepEqual(all.body.items.map((i) => i.cve), ["CVE-2", "CVE-1", "CVE-3"]);
    assert.deepEqual([all.body.items[0].assetName, all.body.items[2].assetName], ["Jelly-Arr", "wazuh:agent:099"]);
    assert.deepEqual([all.body.total, all.body.limit, all.body.offset, all.body.findingsStale, all.body.threatDataStale], [3, 50, 0, false, false]);
    assert.deepEqual((await req(srv.port, "/api/v1/vulnerabilities?kev=true")).body.items.map((i) => i.cve), ["CVE-2"]);
    assert.deepEqual((await req(srv.port, "/api/v1/vulnerabilities?fix=no-fix-exists")).body.items.map((i) => i.cve), ["CVE-3"]);
    assert.deepEqual((await req(srv.port, "/api/v1/vulnerabilities?severity=critical")).body.items.map((i) => i.cve), ["CVE-1"]);
    assert.deepEqual((await req(srv.port, "/api/v1/vulnerabilities?asset=pve%3Aguest%3A100&limit=1&offset=1")).body.items.map((i) => i.cve), ["CVE-1"]);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities?limit=5000")).body.limit, 200);
  } finally { await srv.close(); }
});

test("vulnerability endpoints reject bad filters, missing tokens and non-GET", async () => {
  const srv = await vulnSetup();
  try {
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities?fix=maybe")).status, 400);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities?severity=scary")).status, 400);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities?kev=yes")).status, 400);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities", { token: null })).status, 401);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities/summary", { token: "wrong" })).status, 401);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities", { method: "POST" })).status, 405);
  } finally { await srv.close(); }
});

test("summary lists per-asset counts with names and totals", async () => {
  const srv = await vulnSetup();
  try {
    const { body } = await req(srv.port, "/api/v1/vulnerabilities/summary");
    const jelly = body.assets.find((a) => a.assetKey === "pve:guest:100");
    assert.deepEqual([jelly.assetName, jelly.total, jelly.critical, jelly.high, jelly.fixAvailable, jelly.kev], ["Jelly-Arr", 2, 1, 1, 2, 1]);
    assert.deepEqual([body.totals.total, body.totals.noFix, body.totals.kev], [3, 1, 1]);
    assert.equal(body.collection.status, "ok");
  } finally { await srv.close(); }
});

test("old feeds and old or failed collection are reported as stale, never as current", async () => {
  const old = Date.now() - 30 * 86400_000;
  const srv = await vulnSetup({ feedsAt: old, runAt: old });
  try {
    const { body } = await req(srv.port, "/api/v1/vulnerabilities");
    assert.deepEqual([body.findingsStale, body.threatDataStale, body.items[0].kev, body.items[0].epss], [true, true, null, null]);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities/summary")).body.totals.kev, null);
  } finally { await srv.close(); }
  const failing = await vulnSetup({ failLast: true });
  try {
    const { body } = await req(failing.port, "/api/v1/vulnerabilities");
    assert.equal(body.findingsStale, true);
    assert.equal(body.collection.lastError, "auth: HTTP 401");
  } finally { await failing.close(); }
});

test("no vulnerability collection yet reads as stale with nothing listed", async () => {
  const srv = await setup();
  try {
    const { body } = await req(srv.port, "/api/v1/vulnerabilities");
    assert.deepEqual([body.total, body.findingsStale, body.collection.status], [0, true, "never_run"]);
  } finally { await srv.close(); }
});

test("the indexer password never appears in a vulnerability response", async () => {
  const srv = await vulnSetup();
  try {
    for (const path of ["/api/v1/vulnerabilities", "/api/v1/vulnerabilities/summary", "/api/v1/summary"]) {
      assert.ok(!JSON.stringify((await req(srv.port, path)).body).includes("ix-secret-value"), path);
    }
  } finally { await srv.close(); }
});

test("a fresh KEV list is still usable when EPSS is missing", async () => {
  const srv = await vulnSetup({ epss: false });
  try {
    const { body } = await req(srv.port, "/api/v1/vulnerabilities");
    assert.deepEqual([body.kevStale, body.epssStale, body.threatDataStale, body.items[0].kev, body.items[0].epss], [false, true, true, true, null]);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities?kev=true")).body.total, 1);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities/summary")).body.totals.kev, 1);
  } finally { await srv.close(); }
});

test("filtering by KEV without a current KEV list is refused, not answered with nothing", async () => {
  const srv = await vulnSetup({ feedsAt: Date.now() - 30 * 86400_000 });
  try {
    const r = await req(srv.port, "/api/v1/vulnerabilities?kev=true");
    assert.equal(r.status, 409);
    assert.match(r.body.error, /KEV/u);
  } finally { await srv.close(); }
});

test("feeds or runs dated in the future (clock moved back) are stale everywhere", async () => {
  const future = Date.now() + 86400_000;
  const srv = await vulnSetup({ feedsAt: future, runAt: future });
  try {
    const { body } = await req(srv.port, "/api/v1/vulnerabilities");
    assert.deepEqual([body.kevStale, body.threatDataStale, body.findingsStale, body.items[0].kev], [true, true, true, null]);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities/summary")).body.totals.kev, null);
  } finally { await srv.close(); }
});

test("when vulnerabilities were never read successfully, totals are null rather than zero", async () => {
  const srv = await vulnSetup({ neverRun: true });
  try {
    const { body } = await req(srv.port, "/api/v1/vulnerabilities/summary");
    assert.deepEqual([body.totals, body.findingsStale, body.collection.lastSuccessAt], [null, true, null]);
  } finally { await srv.close(); }
});
