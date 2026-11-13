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
  db.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('default','pve:guest:109','guest','docker','{\"wazuh\":{\"id\":\"003\"}}',1), ('default','wazuh:agent:010','roaming','legion','{}',1)").run();
  new LedgerStore(db, "default").write([
    { assetKey: "pve:guest:109", checkId: "agent_connected", state: "ok", reason: "agent connected", evidence: [], roaming: false },
    { assetKey: "pve:guest:109", checkId: "os_eol", state: "issue", reason: "debian 11 reached end of life", evidence: [], roaming: false },
    { assetKey: "pve:guest:109", checkId: "disk_health", state: "unknown", reason: "no pve.disks evidence", evidence: [], roaming: false },
    { assetKey: "wazuh:agent:010", checkId: "agent_connected", state: "unknown", reason: "away since x", evidence: [], roaming: true }
  ], 1000);
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

  await t.test("health", async () => assert.deepEqual((await req(srv.port, "/api/v1/health")).body, { ok: true, version: "0.1.0" }));

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
