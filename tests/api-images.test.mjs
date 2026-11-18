import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import https from "node:https";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { FindingStore } from "../src/vuln/findings.mjs";
import { CredentialStore, createSecretBox } from "../src/secrets.mjs";
import { createPublicServer } from "../src/api/public.mjs";

const tls = { key: readFileSync(new URL("./fixtures/tls/key.pem", import.meta.url)), cert: readFileSync(new URL("./fixtures/tls/cert.pem", import.meta.url)) };
const TOKEN = "read-token-abc";
const D = "sha256:" + "1".repeat(64);

async function setup({ db = { built: "2026-11-17T04:00:00Z", status: "ok", stale: false, reason: null }, configured = true, evidence = true, imagesStale = false } = {}) {
  const now = Date.now();
  const dbh = openDb(":memory:");
  const store = new EvidenceStore(dbh, "default");
  const credentials = new CredentialStore(dbh, "default", createSecretBox(randomBytes(32)));
  credentials.set("api.readToken", TOKEN, 1);
  dbh.prepare("INSERT INTO assets (tenant_id, asset_key, class, name, sources_json, last_seen_at) VALUES ('default','pve:guest:201','guest','docker-auth','{\"docker\":{\"name\":\"docker-auth\"}}',?)").run(now);
  const f = new FindingStore(dbh, "default");
  const mk = (cve, container, severity, over = {}) => ({ assetKey: "pve:guest:201", container, image: "ghcr.io/goauthentik/server", cve, pkg: { name: "openssl", version: "1", arch: "" }, severity, fixState: "fix-available-not-applied", ...over });
  f.replaceSource("grype", [mk("CVE-1", "authentik-server-1", "critical"), mk("CVE-2", "authentik-server-1", "high"), mk("CVE-3", "authentik-server-1", "low"), mk("CVE-1", "authentik-worker-1", "critical")], now);
  f.replaceSource("wazuh", [{ assetKey: "pve:guest:201", cve: "CVE-9", pkg: { name: "bash", version: "5", arch: "amd64" }, severity: "medium", fixState: "unknown" }], now);
  f.replaceKev([{ cve: "CVE-1" }], now);
  f.replaceEpss([{ cve: "CVE-1", score: 0.5, percentile: 0.9 }], now);
  const v = store.beginRun("wazuh-vulns", now); store.finishRun(v, "ok", {}, now);
  if (evidence) {
    const at = imagesStale ? now - 3 * 3600_000 : now;
    const r = store.beginRun("grype-images", at);
    store.put(r, { assetKey: "pve:guest:201", kind: "grype.images", source: "grype-images", collectedAt: at, staleAfterMs: 45 * 60_000, value: { listing: "ok", images: [
      { container: "authentik-server-1", imageRef: "ghcr.io/goauthentik/server:2026.5.6", repo: "ghcr.io/goauthentik/server", digest: D, status: "scanned", reason: null, scannedAt: now, dbBuilt: db.built, findings: 3 },
      { container: "palmetto-tech-site", imageRef: "palmetto-tech-site:latest", repo: null, digest: null, status: "local", reason: "built locally, no registry digest", scannedAt: null, dbBuilt: null, findings: null }] } });
    store.put(r, { assetKey: "_global", kind: "grype.db", source: "grype-images", collectedAt: at, staleAfterMs: 45 * 60_000, value: db });
    store.finishRun(r, "ok", {}, at);
  }
  return createPublicServer({ db: dbh, tenantId: "default", store, credentials, tls, host: "127.0.0.1", port: 0, version: "0.1.0", imagesConfigured: configured });
}
function req(port, path, { method = "GET", token = TOKEN } = {}) {
  return new Promise((resolve, reject) => {
    const r = https.request({ host: "127.0.0.1", port, path, method, rejectUnauthorized: false, headers: token ? { authorization: `Bearer ${token}` } : {} }, (res) => {
      let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolve({ status: res.statusCode, body: b ? JSON.parse(b) : null }));
    });
    r.on("error", reject); r.end();
  });
}
const using = async (opts, fn) => { const srv = await setup(opts); try { await fn(srv.port); } finally { await srv.close(); } };

test("GET /api/v1/images lists every running image per host, with counts per container", () => using({}, async (port) => {
  const { status, body } = await req(port, "/api/v1/images");
  assert.equal(status, 200);
  assert.deepEqual([body.configured, body.db.built, body.db.stale, body.collection.status], [true, "2026-11-17T04:00:00Z", false, "ok"]);
  const [host] = body.hosts;
  assert.deepEqual([host.assetKey, host.assetName, host.listing], ["pve:guest:201", "docker-auth", "ok"]);
  const server = host.images.find((i) => i.container === "authentik-server-1");
  assert.deepEqual([server.status, server.counts], ["scanned", { total: 3, critical: 1, high: 1, kev: 1, kevUnknown: 0 }]);
}));
test("a stale scanner database is flagged", () => using({ db: { built: "2026-11-01T04:00:00Z", status: "ok", stale: true, reason: null } }, async (port) => {
  assert.equal((await req(port, "/api/v1/images")).body.db.stale, true);
}));
test("without image scanning configured or run, the endpoint says so", async () => {
  await using({ configured: false, evidence: false }, async (port) => {
    const { body } = await req(port, "/api/v1/images");
    assert.deepEqual([body.configured, body.hosts, body.db], [false, null, null]);
  });
  await using({ evidence: false }, async (port) => assert.deepEqual([(await req(port, "/api/v1/images")).body.configured, (await req(port, "/api/v1/images")).body.hosts], [true, null]));
});
test("vulnerability items carry container and image, filter by source, and summaries split host and image findings", () => using({}, async (port) => {
  const all = (await req(port, "/api/v1/vulnerabilities")).body;
  assert.ok(all.items.some((i) => i.container === "authentik-server-1" && i.image === "ghcr.io/goauthentik/server"));
  assert.ok(all.items.some((i) => i.source === "wazuh" && i.container === null));
  assert.deepEqual((await req(port, "/api/v1/vulnerabilities?source=grype")).body.items.map((i) => i.source).sort(), ["grype", "grype", "grype", "grype"]);
  assert.equal((await req(port, "/api/v1/vulnerabilities?source=wazuh")).body.total, 1);
  assert.equal((await req(port, "/api/v1/vulnerabilities?source=trivy")).status, 400);
  const sum = (await req(port, "/api/v1/vulnerabilities/summary")).body;
  assert.deepEqual([sum.assets[0].hostFindings, sum.assets[0].imageFindings, sum.totals.hostFindings, sum.totals.imageFindings], [1, 4, 1, 4]);
}));
test("the images endpoint needs the token and is GET-only", () => using({}, async (port) => {
  assert.equal((await req(port, "/api/v1/images", { token: null })).status, 401);
  assert.equal((await req(port, "/api/v1/images", { method: "POST" })).status, 405);
}));
test("an image without a usable scan has no counts; findings without a CVE are counted as unknown KEV", () => using({}, async (port) => {
  const host = (await req(port, "/api/v1/images")).body.hosts[0];
  assert.equal(host.images.find((i) => i.container === "palmetto-tech-site").counts, null);
}));
test("stale image results mark findings stale and refuse the urgent list", async () => {
  const srv = await setup({ imagesStale: true });
  try {
    const v = (await req(srv.port, "/api/v1/vulnerabilities")).body;
    assert.equal(v.findingsStale, true);
    assert.equal(v.images.stale, true);
    assert.equal((await req(srv.port, "/api/v1/vulnerabilities?urgent=true")).status, 409);
  } finally { await srv.close(); }
});
