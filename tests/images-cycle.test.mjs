import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { FindingStore } from "../src/vuln/findings.mjs";
import { imagesCycle } from "../src/images/cycle.mjs";
import { putOk } from "./helpers/stores.mjs";

const NOW = Date.parse("2026-11-17T12:00:00Z");
const BUILT = "2026-11-17T04:00:00Z";
const D = (n) => `sha256:${String(n).repeat(64).slice(0, 64)}`;
const id = (d) => d.replace(":", "-");
const match = (cve = "CVE-2026-1001", over = {}) => ({ id: "GHSA-aaaa-bbbb-cccc", relatedCves: [cve], severity: "High", cvss: 7.5, fixState: "fixed", fixVersions: ["1.2"],
  pkg: { name: "openssl", version: "1.1", type: "apk", purl: "pkg:apk/openssl@1.1" }, matchType: "exact-direct-match", ...over });

function setup({ containers, images, db = { v: 1, status: "ok", built: BUILT, checkedAt: NOW }, scans = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), "hs-img-"));
  const spoolDir = join(root, "spool"), outDir = join(root, "out");
  mkdirSync(spoolDir); mkdirSync(outDir);
  if (db) writeFileSync(join(outDir, "db.json"), typeof db === "string" ? db : JSON.stringify(db));
  for (const [digest, scan] of Object.entries(scans)) writeFileSync(join(outDir, `scan-${id(digest)}.json`), typeof scan === "string" ? scan : JSON.stringify({ v: 1, digest, status: "scanned", reason: null, dbBuilt: BUILT, scannedAt: NOW - 3600_000, matches: [match()], ...scan }));
  const dbh = openDb(":memory:");
  const store = new EvidenceStore(dbh, "default");
  const findings = new FindingStore(dbh, "default");
  putOk(store, "docker", [
    { assetKey: "pve:guest:201", kind: "docker.containers", value: containers ?? [
      { name: "authentik-server-1", image: "ghcr.io/goauthentik/server:2026.5.6", imageId: "sha256:a1", state: "running", ports: [] },
      { name: "authentik-worker-1", image: "ghcr.io/goauthentik/server:2026.5.6", imageId: "sha256:a1", state: "running", ports: [] },
      { name: "palmetto-tech-site", image: "palmetto-tech-site-palmetto-tech-site", imageId: "sha256:p1", state: "running", ports: [] },
      { name: "hs-docker-proxy", image: "nginx:1.30.6-alpine", imageId: "sha256:n1", state: "running", ports: [] }] },
    { assetKey: "pve:guest:201", kind: "docker.images", value: images ?? [
      { id: "sha256:a1", repoTags: ["ghcr.io/goauthentik/server:2026.5.6"], repoDigests: [`ghcr.io/goauthentik/server@${D(1)}`] },
      { id: "sha256:p1", repoTags: ["palmetto-tech-site-palmetto-tech-site:latest"], repoDigests: [] },
      { id: "sha256:n1", repoTags: ["nginx:1.30.6-alpine"], repoDigests: [`nginx@${D(2)}`] }] }
  ], NOW);
  const config = { thresholds: {}, docker: [{ name: "docker-auth", baseUrl: "http://192.168.0.213:2375", assetKey: "pve:guest:201" }],
    images: { enabled: true, spoolDir, outDir, platform: "linux/amd64", dbMaxAgeDays: 5, resultMaxAgeDays: 7, dockerHubPullsPerHour: 3 } };
  const run = (t = NOW) => imagesCycle({ db: dbh, tenantId: "default", store, findings, config, now: () => t });
  const list = () => findings.list({ limit: 500 }, { now: NOW, maxFeedAgeMs: 86400_000 }).items;
  const ev = (kind, key = "pve:guest:201") => store.get(key, kind)?.value;
  const byContainer = () => Object.fromEntries(ev("grype.images").images.map((i) => [i.container, [i.status, i.reason]]));
  return { root, spoolDir, outDir, store, findings, run, list, ev, byContainer };
}

test("requests are written for registry images only, once per digest, with the engine's settings", async () => {
  const s = setup();
  assert.equal((await s.run()).status, "ok");
  const reqs = readdirSync(s.spoolDir).filter((f) => f.startsWith("req-")).sort();
  assert.deepEqual(reqs, [`req-${id(D(1))}.json`, `req-${id(D(2))}.json`]);
  const r = JSON.parse(readFileSync(join(s.spoolDir, `req-${id(D(2))}.json`), "utf8"));
  assert.deepEqual(r, { v: 1, digest: D(2), ref: `docker.io/library/nginx@${D(2)}`, registry: "docker.io", platform: "linux/amd64", requestedAt: NOW });
  assert.equal(statSync(join(s.spoolDir, `req-${id(D(2))}.json`)).mode & 0o777, 0o644, "readable by the scanner, holds no secrets");
  assert.deepEqual(JSON.parse(readFileSync(join(s.spoolDir, "settings.json"), "utf8")), { v: 1, dockerHubPullsPerHour: 3 });
  await s.run(NOW + 60_000);
  assert.equal(JSON.parse(readFileSync(join(s.spoolDir, `req-${id(D(2))}.json`), "utf8")).requestedAt, NOW, "an existing request isn't rewritten");
});
test("a current scan gives findings per container, filed under the host with the image, joined on the CVE", async () => {
  const s = setup({ scans: { [D(1)]: {} } });
  await s.run();
  const items = s.list();
  assert.deepEqual(items.map((i) => [i.assetKey, i.container, i.image, i.cve, i.pkg.name, i.fixState, i.source]).sort(), [
    ["pve:guest:201", "authentik-server-1", "ghcr.io/goauthentik/server", "CVE-2026-1001", "openssl", "fix-available-not-applied", "grype"],
    ["pve:guest:201", "authentik-worker-1", "ghcr.io/goauthentik/server", "CVE-2026-1001", "openssl", "fix-available-not-applied", "grype"]]);
  assert.deepEqual(s.byContainer(), {
    "authentik-server-1": ["scanned", null], "authentik-worker-1": ["scanned", null],
    "palmetto-tech-site": ["local", "built locally, no registry digest"], "hs-docker-proxy": ["pending", "not scanned yet"] });
  assert.deepEqual(s.ev("grype.db", "_global"), { built: BUILT, status: "ok", stale: false, reason: null });
});
test("a result scanned against an older database still gives findings for that digest, but coverage reads pending", async () => {
  const s = setup({ scans: { [D(1)]: { dbBuilt: "2026-11-16T04:00:00Z" } } });
  await s.run();
  assert.equal(s.list().length, 2);
  assert.deepEqual(s.byContainer()["authentik-server-1"], ["pending", "rescan pending (vulnerability database updated)"]);
});
test("a database older than the limit makes every image stale-db; a missing database makes them unknown", async () => {
  const old = setup({ db: { v: 1, status: "ok", built: "2026-11-10T04:00:00Z", checkedAt: NOW }, scans: { [D(1)]: { dbBuilt: "2026-11-10T04:00:00Z" } } });
  await old.run();
  assert.deepEqual(old.byContainer()["authentik-server-1"], ["stale-db", "Grype database is 7 days old (limit 5)"]);
  assert.equal(old.ev("grype.db", "_global").stale, true);
  const none = setup({ db: null, scans: { [D(1)]: {} } });
  await none.run();
  assert.deepEqual(none.byContainer()["authentik-server-1"], ["unknown", "the scanner hasn't reported a vulnerability database"]);
  assert.equal(none.ev("grype.db", "_global").status, "missing");
  const failed = setup({ db: { v: 1, status: "failed", reason: "db-unavailable", built: BUILT, checkedAt: NOW }, scans: { [D(1)]: {} } });
  await failed.run();
  assert.deepEqual(failed.ev("grype.db", "_global"), { built: BUILT, status: "failed", stale: false, reason: "db-unavailable" });
});
test("a failed scan reports its reason; a truncated result file is a failed read", async () => {
  const s = setup({ scans: { [D(1)]: { status: "failed", reason: "pull-denied", matches: [] }, [D(2)]: "{\"v\":1,\"dig" } });
  await s.run();
  assert.deepEqual(s.byContainer()["authentik-server-1"], ["failed", "pull-denied"]);
  assert.deepEqual(s.byContainer()["hs-docker-proxy"], ["failed", "unreadable result"]);
  assert.equal(s.list().length, 0);
});
test("a result for a different digest (image updated in place) doesn't count for the running one", async () => {
  const s = setup({ scans: { [D(1)]: { digest: D(9) } } });
  await s.run();
  assert.deepEqual(s.byContainer()["authentik-server-1"], ["failed", "unreadable result"]);
  assert.equal(s.list().length, 0);
});
test("when the running digest changes, the old digest's findings disappear and its request is withdrawn", async () => {
  const s = setup({ scans: { [D(1)]: {} } });
  await s.run();
  assert.equal(s.list().length, 2);
  putOk(s.store, "docker", [
    { assetKey: "pve:guest:201", kind: "docker.containers", value: [{ name: "authentik-server-1", image: "ghcr.io/goauthentik/server:2026.5.7", imageId: "sha256:a2", state: "running", ports: [] }] },
    { assetKey: "pve:guest:201", kind: "docker.images", value: [{ id: "sha256:a2", repoTags: ["ghcr.io/goauthentik/server:2026.5.7"], repoDigests: [`ghcr.io/goauthentik/server@${D(3)}`] }] }], NOW + 60_000);
  await s.run(NOW + 60_000);
  assert.equal(s.list().length, 0);
  assert.deepEqual(s.byContainer(), { "authentik-server-1": ["pending", "not scanned yet"] });
  assert.ok(!existsSync(join(s.spoolDir, `req-${id(D(1))}.json`)));
  assert.ok(existsSync(join(s.spoolDir, `req-${id(D(3))}.json`)));
});
test("host-package findings are untouched by the image run", async () => {
  const s = setup({ scans: { [D(1)]: {} } });
  s.findings.replaceSource("wazuh", [{ assetKey: "pve:guest:201", cve: "CVE-2026-9", pkg: { name: "bash", version: "5", arch: "amd64" }, severity: "low", fixState: "unknown" }], NOW);
  await s.run();
  assert.deepEqual(s.list().map((i) => i.source).sort(), ["grype", "grype", "wazuh"]);
});
test("a host without container evidence is reported as such", async () => {
  const s = setup();
  s.store.db.prepare("DELETE FROM evidence WHERE kind IN ('docker.containers', 'docker.images')").run();
  await s.run();
  assert.deepEqual(s.ev("grype.images"), { listing: "missing", images: [] });
});
test("an image scan result over its age limit reads pending", async () => {
  const s = setup({ scans: { [D(1)]: { scannedAt: NOW - 8 * 86400_000 } } });
  await s.run();
  assert.deepEqual(s.byContainer()["authentik-server-1"], ["pending", "last scan is 8 days old (limit 7)"]);
});
