import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { start } from "../src/main.mjs";

function setupDir() {
  const dir = mkdtempSync(join(tmpdir(), "hs-main-"));
  const config = join(dir, "config.json");
  writeFileSync(config, JSON.stringify({
    listen: { apiHost: "127.0.0.1", apiPort: 0, adminHost: "127.0.0.1", adminPort: 0, adminAllowIp: "127.0.0.1" },
    owner: { authentikUser: "owner", adminOrigin: "https://security.lan" },
    eol: { products: [] }
  }));
  const key = join(dir, "master.key");
  writeFileSync(key, randomBytes(32).toString("hex"));
  chmodSync(key, 0o600);
  mkdirSync(join(dir, "tls"));
  copyFileSync(new URL("./fixtures/tls/key.pem", import.meta.url), join(dir, "tls", "key.pem"));
  copyFileSync(new URL("./fixtures/tls/cert.pem", import.meta.url), join(dir, "tls", "cert.pem"));
  return { dir, config, key };
}

test("main recovers an interrupted run on start and prints a new API token once", async () => {
  const { dir, config, key } = setupDir();
  const s = new EvidenceStore(openDb(join(dir, "engine.db")), "default");
  s.beginRun("proxmox", 1);
  const logs = [];
  const engine = await start({ configPath: config, keyPath: key, dataDir: dir, log: (m) => logs.push(m) });
  try {
    assert.ok(logs.some((l) => /1 interrupted run/u.test(l)), logs.join("\n"));
    assert.ok(logs.some((l) => /Helmsman API token/u.test(l)));
    assert.ok(logs.some((l) => /fingerprint/u.test(l)));
    assert.equal(engine.store.lastRun("proxmox").status, "failed");
  } finally { await engine.stop(); }

  const logs2 = [];
  const again = await start({ configPath: config, keyPath: key, dataDir: dir, log: (m) => logs2.push(m) });
  try { assert.ok(!logs2.some((l) => /Helmsman API token/u.test(l)), "token printed only on first start"); }
  finally { await again.stop(); }
});

test("a configured collector without its credential fails visibly", async () => {
  const { dir, key } = setupDir();
  const config = join(dir, "config2.json");
  writeFileSync(config, JSON.stringify({
    listen: { apiHost: "127.0.0.1", apiPort: 0, adminHost: "127.0.0.1", adminPort: 0, adminAllowIp: "127.0.0.1" },
    owner: { authentikUser: "owner", adminOrigin: "https://x" },
    proxmox: { baseUrl: "https://127.0.0.1:1", tokenId: "a@pam!b", certSha256: "00" },
    eol: { products: [] }
  }));
  const engine = await start({ configPath: config, keyPath: key, dataDir: dir, log: () => {}, schedule: false });
  try {
    await engine.collect();
    const r = engine.store.lastRun("proxmox");
    assert.equal(r.status, "failed");
    assert.match(r.error, /proxmox\.tokenSecret is not set/u);
  } finally { await engine.stop(); }
});

test("vulnerability collection and threat feeds run end to end against stand-ins", async () => {
  const { gzipSync } = await import("node:zlib");
  const { startFixtureServer } = await import("./helpers/fixture-server.mjs");
  const { indexerRoutes, vulnDoc } = await import("./fixtures/wazuh-indexer-fixture.mjs");
  const ix = await startFixtureServer({
    ...indexerRoutes([vulnDoc({ cve: "CVE-2024-1000" }), vulnDoc({ cve: "CVE-2024-2000", agent: "011", name: "Main" })]),
    "/kev.json": { vulnerabilities: [{ cveID: "CVE-2024-1000", dateAdded: "2024-05-01", knownRansomwareCampaignUse: "Unknown" }] },
    "/epss.csv.gz": () => [200, gzipSync(Buffer.from("#model\ncve,epss,percentile\nCVE-2024-1000,0.7,0.95\n"))]
  });
  const { dir, key } = setupDir();
  const config = join(dir, "config3.json");
  writeFileSync(config, JSON.stringify({
    listen: { apiHost: "127.0.0.1", apiPort: 0, adminHost: "127.0.0.1", adminPort: 0, adminAllowIp: "127.0.0.1" },
    owner: { authentikUser: "owner", adminOrigin: "https://x" },
    wazuh: { baseUrl: "https://127.0.0.1:1", user: "u", certSha256: "00", indexer: { baseUrl: ix.url, user: "ro", certSha256: ix.certSha256, requestsPerMinute: 6000 } },
    eol: { products: [] }
  }));
  const logs = [];
  const engine = await start({ configPath: config, keyPath: key, dataDir: dir, log: (m) => logs.push(m), schedule: false,
    kevUrl: `${ix.url}/kev.json`, epssUrl: `${ix.url}/epss.csv.gz`, feedCertSha256: ix.certSha256, feedMinimums: { minKev: 1, minEpss: 1 } });
  try {
    assert.equal((await engine.collectVulns()).status, "failed", "no indexer password yet");
    assert.match(engine.store.lastRun("wazuh-vulns").error, /wazuh\.indexerPassword is not set/u);
    engine.credentials.set("wazuh.indexerPassword", "ix-secret-value", 1);
    const fr = await engine.refreshFeeds();
    assert.equal(fr.status, "ok", engine.store.lastRun("threat-feeds").error);
    const vr = await engine.collectVulns();
    assert.equal(vr.status, "ok", engine.store.lastRun("wazuh-vulns").error);
    const { items } = engine.findings.list({}, { now: Date.now(), maxFeedAgeMs: 86400_000 });
    assert.deepEqual(items.map((i) => [i.cve, i.kev, i.epss, i.assetKey]), [["CVE-2024-1000", true, 0.7, "wazuh:agent:010"], ["CVE-2024-2000", false, null, "wazuh:agent:011"]]);
    assert.ok(!logs.join("\n").includes("ix-secret-value"));
  } finally { await engine.stop(); await ix.close(); }
});

test("vulns and threat-feeds tasks are scheduled only when an indexer is configured", async () => {
  const { dir, config, key } = setupDir();
  const engine = await start({ configPath: config, keyPath: key, dataDir: dir, log: () => {} });
  try {
    assert.deepEqual(engine.scheduledTasks, ["eol", "collect"]);
    assert.equal((await engine.collectVulns()).status, "not_configured");
  } finally { await engine.stop(); }
});
