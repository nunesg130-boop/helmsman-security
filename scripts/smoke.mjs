// End-to-end smoke test: real engine, fake Proxmox / Wazuh / Docker /
// endoflife.date servers. One EOL refresh + one collection cycle, then the
// public API must report ok, issue and unknown results and healthy collectors.
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync, copyFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import https from "node:https";
import { start } from "../src/main.mjs";
import { startFixtureServer } from "../tests/helpers/fixture-server.mjs";
import { proxmoxRoutes, T } from "../tests/fixtures/proxmox-fixture.mjs";
import { wazuhRoutes } from "../tests/fixtures/wazuh-fixture.mjs";

const eolFixture = (slug) => JSON.parse(readFileSync(new URL(`../tests/fixtures/eol/${slug}.json`, import.meta.url)));
const PRODUCTS = ["debian", "ubuntu", "proxmox-ve", "macos", "fedora", "docker-engine"];

const pve = await startFixtureServer(proxmoxRoutes());
const wz = await startFixtureServer(wazuhRoutes());
const eol = await startFixtureServer(Object.fromEntries(PRODUCTS.map((p) => [`/api/v1/products/${p}`, eolFixture(p)])));
const docker = await startFixtureServer({ "/containers/json": [{ Names: ["/sonarr"], Image: "sonarr", State: "running", Ports: [] }], "/version": { Version: "27.3.1", ApiVersion: "1.47" } }, { tls: false });

const dir = mkdtempSync(join(tmpdir(), "hs-smoke-"));
const key = join(dir, "master.key");
writeFileSync(key, randomBytes(32).toString("hex"));
chmodSync(key, 0o600);
mkdirSync(join(dir, "tls"));
copyFileSync(new URL("../tests/fixtures/tls/key.pem", import.meta.url), join(dir, "tls", "key.pem"));
copyFileSync(new URL("../tests/fixtures/tls/cert.pem", import.meta.url), join(dir, "tls", "cert.pem"));
writeFileSync(join(dir, "config.json"), JSON.stringify({
  listen: { apiHost: "127.0.0.1", apiPort: 0, adminHost: "127.0.0.1", adminPort: 0, adminAllowIp: "127.0.0.1" },
  owner: { authentikUser: "owner", adminOrigin: "https://security.lan" },
  proxmox: { baseUrl: pve.url, tokenId: "helmsec@pve!engine", certSha256: pve.certSha256, backupStorage: "backups" },
  wazuh: { baseUrl: wz.url, user: "helmsec-ro", certSha256: wz.certSha256 },
  docker: [{ name: "docker-vm", baseUrl: docker.url, assetKey: "pve:guest:109" }],
  assets: { roaming: ["legion"], appliances: [] },
  network: [{ name: "er605", ip: "192.168.0.1" }],
  eol: { products: PRODUCTS }
}));

let token;
const engine = await start({
  configPath: join(dir, "config.json"), keyPath: key, dataDir: dir, schedule: false, now: () => T * 1000,
  eolBase: `${eol.url}/api/v1/products/`,
  eolCertSha256: eol.certSha256,
  log: (m) => { const t = /API token[^:]*: (\S+)/u.exec(m); if (t) token = t[1]; }
});

let failed = false;
const check = (ok, msg) => { console.log(`${ok ? "ok  " : "FAIL"} ${msg}`); if (!ok) failed = true; };
try {
  engine.credentials.set("proxmox.tokenSecret", "11111111-aaaa", 1);
  engine.credentials.set("wazuh.password", "pw", 1);
  const eolRun = await engine.refreshEol().catch((e) => ({ status: `error ${e.message}` }));
  await engine.collect();
  const summary = await new Promise((resolve, reject) => {
    https.get({ host: "127.0.0.1", port: engine.apiPort, path: "/api/v1/summary", rejectUnauthorized: false, headers: { authorization: `Bearer ${token}` } }, (res) => {
      let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolve(JSON.parse(b)));
    }).on("error", reject);
  });
  console.log(JSON.stringify(summary.counts), "roamingAway", summary.roamingAway);
  check(eolRun.status === "ok" || summary.collectors.find((c) => c.name === "eol")?.status === "ok", "EOL refresh succeeded");
  check(summary.counts.ok > 0, "some checks ok");
  check(summary.counts.issue > 0, "some checks are issues");
  check(summary.counts.unknown > 0, "some checks unknown");
  for (const c of summary.collectors) check(c.status === "ok", `collector ${c.name} ok${c.lastError ? ` (${c.lastError})` : ""}`);
} finally {
  await engine.stop();
  await Promise.all([pve.close(), wz.close(), eol.close(), docker.close()]);
}
process.exit(failed ? 1 : 0);
