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
import { indexerRoutes, vulnDoc } from "../tests/fixtures/wazuh-indexer-fixture.mjs";
import { gzipSync } from "node:zlib";
import { cloudflareRoutes } from "../tests/fixtures/cloudflare-fixture.mjs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const eolFixture = (slug) => JSON.parse(readFileSync(new URL(`../tests/fixtures/eol/${slug}.json`, import.meta.url)));
const PRODUCTS = ["debian", "ubuntu", "proxmox-ve", "macos", "fedora", "docker-engine"];

const pve = await startFixtureServer(proxmoxRoutes());
const wz = await startFixtureServer(wazuhRoutes());
const eol = await startFixtureServer(Object.fromEntries(PRODUCTS.map((p) => [`/api/v1/products/${p}`, eolFixture(p)])));
const docker = await startFixtureServer({ "/containers/json": [{ Names: ["/sonarr"], Image: "sonarr", State: "running", Ports: [] }], "/images/json": [], "/version": { Version: "27.3.1", ApiVersion: "1.47" } }, { tls: false });

const ix = await startFixtureServer({
  ...indexerRoutes([vulnDoc({ agent: "001", name: "norco", cve: "CVE-2024-1000" }), vulnDoc({ agent: "001", name: "norco", cve: "CVE-2024-2000", condition: "Package default status" })]),
  "/kev.json": { vulnerabilities: [{ cveID: "CVE-2024-1000", dateAdded: "2024-05-01", knownRansomwareCampaignUse: "Unknown" }] },
  "/epss.csv.gz": () => [200, gzipSync(Buffer.from("#model\ncve,epss,percentile\nCVE-2024-1000,0.7,0.95\n"))]
});

// Exposure stand-ins: the route shape Caddy's host would export (one public
// hostname proxying to the Proxmox node), and the Cloudflare API.
const route = (host, handle) => ({ group: null, terminal: true, match: [{ host: [host], unsupported: [] }], handle });
const caddy = await startFixtureServer({ "/shape.json": { version: 2, generatedAt: T, servers: [{ server: "srv0", listen: [":443"], trustedProxies: null, trustedProxiesStrict: false, clientIpHeaders: null, routes: [
  route("pve.example.com", [{ handler: "reverse_proxy", upstreams: ["192.168.0.10:8006"] }]),
  route("gone.example.com", [{ handler: "reverse_proxy", upstreams: ["192.168.0.10:9999"] }])
] }] } }, { tls: false });
const cf = await startFixtureServer(cloudflareRoutes({ ingress: [{ service: "http_status:404" }], dns: [{ name: "pve.example.com" }] }));

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
  wazuh: { baseUrl: wz.url, user: "helmsec-ro", certSha256: wz.certSha256, requestsPerMinute: 6000, indexer: { baseUrl: ix.url, user: "helmsec-vuln-ro", certSha256: ix.certSha256, requestsPerMinute: 6000 } },
  docker: [{ name: "docker-vm", baseUrl: docker.url, assetKey: "pve:guest:109" }],
  assets: { roaming: ["legion"], appliances: [] },
  network: [{ name: "er605", ip: "192.168.0.1", portForwards: [{ wanPort: 443, lanIp: "192.168.0.114", lanPort: 443, protocol: "tcp" }], upnp: false, dmz: false, ipv6Inbound: false }],
  exposure: { caddy: { url: `${caddy.url}/shape.json`, assetKey: "pve:guest:114", address: "192.168.0.114" }, cloudflare: { accountId: "acc", zoneId: "zone", tunnelIds: ["t1"], assetKey: "pve:guest:109", connectorAddress: "192.168.0.109" }, expectedPrivate: [] },
  eol: { products: PRODUCTS }
}));

let token;
const engine = await start({
  configPath: join(dir, "config.json"), keyPath: key, dataDir: dir, schedule: false, now: () => T * 1000,
  eolBase: `${eol.url}/api/v1/products/`,
  eolCertSha256: eol.certSha256,
  cloudflareBase: `${cf.url}/client/v4`, cloudflareCertSha256: cf.certSha256,
  kevUrl: `${ix.url}/kev.json`, epssUrl: `${ix.url}/epss.csv.gz`, feedCertSha256: ix.certSha256, feedMinimums: { minKev: 1, minEpss: 1 },
  log: (m) => { const t = /API token[^:]*: (\S+)/u.exec(m); if (t) token = t[1]; }
});

let failed = false;
const check = (ok, msg) => { console.log(`${ok ? "ok  " : "FAIL"} ${msg}`); if (!ok) failed = true; };
try {
  engine.credentials.set("proxmox.tokenSecret", "11111111-aaaa", 1);
  engine.credentials.set("wazuh.password", "pw", 1);
  engine.credentials.set("wazuh.indexerPassword", "ix-pw", 1);
  engine.credentials.set("cloudflare.apiToken", "cf-token", 1);
  const eolRun = await engine.refreshEol().catch((e) => ({ status: `error ${e.message}` }));
  await engine.collect();
  await engine.refreshFeeds();
  await engine.collectVulns();
  await engine.collect(); // re-evaluate with the vulnerability evidence in place
  const api = (path) => new Promise((resolve, reject) => {
    https.get({ host: "127.0.0.1", port: engine.apiPort, path, rejectUnauthorized: false, headers: { authorization: `Bearer ${token}` } }, (res) => {
      let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolve(JSON.parse(b)));
    }).on("error", reject);
  });
  const summary = await api("/api/v1/summary");
  const vulns = await api("/api/v1/vulnerabilities/summary");
  check(vulns.totals.total === 2 && vulns.totals.kev === 1 && vulns.totals.fixAvailable === 1 && vulns.totals.noFix === 1, "vulnerabilities read, with KEV and fix state");
  check(vulns.findingsStale === false && vulns.threatDataStale === false, "vulnerability data is current");
  const unknowns = await api("/api/v1/unknowns?pageSize=200");
  check(unknowns.items.some((u) => u.checkId === "vuln_coverage_host" && /can't tell 'clean' from 'not scanned'/u.test(u.reason)), "a machine with no vulnerability records is unknown, not clean");
  const exposure = await api("/api/v1/exposure");
  const pveRoute = exposure.services?.find((s) => s.hostname === "pve.example.com");
  check(exposure.status === "ok" && exposure.sources.caddy === "ok" && exposure.sources.cloudflare === "ok", "exposure map built from Caddy, Cloudflare and the declared router");
  check(pveRoute?.exposure === "internet" && pveRoute.assetKey === "pve:node:norco" && pveRoute.listening === true && pveRoute.process === "pveproxy", "a public route resolves to its machine and listening process");
  check(exposure.problems?.some((p) => p.kind === "dangling_route" && p.hostname === "gone.example.com"), "a route to a port nothing listens on is reported");
  const urgent = await api("/api/v1/vulnerabilities?urgent=true");
  check(urgent.total === 1 && urgent.items[0].cve === "CVE-2024-1000" && urgent.items[0].exposure === "host", "an actively exploited flaw on an internet-reachable machine is urgent");
  const posture = await api("/api/v1/posture");
  check(posture.state === "incomplete" || (posture.confirmed <= 100 && posture.pessimistic <= posture.confirmed), `posture: ${posture.state === "scored" ? `${posture.confirmed} / ${posture.pessimistic}` : `incomplete (${posture.incompleteReasons.join("; ")})`}`);
  const issues = await api("/api/v1/issues?pageSize=200");
  check(issues.items.some((i) => i.checkId === "exposure_routes" && /gone\.example\.com/u.test(i.reason)), "the dangling route is an issue on the Caddy machine");
  // The report must run end to end against the same engine.
  const tokenFile = join(dir, "token");
  writeFileSync(tokenFile, token);
  const cfgForReport = join(dir, "report-config.json");
  writeFileSync(cfgForReport, JSON.stringify({ listen: { apiHost: "127.0.0.1", apiPort: engine.apiPort } }));
  const report = await new Promise((resolve) => {
    let out = "";
    const child = spawn(process.execPath, [fileURLToPath(new URL("./hs-report.mjs", import.meta.url))], { env: { ...process.env, HS_CONFIG: cfgForReport, HS_DATA_DIR: dir, HS_TOKEN_FILE: tokenFile } });
    child.stdout.on("data", (d) => { out += d; }); child.stderr.on("data", (d) => { out += d; });
    child.on("close", (status) => resolve({ status, out }));
  });
  check(report.status === 0 && ["=== PUBLIC ROUTES ===", "=== ROUTE PROBLEMS ===", "=== URGENT ===", "=== POSSIBLY URGENT ===", "POSTURE "].every((h) => report.out.includes(h)) && /pve\.example\.com \| \* \| internet/u.test(report.out), "hs-report prints routes, problems, urgency and posture");
  if (report.status !== 0 || process.env.HS_SMOKE_SHOW_REPORT) console.log(report.out);
  console.log(JSON.stringify(summary.counts), "roamingAway", summary.roamingAway);
  check(eolRun.status === "ok" || summary.collectors.find((c) => c.name === "eol")?.status === "ok", "EOL refresh succeeded");
  check(summary.counts.ok > 0, "some checks ok");
  check(summary.counts.issue > 0, "some checks are issues");
  check(summary.counts.unknown > 0, "some checks unknown");
  for (const c of summary.collectors) check(c.status === "ok", `collector ${c.name} ok${c.lastError ? ` (${c.lastError})` : ""}`);
} finally {
  await engine.stop();
  await Promise.all([pve.close(), wz.close(), eol.close(), docker.close(), ix.close(), caddy.close(), cf.close()]);
}
process.exit(failed ? 1 : 0);
