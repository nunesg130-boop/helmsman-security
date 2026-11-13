import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { randomBytes, X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadConfig, egressHosts } from "./config.mjs";
import { loadMasterKey, createSecretBox, CredentialStore } from "./secrets.mjs";
import { openDb } from "./db.mjs";
import { EvidenceStore } from "./evidence.mjs";
import { HoldStore } from "./holds.mjs";
import { LedgerStore } from "./ledger.mjs";
import { createHttp } from "./http.mjs";
import { collectProxmox } from "./collectors/proxmox.mjs";
import { collectWazuh } from "./collectors/wazuh.mjs";
import { createWazuh414 } from "./collectors/wazuh414.mjs";
import { collectDocker } from "./collectors/docker.mjs";
import { collectEolDataset, EOL_BASE } from "./collectors/eol-dataset.mjs";
import { collectionCycle, eolCycle } from "./cycle.mjs";
import { threshold } from "./checks/thresholds.mjs";
import { startScheduler } from "./scheduler.mjs";
import { createPublicServer } from "./api/public.mjs";
import { createAdminServer } from "./api/admin.mjs";

export const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

// The API certificate is generated once with openssl and its fingerprint is
// logged so Helmsman can pin it.
function ensureTls(dir, log) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  if (!existsSync(keyPath) || !existsSync(certPath)) {
    const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "3650", "-subj", "/CN=helmsman-security"], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`could not generate the API certificate with openssl: ${r.stderr || r.error?.message}`);
    chmodSync(keyPath, 0o600);
    log("Generated a new API certificate.");
  }
  const cert = readFileSync(certPath);
  const fp = new X509Certificate(cert).fingerprint256.replace(/:/gu, "").toLowerCase();
  log(`API certificate SHA-256 fingerprint (pin this in Helmsman): ${fp}`);
  return { key: readFileSync(keyPath), cert };
}

const requireCredential = (credentials, name) => {
  const v = credentials.get(name);
  if (!v) throw Object.assign(new Error(`credential ${name} is not set (add it on the admin page)`), { code: "config" });
  return v;
};

export async function start({
  configPath = process.env.HS_CONFIG ?? "/data/config.json",
  keyPath = process.env.HS_MASTER_KEY ?? "/run/secrets/master.key",
  dataDir = process.env.HS_DATA_DIR ?? "/data",
  log = (m) => console.log(`[helmsman-security] ${m}`),
  now = Date.now,
  schedule = true,
  eolBase = EOL_BASE,
  eolCertSha256 = null // tests only: pin a local endoflife.date stand-in
} = {}) {
  const config = loadConfig(configPath);
  const box = createSecretBox(loadMasterKey(keyPath));
  const db = openDb(join(dataDir, "engine.db"));
  const tenantId = config.tenant;
  const store = new EvidenceStore(db, tenantId);
  const holds = new HoldStore(db, tenantId);
  const ledger = new LedgerStore(db, tenantId);
  const credentials = new CredentialStore(db, tenantId, box);

  const interrupted = store.failOpenRuns(now());
  log(`Startup: ${interrupted} interrupted run${interrupted === 1 ? "" : "s"} marked failed.`);
  if (!credentials.has("api.readToken")) {
    const token = randomBytes(32).toString("base64url");
    credentials.set("api.readToken", token, now());
    log(`New Helmsman API token (shown once, store this in Helmsman): ${token}`);
  }
  const tls = ensureTls(join(dataDir, "tls"), log);

  const hosts = egressHosts(config);
  if (eolBase !== EOL_BASE) hosts.allowHosts.push(new URL(eolBase).hostname);
  const http = createHttp(hosts);
  const secretValues = () => ["proxmox.tokenSecret", "wazuh.password", "api.readToken"].map((n) => credentials.get(n)).filter(Boolean);

  const sources = {};
  if (config.proxmox) sources.proxmox = () => collectProxmox({ http, cfg: config.proxmox, secret: requireCredential(credentials, "proxmox.tokenSecret"), now });
  if (config.wazuh) {
    sources.wazuh = () => collectWazuh({
      adapter: createWazuh414({ http, baseUrl: config.wazuh.baseUrl, user: config.wazuh.user, password: requireCredential(credentials, "wazuh.password"), certSha256: config.wazuh.certSha256 }),
      now
    });
  }
  if (config.docker.length) sources.docker = () => collectDocker({ http, hosts: config.docker, now });

  const collect = () => collectionCycle({ db, tenantId, store, holds, ledger, config, sources, now, secrets: secretValues() });
  const refreshEol = () => eolCycle({
    store, config, now,
    fetchEol: () => collectEolDataset({ fetchJson: (u) => http.fetchJson(u, eolCertSha256 ? { certSha256: eolCertSha256 } : {}), products: config.eol.products, now, maxAgeMs: threshold(config, "eolMaxAgeDays") * 86400_000, base: eolBase })
  });

  const cycleStaleMs = threshold(config, "collectMinutes") * threshold(config, "staleFactor") * 60_000;
  const api = await createPublicServer({ db, tenantId, store, credentials, tls, host: config.listen.apiHost, port: config.listen.apiPort, version: VERSION, staleAfterMs: cycleStaleMs, now });
  const admin = await createAdminServer({ db, tenantId, holds, credentials, config, now });
  log(`API listening on ${config.listen.apiHost}:${api.port}; admin on ${config.listen.adminHost}:${admin.port} (only from ${config.listen.adminAllowIp}).`);

  const scheduler = schedule ? startScheduler({
    tasks: [
      { name: "eol", everyMs: threshold(config, "eolRefreshHours") * 3600_000, run: refreshEol },
      { name: "collect", everyMs: threshold(config, "collectMinutes") * 60_000, run: collect }
    ],
    onError: (name, e) => log(`${name} cycle error: ${e.message}`)
  }) : null;

  let stopped = false;
  async function stop() {
    if (stopped) return;
    stopped = true;
    await Promise.race([scheduler?.stop() ?? Promise.resolve(), new Promise((r) => setTimeout(r, 10_000))]);
    await api.close();
    await admin.close();
    db.close();
  }

  return { config, db, store, ledger, credentials, apiPort: api.port, adminPort: admin.port, collect, refreshEol, stop };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  start().then((engine) => {
    const shutdown = () => engine.stop().then(() => process.exit(0));
    process.on("SIGTERM", shutdown);
    process.on("SIGINT", shutdown);
  }).catch((e) => {
    console.error(`[helmsman-security] failed to start: ${e.message}`);
    process.exit(1);
  });
}
