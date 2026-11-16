#!/usr/bin/env node
// Prints the engine's current picture on the engine host: counts, collectors,
// issues, unknowns and vulnerabilities. Reads the API token from a root-only
// file and verifies the engine's own certificate.
//   node scripts/hs-report.mjs            (or the hs-report wrapper)
import https from "node:https";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const configPath = process.env.HS_CONFIG ?? "/etc/helmsman-security/config.json";
const dataDir = process.env.HS_DATA_DIR ?? "/var/lib/helmsman-security";
const tokenFile = process.env.HS_TOKEN_FILE ?? "/root/.hs-token";

const config = JSON.parse(readFileSync(configPath, "utf8"));
const host = config.listen?.apiHost && config.listen.apiHost !== "0.0.0.0" ? config.listen.apiHost : "127.0.0.1";
const port = config.listen?.apiPort ?? 8443;
const token = readFileSync(tokenFile, "utf8").trim();
const cert = readFileSync(join(dataDir, "tls", "cert.pem"));

function get(path) {
  return new Promise((resolve, reject) => {
    https.get({ host, port, path, ca: cert, checkServerIdentity: () => undefined, headers: { authorization: `Bearer ${token}` } }, (res) => {
      let body = "";
      res.on("data", (d) => { body += d; });
      res.on("end", () => {
        if (res.statusCode !== 200) return reject(new Error(`${path}: HTTP ${res.statusCode}${res.statusCode === 401 ? " (wrong API token?)" : ""}`));
        try { resolve(JSON.parse(body)); } catch { reject(new Error(`${path}: not JSON`)); }
      });
    }).on("error", reject);
  });
}
async function all(path) {
  const items = [];
  for (let page = 1; ; page++) {
    const r = await get(`${path}?page=${page}&pageSize=200`);
    items.push(...r.items);
    if (items.length >= r.total || r.items.length === 0) return items;
  }
}
const ago = (t) => (t == null ? "never" : `${Math.round((Date.now() - t) / 60_000)} min ago`);

try {
  const summary = await get("/api/v1/summary");
  console.log(JSON.stringify(summary.counts, null, 2));
  console.log(JSON.stringify(summary.collectors.map((c) => ({ name: c.name, status: c.status, lastError: c.lastError })), null, 2));
  console.log("=== ISSUES ===");
  for (const i of await all("/api/v1/issues")) console.log(`${i.assetName} | ${i.checkId} | ${i.reason}`);
  console.log("=== UNKNOWNS ===");
  for (const u of await all("/api/v1/unknowns")) console.log(`${u.assetName} | ${u.checkId} | ${u.reason}`);

  const v = await get("/api/v1/vulnerabilities/summary");
  if (v.collection.status !== "never_run") {
    console.log("=== VULNERABILITIES ===");
    console.log(`last read: ${ago(v.collection.lastSuccessAt)}${v.findingsStale ? "  ** OUT OF DATE **" : ""}${v.collection.lastError ? `  last error: ${v.collection.lastError}` : ""}`);
    console.log(`threat lists: KEV ${ago(v.feeds.kev?.fetchedAt)}, EPSS ${ago(v.feeds.epss?.fetchedAt)}${v.threatDataStale ? "  ** OUT OF DATE: 'actively exploited' is unknown **" : ""}`);
    console.log("machine | total | critical/high | fixable by update | actively exploited (KEV) | unrecognised");
    const rows = [...v.assets].sort((a, b) => (b.kev ?? 0) - (a.kev ?? 0) || b.total - a.total);
    for (const a of rows) console.log(`${a.assetName} | ${a.total} | ${a.critical}/${a.high} | ${a.fixAvailable} | ${a.kev ?? "unknown"} | ${a.unrecognisedCondition}`);
    const t = v.totals;
    console.log(`TOTAL | ${t.total} | ${t.critical}/${t.high} | ${t.fixAvailable} | ${t.kev ?? "unknown"} | ${t.unrecognisedCondition}`);
    if (!v.threatDataStale) {
      console.log("=== ACTIVELY EXPLOITED (KEV) ===");
      const kev = [];
      for (let offset = 0; ; offset += 200) {
        const r = await get(`/api/v1/vulnerabilities?kev=true&limit=200&offset=${offset}`);
        kev.push(...r.items);
        if (kev.length >= r.total || r.items.length === 0) break;
      }
      for (const k of kev) console.log(`${k.assetName} | ${k.cve} | ${k.pkg.name} ${k.pkg.version} | ${k.fixedVersion ? `fixed in ${k.fixedVersion}` : k.fixState}${k.lowConfidence ? " | low confidence" : ""}`);
      if (!kev.length) console.log("(none)");
    }
  }
} catch (error) {
  console.error(`hs-report: ${error.message}`);
  process.exit(1);
}
