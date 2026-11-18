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
        if (res.statusCode !== 200) {
          let detail = null;
          try { detail = JSON.parse(body).error ?? null; } catch { /* not JSON */ }
          return reject(Object.assign(new Error(`${path}: HTTP ${res.statusCode}${res.statusCode === 401 ? " (wrong API token?)" : ""}`), { statusCode: res.statusCode, detail }));
        }
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
    if (v.collection.lastError) console.log(`last error: ${v.collection.lastError}`);
    if (v.totals == null) {
      console.log("UNKNOWN: vulnerabilities have never been read successfully. This is not 'none found'.");
    } else {
      if (v.findingsStale) console.log(`** OUT OF DATE: last successful read ${ago(v.collection.lastSuccessAt)}. The figures below are the last known, not current. **`);
      else console.log(`last read: ${ago(v.collection.lastSuccessAt)}`);
      console.log(`threat lists: KEV ${v.kevStale ? "MISSING OR OUT OF DATE" : ago(v.feeds.kev?.fetchedAt)}, EPSS ${v.epssStale ? "MISSING OR OUT OF DATE" : ago(v.feeds.epss?.fetchedAt)}`);
      console.log("machine | total | critical/high | fixable by update | actively exploited (KEV) | unrecognised");
      const rows = [...v.assets].sort((a, b) => (b.kev ?? 0) - (a.kev ?? 0) || b.total - a.total);
      for (const a of rows) console.log(`${a.assetName} | ${a.total} | ${a.critical}/${a.high} | ${a.fixAvailable} | ${a.kev ?? "unknown"} | ${a.unrecognisedCondition}`);
      const t = v.totals;
      console.log(`TOTAL | ${t.total} | ${t.critical}/${t.high} | ${t.fixAvailable} | ${t.kev ?? "unknown"} | ${t.unrecognisedCondition}`);
      console.log("=== ACTIVELY EXPLOITED (KEV) ===");
      if (v.kevStale) console.log("UNKNOWN: the KEV list is missing or out of date.");
      else {
        const kev = [];
        for (let offset = 0; ; offset += 200) {
          const r = await get(`/api/v1/vulnerabilities?kev=true&limit=200&offset=${offset}`);
          kev.push(...r.items);
          if (kev.length >= r.total || r.items.length === 0) break;
        }
        for (const k of kev) console.log(`${k.assetName} | ${k.cve} | ${k.pkg.name} ${k.pkg.version} | ${k.fixedVersion ? `fixed in ${k.fixedVersion}` : k.fixState}${k.lowConfidence ? " | low confidence" : ""}`);
        if (!kev.length) console.log(v.findingsStale ? "(none in the last known data)" : "(none)");
      }
    }
  }

  const ex = await get("/api/v1/exposure");
  if (ex.configured) {
    console.log("=== PUBLIC ROUTES ===");
    if (ex.services == null) console.log(`UNKNOWN: the exposure map is ${ex.status}. This is not 'nothing is exposed'.`);
    else {
      console.log(`sources: Caddy routes ${ex.sources.caddy}, Cloudflare ${ex.sources.cloudflare}, router settings declared (not verified); resolved ${ago(ex.collectedAt)}`);
      if (ex.declaredAddresses?.length) console.log(`declared machine addresses (not verified): ${ex.declaredAddresses.map((d) => `${d.assetName} ${d.ips.join(", ")}`).join("; ")}`);
      console.log("hostname | path | exposure | entry paths | login gate | upstream -> machine | listening");
      const order = { internet: 0, unknown: 1, lan: 2 };
      const entryName = { forward: "router->Caddy", "tunnel-via-caddy": "tunnel->Caddy", "tunnel-direct": "tunnel" };
      const gateName = (g) => (g === "unknown" ? "UNVERIFIED" : g);
      // Entries that differ only by their address condition print once.
      const seen = new Set();
      const rowsToPrint = [...ex.services].filter((s) => { const k = `${s.hostname}|${s.path}|${s.upstream}|${s.exposure}|${s.gate}`; if (seen.has(k)) return false; seen.add(k); return true; });
      for (const s of rowsToPrint.sort((a, b) => order[a.exposure] - order[b.exposure] || a.hostname.localeCompare(b.hostname) || String(a.path).localeCompare(String(b.path)))) {
        const live = s.paths.filter((p) => p.reachable !== false);
        const paths = s.paths.length ? s.paths.map((p) => `${entryName[p.entry] ?? p.entry}${p.reachable === true ? "" : p.reachable === false ? " (blocked)" : " (unknown)"}`).join(", ") : "none";
        const differ = new Set(live.map((p) => p.gate)).size > 1;
        const gate = `${gateName(s.gate)}${differ ? ` (${live.map((p) => `${entryName[p.entry] ?? p.entry}: ${gateName(p.gate)}`).join(", ")})` : ""}`;
        const target = s.upstream ? `${s.upstream} -> ${s.assetName ?? "unknown machine"}` : (s.assetName ? `answered by ${s.assetName}` : "unknown");
        console.log(`${s.hostname} | ${s.path ?? "*"} | ${s.exposure} | ${paths} | ${gate} | ${target} | ${s.listening === true ? "yes" : s.listening === false ? "NO" : "unknown"}`);
      }
      console.log("=== ROUTE PROBLEMS ===");
      for (const p of ex.problems) console.log(`${p.kind} | ${p.hostname ?? "-"} | ${p.upstream ?? "-"} | ${p.reason}`);
      if (!ex.problems.length) console.log("(none)");
    }

    const listed = async (query) => {
      const items = [];
      for (let offset = 0; ; offset += 200) {
        const r = await get(`/api/v1/vulnerabilities?${query}&limit=200&offset=${offset}`);
        items.push(...r.items);
        if (items.length >= r.total || r.items.length === 0) return items;
      }
    };
    const row = (k) => `${k.assetName}${k.container ? ` [${k.container}]` : ""} | ${k.cve} | ${k.pkg.name} ${k.pkg.version} | ${k.urgencyWhy}`;
    const MAX_LINES = 60;
    const print = (items, extra = () => "") => {
      for (const k of items.slice(0, MAX_LINES)) console.log(row(k) + extra(k));
      if (items.length > MAX_LINES) console.log(`... and ${items.length - MAX_LINES} more`);
      if (!items.length) console.log("(none)");
    };
    console.log("=== URGENT ===");
    try { print(await listed("urgent=true")); }
    catch (error) { if (error.statusCode !== 409) throw error; console.log(`UNKNOWN: ${error.detail ?? "urgency can't be established"}. This is not 'nothing urgent'.`); }
    console.log("=== POSSIBLY URGENT ===");
    const uncertain = (k) => {
      const why = [];
      if (k.exposure === "unknown") why.push("exposure unknown");
      if (k.kev === null) why.push("KEV status unknown");
      if (k.possibleExposure) why.push(`may be what serves ${k.via ?? "a public route"}${k.gate === "unknown" ? ", gate unverified" : ""}`);
      return why.length ? ` | uncertain: ${why.join("; ")}` : "";
    };
    print(await listed("possiblyUrgent=true"), uncertain);

    const im = await get("/api/v1/images");
    if (im.configured) {
      console.log("=== CONTAINER IMAGES ===");
      if (!im.db) console.log(`UNKNOWN: no image results yet (collection ${im.collection.status}${im.collection.lastError ? `: ${im.collection.lastError}` : ""}). This is not 'no vulnerabilities'.`);
      else {
        console.log(`scanner database: ${im.db.built ?? "none"}${im.db.stale ? " (OUT OF DATE: image results are unknown)" : ""}${im.db.status !== "ok" ? ` [${im.db.status}${im.db.reason ? `: ${im.db.reason}` : ""}]` : ""}`);
        console.log("machine | container | image | status | findings (critical/high) | KEV");
        for (const h of im.hosts) {
          if (h.listing !== "ok") console.log(`${h.assetName} | - | - | container list ${h.listing} | - | -`);
          for (const i of h.images) {
            const status = i.status === "scanned" ? "scanned" : `${i.status.toUpperCase()}: ${i.reason}`;
            const n = i.counts ? `${i.counts.total} (${i.counts.critical}/${i.counts.high})` : "-";
            const kev = i.counts ? `${i.counts.kev ?? "unknown"}${i.counts.kevUnknown ? ` (+${i.counts.kevUnknown} unknown)` : ""}` : "-";
            console.log(`${h.assetName} | ${i.container} | ${i.imageRef} | ${status} | ${n} | ${kev}`);
          }
        }
      }
    }

    const p = await get("/api/v1/posture");
    if (p.state === "scored") console.log(`POSTURE ${p.confirmed} based on confirmed findings; ${p.pessimistic} in the pessimistic case (rules v${p.rules.score})`);
    else console.log(`POSTURE incomplete: ${p.incompleteReasons.join("; ")}`);
  }
} catch (error) {
  console.error(`hs-report: ${error.message}`);
  process.exit(1);
}
