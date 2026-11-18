// The engine side of container image scanning. One short collector run:
// work out which images are running (by registry digest), queue a scan request
// for each, read whatever results the scanner worker has written, and file the
// findings under the Docker host with the container's name. It never waits on
// a scan; an image without a usable result is pending, failed or unknown.
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { runCollector } from "../collect.mjs";
import { GLOBAL_KEY } from "../checks/runner.mjs";
import { threshold } from "../checks/thresholds.mjs";
import { runningImages } from "./identity.mjs";
import { classifyMatch } from "./classify.mjs";
import { fileId, writeAtomic } from "./worker.mjs";

export const IMAGES_COLLECTOR = "grype-images";
const DAY = 86400_000;
const readJson = (path) => { try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; } };
const days = (ms) => Math.floor(ms / DAY);

function readDb(outDir, cfg, now) {
  const path = join(outDir, "db.json");
  if (!existsSync(path)) return { built: null, status: "missing", stale: true, reason: "the scanner hasn't reported a vulnerability database" };
  const db = readJson(path);
  const built = db && Number.isFinite(Date.parse(db.built)) ? db.built : null;
  if (!built) return { built: null, status: db?.status === "failed" ? "failed" : "unreadable", stale: true, reason: db?.reason ?? "the scanner hasn't reported a vulnerability database" };
  const age = now - Date.parse(built);
  return { built, status: db.status === "ok" ? "ok" : "failed", stale: age > cfg.dbMaxAgeDays * DAY, reason: db.status === "ok" ? null : (db.reason ?? "database update failed"), ageDays: days(age) };
}

// Status of one running image, given the scanner's database and its result file.
function imageStatus(img, db, cfg, outDir, now) {
  if (img.status !== "registry") return { status: img.status, reason: img.reason, scan: null };
  const path = join(outDir, `scan-${fileId(img.digest)}.json`);
  if (!existsSync(path)) return { status: db.built ? "pending" : "unknown", reason: db.built ? "not scanned yet" : db.reason, scan: null };
  const scan = readJson(path);
  if (!scan || scan.v !== 1 || scan.digest !== img.digest || !["scanned", "failed"].includes(scan.status) || !Array.isArray(scan.matches)) return { status: "failed", reason: "unreadable result", scan: null };
  if (scan.status === "failed") return { status: "failed", reason: scan.reason ?? "scan failed", scan: null };
  // From here the result is a real scan of this exact digest: its findings stand,
  // but coverage is only "scanned" when it is current.
  if (!db.built) return { status: "unknown", reason: db.reason, scan };
  if (db.stale) return { status: "stale-db", reason: `Grype database is ${db.ageDays} days old (limit ${cfg.dbMaxAgeDays})`, scan };
  if (scan.dbBuilt !== db.built) return { status: "pending", reason: "rescan pending (vulnerability database updated)", scan };
  const age = now - Number(scan.scannedAt);
  if (!Number.isFinite(age) || age > cfg.resultMaxAgeDays * DAY) return { status: "pending", reason: `last scan is ${days(age)} days old (limit ${cfg.resultMaxAgeDays})`, scan };
  return { status: "scanned", reason: null, scan };
}

export async function imagesCycle({ db: _db, tenantId: _tenant, store, findings, config, now = Date.now, secrets = [] }) {
  const cfg = config.images;
  const staleAfterMs = threshold(config, "collectMinutes") * threshold(config, "staleFactor") * 60_000;
  return runCollector(store, IMAGES_COLLECTOR, async () => {
    const t = now();
    const dbInfo = readDb(cfg.outDir, cfg, t);
    const evidence = [];
    const rows = [];
    const wanted = new Map();

    for (const host of config.docker ?? []) {
      const containers = store.get(host.assetKey, "docker.containers");
      const images = store.get(host.assetKey, "docker.images");
      if (!containers || !images) { evidence.push({ assetKey: host.assetKey, kind: "grype.images", value: { listing: "missing", images: [] } }); continue; }
      const listing = t - Math.min(containers.collectedAt, images.collectedAt) > containers.staleAfterMs ? "stale" : "ok";
      const entries = [];
      for (const img of runningImages(containers.value, images.value)) {
        if (img.status === "registry") wanted.set(img.digest, img);
        const s = imageStatus(img, dbInfo, cfg, cfg.outDir, t);
        entries.push({ container: img.container, imageRef: img.imageRef, repo: img.repo ?? null, digest: img.digest ?? null, status: s.status, reason: s.reason, scannedAt: s.scan?.scannedAt ?? null, dbBuilt: s.scan?.dbBuilt ?? null, findings: s.scan?.matches.length ?? 0 });
        for (const m of s.scan?.matches ?? []) {
          const c = classifyMatch(m);
          if (!c.cve || !m.pkg?.name) continue;
          rows.push({ assetKey: host.assetKey, container: img.container, image: img.repo, cve: c.cve, pkg: { name: m.pkg.name, version: m.pkg.version ?? "", arch: "", type: m.pkg.type ?? null },
            severity: c.severity, cvss: c.cvss, fixState: c.fixState, fixedVersion: c.fixedVersion, lowConfidence: c.lowConfidence, condition: m.matchType ?? null, recognisedCondition: c.recognised, detectedAt: Number(s.scan.scannedAt) || null });
        }
      }
      evidence.push({ assetKey: host.assetKey, kind: "grype.images", value: { listing, images: entries } });
    }
    evidence.push({ assetKey: GLOBAL_KEY, kind: "grype.db", value: { built: dbInfo.built, status: dbInfo.status, stale: dbInfo.stale, reason: dbInfo.reason } });

    // Queue what is running; withdraw what isn't. Requests hold no secrets
    // and must be readable by the scanner's own user.
    writeAtomic(cfg.spoolDir, "settings.json", JSON.stringify({ v: 1, dockerHubPullsPerHour: cfg.dockerHubPullsPerHour }), 0o644);
    for (const [digest, img] of wanted) {
      const name = `req-${fileId(digest)}.json`;
      if (!existsSync(join(cfg.spoolDir, name))) {
        writeAtomic(cfg.spoolDir, name, JSON.stringify({ v: 1, digest, ref: `${img.repo}@${digest}`, registry: img.registry, platform: cfg.platform, requestedAt: t }), 0o644);
      }
    }
    for (const name of readdirSync(cfg.spoolDir)) {
      const m = /^req-(sha256)-([0-9a-f]{64})\.json$/u.exec(name);
      if (m && !wanted.has(`${m[1]}:${m[2]}`)) rmSync(join(cfg.spoolDir, name), { force: true });
    }

    return { evidence: evidence.map((e) => ({ source: IMAGES_COLLECTOR, ...e })), commit: () => findings.replaceSource("grype", rows, t, { transaction: false }) };
  }, { now, staleAfterMs, secrets, deadlineMs: 2 * 60_000 });
}
