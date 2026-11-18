// The container image scanner worker. It runs as its own system user
// (hs-grype), apart from the engine, and talks to the engine only through
// files: the engine drops scan requests in spool/, the worker writes results
// to out/. Syft pulls each image once into an SBOM; Grype scans the SBOM, and
// rescans it when its vulnerability database changes. Both run with a fixed
// minimal environment and reach the network only through a local proxy that
// allows the registries of queued images and the Grype database host.
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, existsSync, fchmodSync, fsyncSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { join } from "node:path";
import { registryHosts } from "./identity.mjs";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
// A registry must be a DNS name (with a dot and a letter): no IP literals,
// no "localhost", no ports. Those would be reached outside the proxy.
const REF = /^(?=[a-z0-9.-]*[a-z])[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$/u;
const PLATFORM = /^[a-z0-9]+\/[a-z0-9]+$/u;
const DB_HOSTS = ["grype.anchore.io"];
const DAY = 86400_000;
const FAILED_RETRY_MS = 6 * 3600_000;
const RATE_LIMITED_RETRY_MS = 3600_000;
const DB_RETRY_MS = 3600_000;
const KEEP_UNREQUESTED_MS = 14 * DAY;

export const fileId = (digest) => digest.replace(":", "-");

// Write a file so that it either has its full new content or isn't changed:
// temp file in the same directory, fsync, rename.
export function writeAtomic(dir, name, text, mode = 0o640) {
  const tmp = join(dir, `.${name}.${randomBytes(4).toString("hex")}.tmp`);
  const fd = openSync(tmp, "w", mode);
  try { fchmodSync(fd, mode); writeSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); } // fchmod: the umask must not narrow it
  renameSync(tmp, join(dir, name));
}

const readJson = (path) => { try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; } };
const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

function classifyFailure(stderr) {
  const text = stderr.toLowerCase();
  if (/toomanyrequests|rate limit|\b429\b/u.test(text)) return "rate-limited";
  if (/unauthorized|denied|\b401\b|\b403\b|authentication required/u.test(text)) return "pull-denied";
  if (/manifest unknown|not found|\b404\b|name unknown/u.test(text)) return "not-found";
  return null;
}

export function createWorker({ binDir, stateDir, homeDir = join(stateDir, "home"), installed, path = "/usr/bin:/bin", now = Date.now, timeoutMs = 20 * 60_000, maxBytes = 256 * 1024 * 1024, dbCheckMs = DAY, log = console.log }) {
  const dir = { spool: join(stateDir, "spool"), out: join(stateDir, "out"), db: join(stateDir, "db"), tmp: join(stateDir, "tmp") };
  const bins = { grype: join(binDir, "grype"), syft: join(binDir, "syft") };
  let proxy = null;
  let proxyPort = 0;
  let allowed = new Set();
  let blocked = new Set();

  function startProxy() {
    proxy = http.createServer((req, res) => { res.writeHead(403); res.end("only CONNECT is allowed"); });
    proxy.on("connect", (req, client) => {
      const [host, port] = String(req.url).split(":");
      const name = host.toLowerCase();
      if (!allowed.has(name) || Number(port) !== 443) {
        blocked.add(name);
        client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
        return;
      }
      const upstream = net.connect(443, name, () => { client.write("HTTP/1.1 200 Connection Established\r\n\r\n"); upstream.pipe(client); client.pipe(upstream); });
      upstream.on("error", () => client.destroy());
      client.on("error", () => upstream.destroy());
    });
    return new Promise((resolve) => proxy.listen(0, "127.0.0.1", () => { proxyPort = proxy.address().port; resolve(); }));
  }

  // Run one scanner with a fixed environment, a deadline and a byte cap on stdout.
  function run(name, args, hosts) {
    allowed = new Set(hosts);
    blocked = new Set();
    const env = {
      PATH: path, HOME: homeDir, TMPDIR: dir.tmp,
      GRYPE_DB_CACHE_DIR: dir.db, GRYPE_DB_AUTO_UPDATE: "false", GRYPE_CHECK_FOR_APP_UPDATE: "false", SYFT_CHECK_FOR_APP_UPDATE: "false",
      HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`, HTTP_PROXY: `http://127.0.0.1:${proxyPort}`, NO_PROXY: ""
    };
    return new Promise((resolve) => {
      const child = spawn(bins[name], args, { env, cwd: homeDir, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "", size = 0, tooLarge = false, timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
      child.stdout.on("data", (d) => { size += d.length; if (size > maxBytes) { tooLarge = true; child.kill("SIGKILL"); } else stdout += d; });
      child.stderr.on("data", (d) => { stderr = (stderr + d).slice(-4096); });
      child.on("close", (code) => { clearTimeout(timer); allowed = new Set(); resolve({ code, stdout, stderr, timedOut, tooLarge, blocked: [...blocked] }); });
      child.on("error", (e) => { clearTimeout(timer); resolve({ code: -1, stdout: "", stderr: e.message, timedOut: false, tooLarge: false, blocked: [] }); });
    });
  }

  function failure(r) {
    if (r.timedOut) return "timeout";
    if (r.tooLarge) return "too-large";
    if (r.blocked.length) return `blocked-host ${r.blocked[0]}`;
    return classifyFailure(r.stderr);
  }

  async function refreshDb() {
    const previous = readJson(join(dir.out, "db.json"));
    if (previous && previous.status === "ok" && now() - previous.checkedAt < dbCheckMs) return previous;
    if (previous && previous.status === "failed" && now() - previous.checkedAt < DB_RETRY_MS) return previous;
    const base = { v: 1, grypeVersion: installed.grype.version, checkedAt: now() };
    const update = await run("grype", ["db", "update"], DB_HOSTS);
    if (update.code !== 0) {
      const db = { ...base, status: "failed", reason: update.blocked.length ? `blocked-host ${update.blocked[0]}` : "db-unavailable", built: previous?.built ?? null, schemaVersion: previous?.schemaVersion ?? null, detail: update.stderr };
      writeAtomic(dir.out, "db.json", JSON.stringify(db));
      return db;
    }
    const status = await run("grype", ["db", "status", "-o", "json"], []);
    let parsed = null;
    try { parsed = JSON.parse(status.stdout); } catch { /* reported below */ }
    const built = parsed?.built && Number.isFinite(Date.parse(parsed.built)) ? parsed.built : null;
    const db = built && parsed.valid !== false
      ? { ...base, status: "ok", reason: null, built, schemaVersion: parsed.schemaVersion ?? null }
      : { ...base, status: "failed", reason: "db-unavailable", built: null, schemaVersion: null, detail: status.stderr };
    writeAtomic(dir.out, "db.json", JSON.stringify(db));
    return db;
  }

  function requests() {
    const out = [];
    for (const name of readdirSync(dir.spool)) {
      if (!/^req-sha256-[0-9a-f]{64}\.json$/u.test(name)) continue;
      const r = readJson(join(dir.spool, name));
      if (!r || r.v !== 1 || !DIGEST.test(r.digest) || !REF.test(r.ref) || !r.ref.endsWith(`@${r.digest}`) || !PLATFORM.test(r.platform ?? "")) {
        log(`ignoring malformed request ${name}`);
        continue;
      }
      if (name !== `req-${fileId(r.digest)}.json`) continue;
      out.push({ digest: r.digest, ref: r.ref, platform: r.platform, registry: r.ref.split("/")[0] });
    }
    return out.sort((a, b) => a.digest.localeCompare(b.digest));
  }

  function hubCap() {
    const s = readJson(join(dir.spool, "settings.json"));
    const n = Number(s?.dockerHubPullsPerHour);
    return Number.isFinite(n) && n > 0 ? n : 8;
  }

  // Docker Hub pulls in the last hour, kept on disk so a restart doesn't reset the cap.
  function hubPulls() {
    const list = readJson(join(dir.out, "hub-pulls.json"));
    return (Array.isArray(list) ? list : []).filter((x) => Number.isFinite(x) && now() - x < 3600_000);
  }

  function writeScan(req, fields, previous = null) {
    // A failed attempt keeps the last good result for this digest: same digest,
    // same packages, so those findings still stand.
    const lastGood = fields.status === "failed"
      ? (previous?.status === "scanned" ? { dbBuilt: previous.dbBuilt, scannedAt: previous.scannedAt, matches: previous.matches } : previous?.lastGood ?? null)
      : null;
    writeAtomic(dir.out, `scan-${fileId(req.digest)}.json`, JSON.stringify({
      v: 1, digest: req.digest, ref: req.ref, grypeVersion: installed.grype.version, syftVersion: installed.syft.version, scannedAt: now(), matches: [], reason: null, detail: null, lastGood, ...fields
    }));
  }

  async function scanOne(req, db) {
    const id = fileId(req.digest);
    const sbomPath = join(dir.out, `sbom-${id}.json`);
    const attemptPath = join(dir.out, `attempt-${id}.json`);
    const previous = readJson(join(dir.out, `scan-${id}.json`));
    const fail = (reason, detail) => writeScan(req, { status: "failed", reason, detail: detail || reason, dbBuilt: db.built }, previous);
    // An attempt record left behind means the worker died mid-scan (out of memory, power cut).
    if (existsSync(attemptPath)) { rmSync(attemptPath, { force: true }); fail("worker-stopped", "the scanner stopped during this image's scan"); return; }
    if (previous?.status === "scanned" && previous.dbBuilt === db.built && existsSync(sbomPath)) return;
    if (previous?.status === "failed") {
      const wait = previous.reason === "rate-limited" ? RATE_LIMITED_RETRY_MS : FAILED_RETRY_MS;
      if (now() - previous.scannedAt < wait) return;
    }
    const needsPull = !existsSync(sbomPath);
    const hub = req.registry === "docker.io";
    if (needsPull && hub && hubPulls().length >= hubCap()) return; // waits in the queue
    writeAtomic(dir.out, `attempt-${id}.json`, JSON.stringify({ v: 1, startedAt: now() }));
    try {
      if (needsPull) {
        if (hub) writeAtomic(dir.out, "hub-pulls.json", JSON.stringify([...hubPulls(), now()]));
        const tmp = join(dir.tmp, `sbom-${id}.${randomBytes(4).toString("hex")}.json`);
        const r = await run("syft", [`registry:${req.ref}`, "-o", `syft-json=${tmp}`, "--platform", req.platform], registryHosts(req.registry));
        let reason = failure(r);
        if (!reason && r.code === 0) {
          if (!existsSync(tmp)) reason = "syft-error";
          else if (statSync(tmp).size > maxBytes) reason = "too-large";
        } else if (!reason) reason = "syft-error";
        if (reason) { rmSync(tmp, { force: true }); fail(reason, r.stderr.slice(-4096)); return; }
        const fd = openSync(tmp, "r+");
        try { fsyncSync(fd); } finally { closeSync(fd); } // the SBOM must survive a power cut before it is trusted
        renameSync(tmp, sbomPath);
      }

      const outTmp = join(dir.tmp, `grype-${id}.${randomBytes(4).toString("hex")}.json`);
      const g = await run("grype", [`sbom:${sbomPath}`, "-o", "json", "--file", outTmp], []);
      const reason = failure(g) ?? (g.code === 0 && existsSync(outTmp) ? null : "grype-error");
      if (reason) {
        rmSync(outTmp, { force: true });
        if (reason === "grype-error") rmSync(sbomPath, { force: true }); // possibly a damaged SBOM: pull again after the back-off
        fail(reason, g.stderr.slice(-4096));
        return;
      }
      if (statSync(outTmp).size > maxBytes) { rmSync(outTmp, { force: true }); fail("too-large", "grype output over the size cap"); return; }
      const parsed = readJson(outTmp);
      rmSync(outTmp, { force: true });
      if (!parsed || !Array.isArray(parsed.matches)) { fail("grype-error", "unreadable grype output"); return; }
      const matches = parsed.matches.map((m) => {
        const v = m.vulnerability ?? {};
        const scoresOf = (list) => (list ?? []).map((c) => Number(c?.metrics?.baseScore)).filter(Number.isFinite);
        // Distro records often carry no score of their own; the related NVD record does.
        const own = scoresOf(v.cvss);
        const related = (m.relatedVulnerabilities ?? []).flatMap((r) => scoresOf(r.cvss));
        const scores = own.length ? own : related;
        return {
          id: String(v.id ?? ""),
          relatedCves: [...new Set((m.relatedVulnerabilities ?? []).map((r) => String(r.id ?? "")).filter((x) => x.startsWith("CVE-")))],
          severity: v.severity ?? null,
          cvss: scores.length ? Math.max(...scores) : null,
          fixState: v.fix?.state ?? "unknown",
          fixVersions: Array.isArray(v.fix?.versions) ? v.fix.versions.map(String) : [],
          pkg: { name: m.artifact?.name ?? null, version: m.artifact?.version ?? null, type: m.artifact?.type ?? null, purl: m.artifact?.purl ?? null },
          matchType: m.matchDetails?.[0]?.type ?? null
        };
      });
      writeScan(req, { status: "scanned", dbBuilt: db.built, matches });
    } finally {
      rmSync(attemptPath, { force: true });
    }
  }

  // Results for digests nobody has asked about in two weeks are removed.
  function tidy(live) {
    const keep = new Set(live.map((r) => fileId(r.digest)));
    for (const name of readdirSync(dir.out)) {
      const m = /^(?:sbom|scan)-(sha256-[0-9a-f]{64})\.json$/u.exec(name);
      if (m && !keep.has(m[1]) && now() - statSync(join(dir.out, name)).mtimeMs > KEEP_UNREQUESTED_MS) rmSync(join(dir.out, name), { force: true });
    }
    for (const name of readdirSync(dir.tmp)) rmSync(join(dir.tmp, name), { force: true, recursive: true });
  }

  return {
    async start() {
      for (const name of ["grype", "syft"]) {
        if (!existsSync(bins[name]) || sha256File(bins[name]) !== installed[name]?.sha256) throw new Error(`${name} checksum doesn't match the installed record; refusing to run`);
      }
      await startProxy();
    },
    async tick() {
      const live = requests();
      tidy(live);
      const db = await refreshDb();
      if (db.status !== "ok") return;
      for (const req of live) await scanOne(req, db);
    },
    async stop() { if (proxy) await new Promise((r) => { proxy.closeAllConnections?.(); proxy.close(r); }); proxy = null; }
  };
}
