import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
const PATH = `${dirname(process.execPath)}:/usr/bin:/bin`;
import { createHash } from "node:crypto";
import { createWorker } from "../src/images/worker.mjs";

const FAKES = new URL("./fixtures/grype/", import.meta.url).pathname;
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const D = (n) => `sha256:${String(n).repeat(64).slice(0, 64)}`;
const fileOf = (digest) => digest.replace(":", "-");

function setup({ settings } = {}) {
  const root = mkdtempSync(join(tmpdir(), "hs-grype-"));
  const state = join(root, "state"), bin = join(root, "bin");
  for (const d of ["spool", "out", "db", "tmp", "home"]) mkdirSync(join(state, d), { recursive: true });
  mkdirSync(bin);
  copyFileSync(join(FAKES, "fake-grype"), join(bin, "grype"));
  copyFileSync(join(FAKES, "fake-syft"), join(bin, "syft"));
  const installed = { grype: { version: "0.122.0", sha256: sha(join(bin, "grype")) }, syft: { version: "1.57.2", sha256: sha(join(bin, "syft")) } };
  if (settings) writeFileSync(join(state, "spool", "settings.json"), JSON.stringify(settings));
  let t = Date.parse("2026-11-17T12:00:00Z");
  const worker = createWorker({ binDir: bin, stateDir: state, installed, path: PATH, now: () => t, timeoutMs: 3000, maxBytes: 1_000_000, log: () => {} });
  const request = (ref, digest = ref.slice(ref.indexOf("@") + 1)) => writeFileSync(join(state, "spool", `req-${fileOf(digest)}.json`),
    JSON.stringify({ v: 1, digest, ref, registry: ref.split("/")[0], platform: "linux/amd64", requestedAt: t }));
  const read = (name) => JSON.parse(readFileSync(join(state, "out", name), "utf8"));
  const home = join(state, "home");
  const calls = () => (existsSync(join(home, "fake-calls.log")) ? readFileSync(join(home, "fake-calls.log"), "utf8").trim().split("\n") : []);
  return { state, home, bin, installed, worker, request, read, calls, advance: (ms) => { t += ms; }, run: async () => { await worker.start(); try { await worker.tick(); } finally { await worker.stop(); } } };
}

test("a request is pulled once into an SBOM, then scanned; the result carries the database build", async () => {
  const w = setup();
  w.request(`ghcr.io/goauthentik/server@${D(1)}`);
  await w.run();
  const db = w.read("db.json");
  assert.deepEqual([db.status, db.built, db.grypeVersion], ["ok", "2026-11-17T04:00:00Z", "0.122.0"]);
  const scan = w.read(`scan-${fileOf(D(1))}.json`);
  assert.deepEqual([scan.status, scan.reason, scan.digest, scan.dbBuilt, scan.syftVersion], ["scanned", null, D(1), "2026-11-17T04:00:00Z", "1.57.2"]);
  assert.deepEqual(scan.matches, [{ id: "GHSA-abcd-efgh-ijkl", relatedCves: ["CVE-2026-1001"], severity: "High", cvss: 7.5, fixState: "fixed", fixVersions: ["1.2"],
    pkg: { name: "openssl", version: "1.1", type: "apk", purl: "pkg:apk/alpine/openssl@1.1" }, matchType: "exact-direct-match" }]);
  assert.ok(existsSync(join(w.state, "out", `sbom-${fileOf(D(1))}.json`)));
  assert.deepEqual(readdirSync(join(w.state, "out")).filter((f) => f.startsWith(".")), [], "no temp files left behind");
  assert.ok(w.calls().some((c) => c.startsWith(`syft registry:ghcr.io/goauthentik/server@${D(1)} -o syft-json=`) && c.endsWith("--platform linux/amd64")));
});
test("a scanned digest isn't pulled again; a newer database rescans the stored SBOM only", async () => {
  const w = setup();
  w.request(`ghcr.io/a/b@${D(2)}`);
  await w.run();
  await w.run();
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 1);
  assert.equal(w.calls().filter((c) => c.startsWith("grype sbom:")).length, 1);
  writeFileSync(join(w.home, "fake-db-built"), "2026-11-18T04:00:00Z");
  w.advance(25 * 3600_000);
  await w.run();
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 1, "no new pull");
  assert.equal(w.calls().filter((c) => c.startsWith("grype sbom:")).length, 2);
  assert.equal(w.read(`scan-${fileOf(D(2))}.json`).dbBuilt, "2026-11-18T04:00:00Z");
});
for (const [word, reason] of [["denied", "pull-denied"], ["notfound", "not-found"], ["ratelimit", "rate-limited"]]) {
  test(`a pull that fails with "${word}" is a failed scan with reason ${reason}`, async () => {
    const w = setup();
    w.request(`ghcr.io/x/${word}@${D(3)}`);
    await w.run();
    const scan = w.read(`scan-${fileOf(D(3))}.json`);
    assert.deepEqual([scan.status, scan.reason, scan.matches], ["failed", reason, []]);
    assert.ok(scan.detail.length > 0 && scan.detail.length <= 4096);
  });
}
test("a scan that runs too long is stopped and recorded as a timeout", async () => {
  const w = setup();
  w.request(`ghcr.io/x/slow@${D(4)}`);
  const t0 = Date.now();
  await w.run();
  assert.ok(Date.now() - t0 < 10_000);
  assert.equal(w.read(`scan-${fileOf(D(4))}.json`).reason, "timeout");
});
test("an SBOM over the size cap is refused as too-large", async () => {
  const w = setup();
  const small = createWorker({ binDir: w.bin, stateDir: w.state, installed: w.installed, path: PATH, now: () => Date.now(), timeoutMs: 3000, maxBytes: 1000, log: () => {} });
  w.request(`ghcr.io/x/huge@${D(5)}`);
  await small.start(); try { await small.tick(); } finally { await small.stop(); }
  assert.equal(w.read(`scan-${fileOf(D(5))}.json`).reason, "too-large");
});
test("a connection to a host outside the allowlist is refused and named", async () => {
  const w = setup();
  w.request(`ghcr.io/x/blocked@${D(6)}`);
  await w.run();
  assert.equal(w.read(`scan-${fileOf(D(6))}.json`).reason, "blocked-host evil.example.com");
});
test("Docker Hub pulls are capped per hour; the rest wait in the queue", async () => {
  const w = setup({ settings: { dockerHubPullsPerHour: 2 } });
  for (const n of [7, 8, 9]) w.request(`docker.io/library/app${n}@${D(n)}`);
  await w.run();
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 2);
  assert.equal(readdirSync(join(w.state, "out")).filter((f) => f.startsWith("scan-")).length, 2);
  w.advance(61 * 60_000);
  await w.run();
  assert.equal(readdirSync(join(w.state, "out")).filter((f) => f.startsWith("scan-")).length, 3);
});
test("the scanners get only a fixed, minimal environment", async () => {
  const w = setup();
  process.env.HS_SECRET_SHOULD_NOT_LEAK = "x";
  try {
    w.request(`ghcr.io/x/y@${D(1)}`);
    await w.run();
  } finally { delete process.env.HS_SECRET_SHOULD_NOT_LEAK; }
  for (const name of ["syft", "grype"]) {
    const env = JSON.parse(readFileSync(join(w.home, `fake-env-${name}.json`), "utf8"));
    const keys = Object.keys(env).filter((k) => !["_", "PWD", "SHLVL", "OLDPWD"].includes(k)).sort();
    assert.deepEqual(keys, ["GRYPE_CHECK_FOR_APP_UPDATE", "GRYPE_DB_AUTO_UPDATE", "GRYPE_DB_CACHE_DIR", "HOME", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "PATH", "SYFT_CHECK_FOR_APP_UPDATE", "TMPDIR"], name);
    assert.match(env.HTTPS_PROXY, /^http:\/\/127\.0\.0\.1:\d+$/u);
    assert.equal(env.NO_PROXY, "");
  }
});
test("the worker refuses to start when a binary's checksum doesn't match", async () => {
  const w = setup();
  const bad = createWorker({ binDir: w.bin, stateDir: w.state, installed: { ...w.installed, syft: { version: "1.57.2", sha256: "0".repeat(64) } }, now: Date.now, log: () => {} });
  await assert.rejects(bad.start(), /syft checksum/u);
});
test("a database that can't be updated is recorded as failed, and nothing is scanned against it", async () => {
  const w = setup();
  writeFileSync(join(w.home, "fake-db-fail"), "1");
  w.request(`ghcr.io/x/y@${D(1)}`);
  await w.run();
  assert.deepEqual([w.read("db.json").status, w.read("db.json").reason], ["failed", "db-unavailable"]);
  assert.ok(!existsSync(join(w.state, "out", `scan-${fileOf(D(1))}.json`)));
});
test("malformed request files are ignored, never passed to the scanners", async () => {
  const w = setup();
  writeFileSync(join(w.state, "spool", "req-sha256-zzz.json"), JSON.stringify({ v: 1, digest: "sha256:zzz", ref: "ghcr.io/x@sha256:zzz", platform: "linux/amd64" }));
  writeFileSync(join(w.state, "spool", `req-${fileOf(D(1))}.json`), JSON.stringify({ v: 1, digest: D(1), ref: `ghcr.io/x;rm -rf /@${D(1)}`, platform: "linux/amd64" }));
  writeFileSync(join(w.state, "spool", "req-garbage.json"), "{not json");
  await w.run();
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 0);
});

// --- review fixes ---
test("a failed rescan keeps the last good result for the same digest", async () => {
  const w = setup();
  w.request(`ghcr.io/a/b@${D(2)}`);
  await w.run();
  writeFileSync(join(w.home, "fake-db-built"), "2026-11-18T04:00:00Z");
  writeFileSync(join(w.home, "fake-grype-fail"), "1");
  w.advance(25 * 3600_000);
  await w.run();
  const scan = w.read(`scan-${fileOf(D(2))}.json`);
  assert.deepEqual([scan.status, scan.reason], ["failed", "grype-error"]);
  assert.deepEqual([scan.lastGood.dbBuilt, scan.lastGood.matches.length], ["2026-11-17T04:00:00Z", 1]);
});
test("an SBOM Grype can't read is removed so the image is pulled again later, after a back-off", async () => {
  const w = setup();
  writeFileSync(join(w.home, "fake-grype-fail"), "1");
  w.request(`ghcr.io/a/b@${D(2)}`);
  await w.run();
  assert.equal(w.read(`scan-${fileOf(D(2))}.json`).reason, "grype-error");
  assert.ok(!existsSync(join(w.state, "out", `sbom-${fileOf(D(2))}.json`)));
  w.advance(60_000);
  await w.run();
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 1, "no retry inside the back-off");
});
test("a pull interrupted by a crash is recorded as failed and backed off, not retried in a loop", async () => {
  const w = setup();
  w.request(`ghcr.io/a/b@${D(2)}`);
  writeFileSync(join(w.state, "out", `attempt-${fileOf(D(2))}.json`), JSON.stringify({ v: 1, startedAt: Date.parse("2026-11-17T11:00:00Z") }));
  await w.run();
  assert.equal(w.read(`scan-${fileOf(D(2))}.json`).reason, "worker-stopped");
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 0);
  assert.ok(!existsSync(join(w.state, "out", `attempt-${fileOf(D(2))}.json`)));
});
test("the Docker Hub hourly count survives a restart of the worker", async () => {
  const w = setup({ settings: { dockerHubPullsPerHour: 1 } });
  w.request(`docker.io/library/a@${D(7)}`);
  await w.run();
  w.request(`docker.io/library/b@${D(8)}`);
  const second = createWorker({ binDir: w.bin, stateDir: w.state, installed: w.installed, path: PATH, now: () => Date.parse("2026-11-17T12:10:00Z"), timeoutMs: 3000, log: () => {} });
  await second.start(); try { await second.tick(); } finally { await second.stop(); }
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 1);
});
test("requests for registries given by address, port or localhost are ignored", async () => {
  const w = setup();
  for (const [n, ref] of [[1, "127.0.0.1:5000/x"], [2, "localhost/x"], [3, "10.0.0.5/x"], [4, "registry.lan:5000/x"]]) w.request(`${ref}@${D(n)}`);
  await w.run();
  assert.equal(w.calls().filter((c) => c.startsWith("syft")).length, 0);
});
