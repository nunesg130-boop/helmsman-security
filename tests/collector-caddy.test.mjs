import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { collectCaddyShape, validateShape } from "../src/collectors/caddy-shape.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const FILTER = here("../deploy/caddy/shape.jq");
const EXPORTER = here("../deploy/caddy/export-shape.sh");
const PLANTED = here("./fixtures/caddy-config-planted.json");
const live = () => JSON.parse(readFileSync(here("./fixtures/caddy-shape-live.json"), "utf8"));

// The filter decides what leaves the Caddy host, so in CI this can't be skipped.
const haveJq = spawnSync("jq", ["--version"]).status === 0;
if (!haveJq && process.env.CI) throw new Error("jq is required in CI: the Caddy shape filter tests must run");
const jqTest = haveJq ? test : (name) => test(name, { skip: "jq is not installed on this machine" }, () => {});

jqTest("the filter emits no planted secret and names what it doesn't understand", () => {
  const r = spawnSync("jq", ["-f", FILTER, PLANTED], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!r.stdout.includes("SECRET"), "a planted secret leaked");
  const s = JSON.parse(r.stdout).servers[0];
  assert.equal(JSON.parse(r.stdout).version, 2);
  assert.deepEqual([s.trustedProxies, s.trustedProxiesStrict, s.clientIpHeaders], [{ source: "static", ranges: ["192.168.0.108/32"] }, true, ["Cf-Connecting-Ip"]]);
  const [a, b] = s.routes;
  assert.equal(a.group, "g1");
  assert.deepEqual(a.match[0], { host: ["a.example"], unsupported: ["header"] });
  assert.deepEqual(a.match[1].not, [{ remote_ip: { ranges: ["10.0.0.0/8"] }, unsupported: ["query"] }]);
  assert.deepEqual(a.handle[1].handleResponse, [{ statusCodes: [2], unsupportedMatch: [], setsStatus: false, handlers: ["headers", "vars"], setsRequestHeaders: ["X-Authentik-Username"], innerMatchers: ["not"] }]);
  assert.deepEqual(b.match[0].client_ip, { ranges: ["192.168.0.0/24"] });
  assert.deepEqual(b.handle, [{ handler: "static_response" }, { handler: "weird" }]);
});

async function exporter(routes, { seed } = {}) {
  const srv = await startFixtureServer(routes, { tls: false });
  const dir = mkdtempSync(join(tmpdir(), "hs-shape-"));
  const out = join(dir, "shape.json");
  if (seed !== undefined) writeFileSync(out, seed);
  try {
    // Asynchronous: the stand-in admin API runs in this process and must stay responsive.
    const r = await new Promise((resolve) => {
      const child = spawn("sh", [EXPORTER], { env: { ...process.env, HS_CADDY_ADMIN_URL: `${srv.url}/config/`, HS_CADDY_FILTER: process.env.TEST_FILTER ?? FILTER, HS_CADDY_OUT: out } });
      let stderr = "";
      child.stderr.on("data", (d) => { stderr += d; });
      child.on("close", (status) => resolve({ status, stderr }));
    });
    let text = null;
    try { text = readFileSync(out, "utf8"); } catch { /* no file */ }
    return { status: r.status, text, stderr: r.stderr };
  } finally { await srv.close(); }
}
const planted = () => JSON.parse(readFileSync(PLANTED, "utf8"));

jqTest("the exporter writes a validated shape", async () => {
  const r = await exporter({ "/config/": planted() }, { seed: "old" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.text).version, 2);
});
for (const [label, routes] of [
  ["an HTTP error from the admin API", { "/config/": () => [500, "boom"] }],
  ["a body that isn't JSON", { "/config/": () => [200, "<html>error</html>"] }],
  ["a config with no routes", { "/config/": { apps: { http: { servers: { srv0: { listen: [":443"], routes: [] } } } } } }],
  ["a config with no http app", { "/config/": { admin: {} } }]
]) {
  jqTest(`the exporter leaves the previous file untouched on ${label}`, async () => {
    const r = await exporter(routes, { seed: "previous-content" });
    assert.notEqual(r.status, 0);
    assert.equal(r.text, "previous-content");
  });
}
jqTest("the exporter leaves the previous file untouched when the filter itself fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hs-filter-"));
  const broken = join(dir, "broken.jq");
  writeFileSync(broken, "this is not jq (");
  process.env.TEST_FILTER = broken;
  try {
    const r = await exporter({ "/config/": planted() }, { seed: "previous-content" });
    assert.notEqual(r.status, 0);
    assert.equal(r.text, "previous-content");
  } finally { delete process.env.TEST_FILTER; }
});

const AT = 1794873596_000;
const check = (doc, now = AT + 60_000) => validateShape(doc, { now, maxAgeMs: 30 * 60_000 });
test("the live shape is accepted", () => assert.equal(check(live()).servers[0].routes.length, 11));
test("stale, future-dated, old-version, empty and malformed shapes are rejected", () => {
  assert.throws(() => check(live(), AT + 31 * 60_000), /min old/u);
  assert.throws(() => check(live(), AT - 10 * 60_000), /future/u);
  assert.throws(() => check({ ...live(), version: 1 }), /version 1/u);
  assert.throws(() => check({ ...live(), servers: [{ server: "srv0", routes: [] }] }), /no routes/u);
  assert.throws(() => check({ version: 2, generatedAt: AT / 1000 }), /servers/u);
  assert.throws(() => check([]), /not an object/u);
});
test("the collector stores the shape dated at its generation time", async () => {
  const srv = await startFixtureServer({ "/shape.json": live() }, { tls: false });
  try {
    const http = createHttp({ allowHttpHosts: ["127.0.0.1"] });
    const cfg = { url: `${srv.url}/shape.json`, assetKey: "pve:guest:105", maxAgeMinutes: 30 };
    const out = await collectCaddyShape({ http, cfg, now: () => AT + 60_000 });
    assert.deepEqual([out.evidence[0].assetKey, out.evidence[0].kind, out.evidence[0].collectedAt], ["pve:guest:105", "caddy.shape", AT]);
    await assert.rejects(collectCaddyShape({ http, cfg, now: () => AT + 3600_000 }), (e) => e.code === "parse");
  } finally { await srv.close(); }
});
jqTest("the exporter fails on an HTTP error even when the error body is a valid config", async () => {
  const r = await exporter({ "/config/": () => [500, planted()] }, { seed: "previous-content" });
  assert.notEqual(r.status, 0);
  assert.equal(r.text, "previous-content");
});
