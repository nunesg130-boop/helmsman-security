import test from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { parseKev, parseEpssCsvGz, refreshThreatFeeds } from "../src/collectors/threat-feeds.mjs";
import { FindingStore } from "../src/vuln/findings.mjs";
import { openDb } from "../src/db.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";

const kevDoc = (n) => ({ catalogVersion: "x", vulnerabilities: Array.from({ length: n }, (_, i) => ({ cveID: `CVE-2024-${1000 + i}`, dateAdded: "2024-05-01", knownRansomwareCampaignUse: i === 0 ? "Known" : "Unknown" })) });
const epssCsv = (n) => gzipSync(Buffer.from(`#model_version:v2025.03.14,score_date:2026-11-15T00:00:00+0000\ncve,epss,percentile\n${Array.from({ length: n }, (_, i) => `CVE-2024-${1000 + i},0.5,0.9`).join("\n")}\n`));

test("parseKev reads cveID, dateAdded and the ransomware flag", () => {
  const rows = parseKev(kevDoc(2));
  assert.deepEqual(rows, [{ cve: "CVE-2024-1000", dateAdded: "2024-05-01", ransomware: true }, { cve: "CVE-2024-1001", dateAdded: "2024-05-01", ransomware: false }]);
});
test("parseKev rejects a document without a vulnerabilities array or with a bad id", () => {
  assert.throws(() => parseKev({ title: "error page" }), /KEV/u);
  assert.throws(() => parseKev({ vulnerabilities: [{ cveID: "not-a-cve" }] }), /KEV/u);
});
test("parseEpssCsvGz reads a gzipped CSV with its comment line and header", () => {
  assert.deepEqual(parseEpssCsvGz(epssCsv(3)).map((r) => [r.cve, r.score, r.percentile]), [["CVE-2024-1000", 0.5, 0.9], ["CVE-2024-1001", 0.5, 0.9], ["CVE-2024-1002", 0.5, 0.9]]);
});
test("parseEpssCsvGz rejects non-gzip data, a wrong header and scores outside 0–1", () => {
  assert.throws(() => parseEpssCsvGz(Buffer.from("<html>not gzip</html>")), /EPSS/u);
  assert.throws(() => parseEpssCsvGz(gzipSync(Buffer.from("a,b,c\nCVE-2024-1,0.1,0.1\n"))), /EPSS/u);
  assert.throws(() => parseEpssCsvGz(gzipSync(Buffer.from("cve,epss,percentile\nCVE-2024-1,1.5,0.1\n"))), /EPSS/u);
});

async function run(routes, { minKev = 2, minEpss = 2, seed } = {}) {
  const srv = await startFixtureServer(routes);
  const findings = new FindingStore(openDb(":memory:"), "t");
  seed?.(findings);
  try {
    const http = createHttp({ allowHosts: ["127.0.0.1"] });
    const out = await refreshThreatFeeds({ http, findings, now: () => 5000, kevUrl: `${srv.url}/kev.json`, epssUrl: `${srv.url}/epss.csv.gz`, certSha256: srv.certSha256, minKev, minEpss })
      .then((o) => ({ out: o }), (error) => ({ error }));
    return { ...out, findings };
  } finally { await srv.close(); }
}
const good = { "/kev.json": kevDoc(3), "/epss.csv.gz": () => [200, epssCsv(3)] };

test("both feeds are stored with their fetch time", async () => {
  const { out, findings } = await run(good);
  assert.deepEqual(findings.feed("kev"), { fetchedAt: 5000, count: 3 });
  assert.deepEqual(findings.feed("epss"), { fetchedAt: 5000, count: 3 });
  assert.deepEqual(out.warnings, []);
  assert.deepEqual(out.evidence[0].value, { kev: { fetchedAt: 5000, count: 3 }, epss: { fetchedAt: 5000, count: 3 } });
});
test("a failing EPSS download keeps the old EPSS table and still updates KEV", async () => {
  const { out, findings } = await run({ ...good, "/epss.csv.gz": () => [500, "boom"] }, { seed: (f) => f.replaceEpss([{ cve: "CVE-1", score: 0.1, percentile: 0.1 }], 1000) });
  assert.deepEqual(findings.feed("epss"), { fetchedAt: 1000, count: 1 });
  assert.deepEqual(findings.feed("kev"), { fetchedAt: 5000, count: 3 });
  assert.ok(out.warnings.some((w) => /EPSS/u.test(w)));
});
test("an implausibly small feed is rejected (error page or truncated file)", async () => {
  const { out, findings } = await run(good, { minKev: 100, minEpss: 2 });
  assert.equal(findings.feed("kev"), null);
  assert.ok(out.warnings.some((w) => /KEV.*3 entries/u.test(w)));
});
test("when both feeds fail the run fails", async () => {
  const { error } = await run({ "/kev.json": () => [500, "x"], "/epss.csv.gz": () => [500, "x"] });
  assert.match(error.message, /KEV.*EPSS/su);
});
