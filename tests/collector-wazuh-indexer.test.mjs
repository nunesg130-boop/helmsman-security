import test from "node:test";
import assert from "node:assert/strict";
import { createWazuhIndexer414 } from "../src/collectors/wazuh-indexer414.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";
import { indexerRoutes, vulnDoc, SEARCH_PATH } from "./fixtures/wazuh-indexer-fixture.mjs";

async function withIndexer(routes, fn, opts = {}) {
  const srv = await startFixtureServer(routes);
  try {
    const ix = createWazuhIndexer414({ http: createHttp({ allowHosts: ["127.0.0.1"] }), baseUrl: srv.url, user: "helmsec-vuln-ro", password: "ix-secret", certSha256: srv.certSha256, requestsPerMinute: 0, sleep: async () => {}, ...opts });
    return await fn(ix, srv);
  } finally { await srv.close(); }
}
const many = (n) => Array.from({ length: n }, (_, i) => vulnDoc({ agent: String(i % 3).padStart(3, "0"), cve: `CVE-2026-${String(i).padStart(5, "0")}` }));

test("pages with search_after until empty and returns every record", async () => {
  await withIndexer(indexerRoutes(many(2500)), async (ix, srv) => {
    const out = await ix.vulnerabilities();
    assert.equal(out.records.length, 2500);
    assert.equal(out.total, 2500);
    assert.equal(new Set(out.records.map((r) => r.cve)).size, 2500);
    const pages = srv.requests.map((r) => JSON.parse(r.body)).filter((q) => q.size > 0);
    assert.equal(pages.length, 4);
    assert.equal(pages[0].search_after, undefined);
    assert.ok(Array.isArray(pages[1].search_after));
  });
});

test("sends Basic auth with GET and requests only the needed fields, sorted for search_after", async () => {
  await withIndexer(indexerRoutes([vulnDoc()]), async (ix, srv) => {
    await ix.vulnerabilities();
    const r = srv.requests[0];
    assert.equal(r.method, "GET");
    assert.equal(r.url, SEARCH_PATH);
    assert.equal(r.headers.authorization, `Basic ${Buffer.from("helmsec-vuln-ro:ix-secret").toString("base64")}`);
    const q = JSON.parse(r.body);
    assert.equal(q.track_total_hits, true);
    assert.deepEqual(q.sort.map((x) => Object.keys(x)[0]), ["agent.id", "vulnerability.id", "package.name", "package.version", "package.architecture", "package.type"]);
    assert.ok(q._source.includes("vulnerability.scanner.condition") && !q._source.includes("vulnerability.description"));
  });
});

test("a record is normalised: severity, cvss, fix state, confidence, detectedAt", async () => {
  await withIndexer(indexerRoutes([vulnDoc()]), async (ix) => {
    assert.deepEqual((await ix.vulnerabilities()).records[0], {
      agentId: "010", agentName: "Jellyfin", cve: "CVE-2026-68479",
      pkg: { name: "linux-image-amd64", version: "6.12.74-2", arch: "amd64", type: "deb" },
      severity: "high", cvss: 7.8, fixState: "fix-available-not-applied", fixedVersion: "6.12.100-1", lowConfidence: false,
      condition: "Package less than 6.12.100-1", recognisedCondition: true, detectedAt: Date.parse("2026-11-13T21:45:37.604Z")
    });
  });
});

test("odd values degrade to unknown rather than failing or guessing", async () => {
  const doc = vulnDoc({ severity: "-", score: null, condition: "some new wording", source: "National Vulnerability Database", detectedAt: "not a date" });
  await withIndexer(indexerRoutes([doc]), async (ix) => {
    const r = (await ix.vulnerabilities()).records[0];
    assert.deepEqual([r.severity, r.cvss, r.fixState, r.fixedVersion, r.lowConfidence, r.recognisedCondition, r.detectedAt], ["unknown", null, "unknown", null, true, false, null]);
  });
});

test("a short result (count differs from total) is retried once, then fails the run", async () => {
  await withIndexer(indexerRoutes(many(9), { total: 10 }), async (ix, srv) => {
    await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "parse" && /9 of 10/u.test(e.message));
    assert.equal(srv.requests.filter((r) => JSON.parse(r.body).search_after === undefined && JSON.parse(r.body).size > 0).length, 2);
  });
});

test("an empty answer is a failed read, never 'no vulnerabilities'", async () => {
  await withIndexer(indexerRoutes([]), async (ix) => {
    await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "parse" && /no vulnerability records/u.test(e.message));
  });
});

for (const [label, envelope] of [["a timed-out search", { timed_out: true }], ["a failed shard", { _shards: { total: 2, successful: 1, failed: 1 } }], ["missing shard information", { _shards: undefined }]]) {
  test(`${label} fails the run instead of being read as complete`, async () => {
    await withIndexer(indexerRoutes(many(5), { envelope }), async (ix) => {
      await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "parse" && /partial/u.test(e.message));
    });
  });
}

test("a lower-bound total (relation gte) fails the run", async () => {
  const hits = [{ _source: vulnDoc(), sort: ["010", "CVE-2026-68479", "linux-image-amd64", "6.12.74-2", "amd64", "deb"] }];
  await withIndexer({ [`GET ${SEARCH_PATH}`]: () => [200, { timed_out: false, _shards: { failed: 0 }, hits: { total: { value: 10000, relation: "gte" }, hits } }] }, async (ix) => {
    await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "parse");
  });
});

test("identical records straddling a page boundary are counted, not lost or fatal", async () => {
  const twin = () => vulnDoc({ agent: "001", cve: "CVE-2026-00002" });
  const docs = [vulnDoc({ agent: "001", cve: "CVE-2026-00001" }), twin(), twin(), twin(), vulnDoc({ agent: "001", cve: "CVE-2026-00003" })];
  await withIndexer(indexerRoutes(docs), async (ix) => {
    const out = await ix.vulnerabilities();
    assert.deepEqual(out.records.map((r) => r.cve), ["CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"]);
    assert.deepEqual([out.total, out.duplicates], [5, 2]);
    assert.deepEqual([...out.agents], [["001", 3]]);
  }, { pageSize: 2 });
});

test("identical records on the same page collapse into one finding and are counted", async () => {
  const docs = [vulnDoc({ cve: "CVE-1" }), vulnDoc({ cve: "CVE-1" }), vulnDoc({ cve: "CVE-2" })];
  await withIndexer(indexerRoutes(docs), async (ix) => {
    const out = await ix.vulnerabilities();
    assert.deepEqual([out.records.length, out.duplicates, out.total], [2, 1, 3]);
  });
});

test("records missing an optional sort field still page correctly", async () => {
  const docs = many(5).map((d) => { delete d.package.architecture; return d; });
  await withIndexer(indexerRoutes(docs), async (ix) => {
    assert.equal((await ix.vulnerabilities()).records.length, 5);
  }, { pageSize: 2 });
});

test("a hit without a CVE id fails the run rather than being skipped", async () => {
  const bad = vulnDoc();
  delete bad.vulnerability.id;
  await withIndexer(indexerRoutes([vulnDoc({ cve: "CVE-1" }), bad]), async (ix) => {
    await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "parse");
  });
});

test("an unexpected response shape fails with parse", async () => {
  await withIndexer({ [`GET ${SEARCH_PATH}`]: () => [200, { error: "nope" }] }, async (ix) => {
    await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "parse");
  });
});

test("agents map counts records per agent", async () => {
  await withIndexer(indexerRoutes(many(7)), async (ix) => {
    assert.deepEqual([...(await ix.vulnerabilities()).agents].sort(), [["000", 3], ["001", 2], ["002", 2]]);
  });
});

test("HTTP 401 fails with auth", async () => {
  await withIndexer({ [`GET ${SEARCH_PATH}`]: () => [401, {}] }, async (ix) => {
    await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "auth");
  });
});

test("HTTP 429 waits and retries", async () => {
  let calls = 0;
  const waits = [];
  const ok = indexerRoutes([vulnDoc()])[`GET ${SEARCH_PATH}`];
  await withIndexer({ [`GET ${SEARCH_PATH}`]: (req, text) => (++calls === 1 ? [429, {}] : ok(req, text)) }, async (ix) => {
    assert.equal((await ix.vulnerabilities()).records.length, 1);
    assert.deepEqual(waits, [15_000]);
  }, { sleep: async (ms) => { waits.push(ms); } });
});

test("a server that keeps returning the same page is stopped, not followed forever", async () => {
  const hits = [{ _source: vulnDoc(), sort: ["010", "CVE-2026-68479", "linux-image-amd64", "6.12.74-2", "amd64", "deb"] }];
  await withIndexer({ [`GET ${SEARCH_PATH}`]: () => [200, { timed_out: false, _shards: { failed: 0 }, hits: { total: { value: 1, relation: "eq" }, hits } }] }, async (ix) => {
    await assert.rejects(() => ix.vulnerabilities(), (e) => e.code === "parse");
  });
});
