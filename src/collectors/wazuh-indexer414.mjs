import { createPacer } from "./pacing.mjs";
import { fixStateFromCondition, normaliseSeverity, isLowConfidence } from "../vuln/classify.mjs";

// Wazuh 4.14 keeps vulnerability state in its indexer (OpenSearch), not in
// the server API. This adapter reads it with a search-only user. Contract
// (a Wazuh 5.x adapter must match it):
//   vulnerabilities() -> { records, total, duplicates, agents: Map<agentId, count> }
// The read is all-or-nothing: a count that doesn't match what the indexer
// says exists, or a record missing its identity, fails the whole run.
const INDEX = "wazuh-states-vulnerabilities-*";
const SORT = ["agent.id", "vulnerability.id", "package.name", "package.version", "package.architecture", "package.type"];
const FIELDS = [
  "agent.id", "agent.name", "package.name", "package.version", "package.architecture", "package.type",
  "vulnerability.id", "vulnerability.severity", "vulnerability.score.base", "vulnerability.detected_at",
  "vulnerability.under_evaluation", "vulnerability.scanner.condition", "vulnerability.scanner.source"
];
const parseError = (message) => Object.assign(new Error(message), { code: "parse" });

function normalise(src) {
  const agentId = src?.agent?.id;
  const cve = src?.vulnerability?.id;
  const name = src?.package?.name;
  if (![agentId, cve, name].every((v) => typeof v === "string" && v)) throw parseError("vulnerability record without agent, CVE or package name");
  const v = src.vulnerability;
  const condition = typeof v.scanner?.condition === "string" ? v.scanner.condition : null;
  const fix = fixStateFromCondition(condition);
  const cvss = Number(v.score?.base);
  const detected = Date.parse(v.detected_at);
  return {
    agentId, agentName: String(src.agent.name ?? ""), cve,
    pkg: { name, version: String(src.package.version ?? ""), arch: String(src.package.architecture ?? ""), type: src.package.type ?? null },
    severity: normaliseSeverity(v.severity),
    cvss: v.score?.base != null && Number.isFinite(cvss) ? cvss : null,
    fixState: fix.fixState, fixedVersion: fix.fixedVersion,
    lowConfidence: isLowConfidence({ source: v.scanner?.source, underEvaluation: v.under_evaluation }),
    condition, recognisedCondition: fix.recognised,
    detectedAt: Number.isFinite(detected) ? detected : null
  };
}

const keyOf = (r) => [r.agentId, r.cve, r.pkg.name, r.pkg.version, r.pkg.arch, r.pkg.type ?? ""];

export function createWazuhIndexer414({ http, baseUrl, user, password, certSha256, requestsPerMinute = 60, pageSize = 1000, sleep, now }) {
  const url = `${baseUrl.replace(/\/+$/u, "")}/${INDEX}/_search`;
  const headers = { authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}` };
  const paced = createPacer({ requestsPerMinute, sleep, now });

  // Every answer must be complete: no timeout, no failed shard, an exact total.
  async function search(body) {
    const res = await paced(() => http.fetchJson(url, { certSha256, headers, body: { track_total_hits: true, ...body }, timeoutMs: 30_000, maxBytes: 20_000_000 }));
    const hits = res?.hits?.hits;
    if (!Array.isArray(hits) || !Number.isFinite(res.hits.total?.value)) throw parseError("unexpected response from the indexer");
    if (res.timed_out !== false || res._shards?.failed !== 0 || res.hits.total.relation !== "eq") throw parseError("the indexer returned a partial answer (timeout, failed shard or inexact total)");
    return { hits, total: res.hits.total.value };
  }

  // How many records share one exact identity. search_after skips every
  // record equal to the last one on a page, so twins across a page boundary
  // have to be counted separately.
  async function countOf(key) {
    const filter = [];
    const mustNot = [];
    SORT.forEach((field, i) => {
      if (key[i] === "" || key[i] == null) mustNot.push({ exists: { field } });
      else filter.push({ term: { [field]: key[i] } });
    });
    return (await search({ size: 0, query: { bool: { filter, must_not: mustNot } } })).total;
  }

  async function readAll() {
    const byKey = new Map();
    let seen = 0; // records accounted for, twins included
    let total = null;
    let after;
    for (;;) {
      const page = await search({ size: pageSize, _source: FIELDS, sort: SORT.map((f) => ({ [f]: { order: "asc", missing: "_first" } })), query: { match_all: {} }, ...(after ? { search_after: after } : {}) });
      total = page.total;
      if (page.hits.length === 0) break;
      let lastKey = null;
      let lastOnPage = 0;
      for (const h of page.hits) {
        const r = normalise(h._source);
        const k = JSON.stringify(keyOf(r));
        if (!byKey.has(k)) byKey.set(k, r);
        seen += 1;
        lastOnPage = k === lastKey ? lastOnPage + 1 : 1;
        lastKey = k;
      }
      const next = page.hits[page.hits.length - 1].sort;
      if (!Array.isArray(next)) throw parseError("indexer hit without sort values");
      if (page.hits.length === pageSize) {
        const twins = await countOf(JSON.parse(lastKey));
        if (twins > lastOnPage) seen += twins - lastOnPage;
      }
      // More than the indexer says exist means the same page keeps coming back.
      if (seen > total) throw parseError(`indexer returned ${seen} of ${total} vulnerability records`);
      after = next;
    }
    if (total === 0) throw parseError("the indexer returned no vulnerability records at all (wrong permissions, or the index is missing?)");
    if (seen !== total) throw Object.assign(parseError(`indexer returned ${seen} of ${total} vulnerability records`), { mismatch: true });
    const records = [...byKey.values()];
    const agents = new Map();
    for (const r of records) agents.set(r.agentId, (agents.get(r.agentId) ?? 0) + 1);
    return { records, total, duplicates: total - records.length, agents };
  }

  return {
    version: "4.14",
    // The index changes while it is read (agents rescan), so one count
    // mismatch is retried before the run is failed.
    async vulnerabilities() {
      try { return await readAll(); }
      catch (error) {
        if (!error.mismatch) throw error;
        return readAll();
      }
    }
  };
}
