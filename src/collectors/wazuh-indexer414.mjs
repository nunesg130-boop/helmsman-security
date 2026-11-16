import { createPacer } from "./pacing.mjs";
import { fixStateFromCondition, normaliseSeverity, isLowConfidence } from "../vuln/classify.mjs";

// Wazuh 4.14 keeps vulnerability state in its indexer (OpenSearch), not in
// the server API. This adapter reads it with a search-only user. Contract
// (a Wazuh 5.x adapter must match it):
//   vulnerabilities() -> { records, total, agents: Map<agentId, count> }
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

export function createWazuhIndexer414({ http, baseUrl, user, password, certSha256, requestsPerMinute = 60, pageSize = 1000, sleep, now }) {
  const url = `${baseUrl.replace(/\/+$/u, "")}/${INDEX}/_search`;
  const headers = { authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}` };
  const paced = createPacer({ requestsPerMinute, sleep, now });

  return {
    version: "4.14",
    async vulnerabilities() {
      const records = [];
      const agents = new Map();
      let total = null;
      let after;
      for (;;) {
        const body = { size: pageSize, track_total_hits: true, _source: FIELDS, sort: SORT, query: { match_all: {} }, ...(after ? { search_after: after } : {}) };
        const res = await paced(() => http.fetchJson(url, { certSha256, headers, body, timeoutMs: 30_000, maxBytes: 20_000_000 }));
        const hits = res?.hits?.hits;
        if (!Array.isArray(hits) || !Number.isFinite(res.hits.total?.value)) throw parseError("unexpected response from the indexer");
        total = res.hits.total.value;
        if (hits.length === 0) break;
        for (const h of hits) {
          const r = normalise(h._source);
          records.push(r);
          agents.set(r.agentId, (agents.get(r.agentId) ?? 0) + 1);
        }
        const next = hits[hits.length - 1].sort;
        if (!Array.isArray(next)) throw parseError("indexer hit without sort values");
        // More records than the indexer says exist means the same page is coming back.
        if (records.length > total) throw parseError(`indexer returned ${records.length} of ${total} vulnerability records`);
        after = next;
      }
      if (records.length !== total) throw parseError(`indexer returned ${records.length} of ${total} vulnerability records`);
      return { records, total, agents };
    }
  };
}
