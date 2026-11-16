// A stand-in for the Wazuh indexer's vulnerability search. Honours size and
// search_after over the same sort keys the adapter asks for.
export const SEARCH_PATH = "/wazuh-states-vulnerabilities-*/_search";

export function vulnDoc({ agent = "010", name = "Jellyfin", cve = "CVE-2026-68479", pkg = "linux-image-amd64", version = "6.12.74-2", arch = "amd64", severity = "High", score = 7.8,
  condition = "Package less than 6.12.100-1", source = "Debian Security Tracker", underEvaluation = false, detectedAt = "2026-11-13T21:45:37.604Z" } = {}) {
  return {
    agent: { id: agent, name, type: "Wazuh", version: "v4.14.10" },
    package: { architecture: arch, name: pkg, type: "deb", version },
    vulnerability: {
      id: cve, severity, score: { base: score, version: "3.1" }, detected_at: detectedAt, under_evaluation: underEvaluation,
      reference: `https://security-tracker.debian.org/tracker/${cve}`,
      scanner: { condition, source, vendor: "Wazuh" }
    }
  };
}

const sortKey = (d) => [d.agent?.id, d.vulnerability?.id, d.package?.name, d.package?.version, d.package?.architecture, d.package?.type].map((v) => v ?? "");
const cmp = (a, b) => { for (let i = 0; i < a.length; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; } return 0; };

export function indexerRoutes(docs, { total, mutatePage } = {}) {
  const sorted = [...docs].sort((a, b) => cmp(sortKey(a), sortKey(b)));
  return {
    [`GET ${SEARCH_PATH}`]: (req, text) => {
      const q = JSON.parse(text || "{}");
      const after = q.search_after;
      const rest = after ? sorted.filter((d) => cmp(sortKey(d), after) > 0) : sorted;
      let hits = rest.slice(0, q.size ?? 10).map((d) => ({ _source: d, sort: sortKey(d) }));
      if (mutatePage) hits = mutatePage(hits, q);
      return [200, { hits: { total: { value: total ?? sorted.length, relation: "eq" }, hits } }];
    }
  };
}
