import { runCollector } from "../collect.mjs";
import { INVENTORY_KEY } from "../checks/runner.mjs";
import { threshold } from "../checks/thresholds.mjs";

export const VULN_COLLECTOR = "wazuh-vulns";
const DEADLINE_MS = 10 * 60_000;

// One vulnerability cycle: read every record from the Wazuh indexer (all or
// nothing), file each under its machine, and record per-agent scan evidence
// for the coverage check. A failed or interrupted read changes nothing.
export async function vulnCycle({ db, tenantId, store, findings, indexer, config, now = Date.now, secrets = [] }) {
  const staleAfterMs = threshold(config, "vulnsRefreshMinutes") * threshold(config, "staleFactor") * 60_000;
  return runCollector(store, VULN_COLLECTOR, async () => {
    const { records, total, agents } = await indexer.vulnerabilities();

    const assetByAgent = new Map();
    for (const row of db.prepare("SELECT asset_key, sources_json FROM assets WHERE tenant_id = ?").all(tenantId)) {
      const id = JSON.parse(row.sources_json)?.wazuh?.id;
      // A machine's own asset wins over a stand-alone agent asset.
      if (id && (!assetByAgent.has(String(id)) || !row.asset_key.startsWith("wazuh:agent:"))) assetByAgent.set(String(id), row.asset_key);
    }
    const keyFor = (agentId) => assetByAgent.get(agentId) ?? `wazuh:agent:${agentId}`;
    findings.replaceSource("wazuh", records.map((r) => ({ ...r, assetKey: keyFor(r.agentId) })), now());

    const newest = new Map();
    for (const r of records) if (r.detectedAt != null && r.detectedAt > (newest.get(r.agentId) ?? -Infinity)) newest.set(r.agentId, r.detectedAt);
    const known = (store.get(INVENTORY_KEY, "inventory.wazuh")?.value?.agents ?? []).map((a) => String(a.id));
    const ids = [...new Set([...known, ...agents.keys()])].sort();
    const evidence = ids.map((id) => ({
      assetKey: `wazuh:agent:${id}`, kind: "wazuh.vulnscan", source: VULN_COLLECTOR,
      value: { count: agents.get(id) ?? 0, newestDetectedAt: newest.get(id) ?? null }
    }));
    evidence.push({ assetKey: INVENTORY_KEY, kind: `inventory.${VULN_COLLECTOR}`, source: VULN_COLLECTOR, value: { agents: [...agents.keys()].sort(), total } });
    return { evidence, warnings: [] };
  }, { now, staleAfterMs, secrets, deadlineMs: DEADLINE_MS });
}
