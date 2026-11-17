// Turns a Wazuh adapter's normalized data into evidence. Inventory reported
// by the manager is only as fresh as the agent's last check-in, so for an
// agent that isn't active it's dated at lastKeepAlive (not "now") and ages
// out to unknown on its own.
// Processes aren't used by any check, and hotfixes only exist on Windows;
// skipping them keeps each cycle well inside the Wazuh API's request budget.
const KINDS = [
  ["os", "wazuh.os"],
  ["packages", "wazuh.packages"],
  ["ports", "wazuh.ports"],
  ["hardware", "wazuh.hardware"]
];

export async function collectWazuh({ adapter, now = Date.now }) {
  const evidence = [];
  const warnings = [];
  const agents = [];
  for (const agent of await adapter.listAgents()) {
    const key = `wazuh:agent:${agent.id}`;
    const t = now();
    evidence.push({ assetKey: key, kind: "wazuh.agent", value: agent, collectedAt: t });
    let macs = [];
    if (agent.status !== "never_connected") {
      // Active agent: as fresh as now. Otherwise: its last check-in, unless
      // that is in the future (clock trouble), which counts as unknown age.
      const keepAlive = agent.lastKeepAlive != null && agent.lastKeepAlive <= t ? agent.lastKeepAlive : 0;
      // Not the syscollector scan time: Wazuh only rewrites it when an item
      // changes, so an unchanged package list would look stale forever.
      const baseAt = agent.status === "active" ? t : keepAlive;
      const datedAt = () => baseAt;
      try {
        // MACs first: they link the agent to its machine, so keep them even
        // if a later table fails.
        macs = (await adapter.netiface(agent.id)).macs;
        const got = {};
        for (const [method] of KINDS) got[method] = await adapter[method](agent.id);
        const kinds = [...KINDS];
        if (got.os?.platform === "windows") {
          got.hotfixes = await adapter.hotfixes(agent.id);
          kinds.push(["hotfixes", "wazuh.hotfixes"]);
        }
        for (const [method, kind] of kinds) {
          if (got[method] != null) evidence.push({ assetKey: key, kind, value: got[method], collectedAt: datedAt(method) });
        }
        // A later "nothing is listening on that port" is only sound if the
        // port list is known to be whole: every page read, count matching.
        const meta = adapter.tableMeta?.(agent.id, "ports");
        if (got.ports != null && meta && Number.isFinite(meta.total) && meta.rows === meta.total && meta.rows === got.ports.length) {
          evidence.push({ assetKey: key, kind: "wazuh.ports.meta", value: { complete: true, rows: meta.rows, total: meta.total, pages: meta.pages }, collectedAt: datedAt("ports") });
        }
      } catch (error) {
        if (error.code === "auth") throw error;
        warnings.push(`agent ${agent.id} (${agent.name}) inventory: ${error.code ?? "error"} ${error.message}`);
      }
    }
    agents.push({ id: agent.id, name: agent.name, ip: agent.ip, macs, status: agent.status });
  }
  return { evidence, warnings, inventory: { agents } };
}
