// Turns a Wazuh adapter's normalized data into evidence. Inventory reported
// by the manager is only as fresh as the agent's last check-in, so for an
// agent that isn't active it's dated at lastKeepAlive (not "now") and ages
// out to unknown on its own.
const KINDS = [
  ["os", "wazuh.os"],
  ["packages", "wazuh.packages"],
  ["hotfixes", "wazuh.hotfixes"],
  ["ports", "wazuh.ports"],
  ["processes", "wazuh.processes"],
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
      const inventoryAt = agent.status === "active" ? t : Math.min(t, agent.lastKeepAlive ?? 0);
      try {
        const got = {};
        for (const [method] of KINDS) got[method] = await adapter[method](agent.id);
        macs = (await adapter.netiface(agent.id)).macs;
        for (const [method, kind] of KINDS) {
          if (got[method] != null) evidence.push({ assetKey: key, kind, value: got[method], collectedAt: inventoryAt });
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
