import { result } from "../states.mjs";
import { formatAge, HOST_CLASSES } from "./runner.mjs";

export const agentConnected = {
  id: "agent_connected",
  title: "Wazuh agent connected",
  requires: ["wazuh.agent"],
  appliesTo: (asset) => HOST_CLASSES.includes(asset.class),
  evaluate({ "wazuh.agent": ev }, { asset, now }) {
    const { status, lastKeepAlive } = ev.value;
    if (status === "active") return result("ok", "agent connected");
    if (asset.class === "roaming") {
      const since = lastKeepAlive ? new Date(lastKeepAlive).toISOString() : "never";
      return result("unknown", `away since ${since}`, [], { roaming: true });
    }
    const seen = lastKeepAlive ? `last seen ${formatAge(now - lastKeepAlive)} ago` : "never seen";
    return result("issue", `agent ${status}, ${seen}`);
  }
};

export const agentPresent = {
  id: "agent_present",
  title: "Wazuh agent installed",
  // Judged against the inventories it was linked from, so it can't stay
  // "ok" once those stop being refreshed.
  requires: (asset) => [...(asset.sources?.pve ? ["inventory.proxmox"] : []), "inventory.wazuh"],
  appliesTo: (asset) => ["host", "guest"].includes(asset.class),
  notApplicableReason: (asset) => (asset.class === "appliance" ? "no agent possible" : null),
  evaluate(_inputs, { asset }) {
    return asset.sources?.wazuh ? result("ok", "agent installed") : result("issue", "no Wazuh agent installed");
  }
};
