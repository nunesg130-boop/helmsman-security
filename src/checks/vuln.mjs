import { result } from "../states.mjs";
import { HOST_CLASSES } from "./runner.mjs";

// Coverage, not severity: has this machine's software actually been checked
// for known vulnerabilities, recently? No records is never read as "clean".
export const vulnCoverageHost = {
  id: "vuln_coverage_host",
  title: "Vulnerability scan coverage",
  requires: ["wazuh.agent", "wazuh.packages", "wazuh.vulnscan"],
  appliesTo: (asset, config) => HOST_CLASSES.includes(asset.class) && Boolean(config?.wazuh?.indexer),
  notApplicableReason: (asset) => (HOST_CLASSES.includes(asset.class) ? "vulnerability scanning not configured" : `does not apply to ${asset.class}`),
  evaluate({ "wazuh.agent": agent, "wazuh.vulnscan": scan }) {
    if (agent.value.status !== "active") return result("unknown", `agent is ${agent.value.status}; vulnerability data may be out of date`);
    const count = Number(scan.value?.count);
    if (!(count > 0)) return result("unknown", "Wazuh has no vulnerability records for this machine; can't tell 'clean' from 'not scanned'");
    return result("ok", `${count} known vulnerabilities on record`);
  }
};
