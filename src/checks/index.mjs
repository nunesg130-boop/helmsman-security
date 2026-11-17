import { result } from "../states.mjs";
import { agentConnected, agentPresent } from "./agent.mjs";
import { osEol, softwareEol } from "./eol.mjs";
import { diskHealth } from "./disk.mjs";
import { backupJobs, backupStorage } from "./backup.mjs";
import { clockDrift } from "./clock.mjs";
import { pendingReboot } from "./reboot.mjs";
import { windowsFailedUpdates } from "./windows.mjs";
import { vulnCoverageHost } from "./vuln.mjs";
import { exposureRoutes, exposureGates, exposureExpectedPrivate } from "./exposure.mjs";

// Devices with no collector yet (router, switches) still appear, as unknown.
// What the owner declared about the router is repeated here, labelled as such.
export const collectorCoverage = {
  id: "collector_coverage",
  title: "Device is being monitored",
  requires: [],
  appliesTo: (asset) => asset.class === "network",
  evaluate: (_inputs, { asset, config } = {}) => {
    const base = "no collector for this device yet (phase 2)";
    const entry = (config?.network ?? []).find((n) => `net:${n.name}` === asset?.assetKey);
    if (!entry) return result("unknown", base);
    const onOff = (v) => (v ? "on" : "off");
    const facts = [
      ["port forwards", Array.isArray(entry.portForwards) ? `${entry.portForwards.length} port forward${entry.portForwards.length === 1 ? "" : "s"}` : null],
      ["UPnP", typeof entry.upnp === "boolean" ? `UPnP ${onOff(entry.upnp)}` : null],
      ["DMZ", entry.dmz == null ? null : typeof entry.dmz === "string" ? `DMZ to ${entry.dmz}` : `DMZ ${onOff(entry.dmz)}`],
      ["inbound IPv6", typeof entry.ipv6Inbound === "boolean" ? `inbound IPv6 ${onOff(entry.ipv6Inbound)}` : null]
    ];
    const declared = facts.filter(([, text]) => text).map(([, text]) => text);
    if (!declared.length) return result("unknown", base);
    const missing = facts.filter(([, text]) => !text).map(([name]) => name);
    return result("unknown", `${base}; declared, not verified: ${declared.join(", ")}${missing.length ? `; not declared: ${missing.join(", ")}` : ""}`);
  }
};

export const CHECKS = Object.freeze([
  agentConnected,
  agentPresent,
  osEol,
  softwareEol,
  diskHealth,
  backupJobs,
  backupStorage,
  clockDrift,
  pendingReboot,
  windowsFailedUpdates,
  vulnCoverageHost,
  exposureRoutes,
  exposureGates,
  exposureExpectedPrivate,
  collectorCoverage
]);
