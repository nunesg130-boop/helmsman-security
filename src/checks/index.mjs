import { result } from "../states.mjs";
import { agentConnected, agentPresent } from "./agent.mjs";
import { osEol, softwareEol } from "./eol.mjs";
import { diskHealth } from "./disk.mjs";
import { backupJobs, backupStorage } from "./backup.mjs";
import { clockDrift } from "./clock.mjs";
import { pendingReboot } from "./reboot.mjs";
import { windowsFailedUpdates } from "./windows.mjs";

// Devices with no collector yet (router, switches) still appear, as unknown.
export const collectorCoverage = {
  id: "collector_coverage",
  title: "Device is being monitored",
  requires: [],
  appliesTo: (asset) => asset.class === "network",
  evaluate: () => result("unknown", "no collector for this device yet (phase 2)")
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
  collectorCoverage
]);
