import { result } from "../states.mjs";
import { threshold } from "./thresholds.mjs";

// Proxmox reports `wearout` as % life REMAINING: PVE/Diskmanage.pm stores
// `100 - Percentage Used` (NVMe/SAS) or the inverted "Used" attribute, and
// notes "wearout is really the 'life left' value". It can go negative once
// a drive passes its rated endurance.
const GOOD = new Set(["PASSED", "OK"]);

export const diskHealth = {
  id: "disk_health",
  title: "Disk health (SMART)",
  requires: ["pve.disks"],
  appliesTo: (asset) => asset.class === "host" && Boolean(asset.sources?.pve?.node),
  evaluate({ "pve.disks": ev }, { config }) {
    const disks = Array.isArray(ev.value) ? ev.value : [];
    if (!disks.length) return result("unknown", "no disks reported");
    const minLife = threshold(config, "ssdLifeRemainingPct");
    const bad = [];
    const unknown = [];
    for (const d of disks) {
      const health = String(d.health ?? "").toUpperCase();
      if (!health || health === "UNKNOWN") unknown.push(`${d.devpath}: SMART health not reported`);
      else if (!GOOD.has(health)) bad.push(`${d.devpath}: SMART ${d.health}`);
      if (typeof d.wearout === "number" && d.wearout <= minLife) bad.push(`${d.devpath}: ${d.wearout}% life left`);
    }
    if (bad.length) return result("issue", bad.join("; "));
    if (unknown.length) return result("unknown", unknown.join("; "));
    return result("ok", `${disks.length} disk${disks.length === 1 ? "" : "s"} healthy`);
  }
};
