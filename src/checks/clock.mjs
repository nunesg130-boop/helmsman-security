import { result } from "../states.mjs";
import { threshold } from "./thresholds.mjs";

export const clockDrift = {
  id: "clock_drift",
  title: "Clock in sync",
  requires: ["pve.time"],
  appliesTo: (asset) => asset.class === "host" && Boolean(asset.sources?.pve?.node),
  evaluate({ "pve.time": ev }, { config }) {
    const off = Number(ev.value?.offsetSeconds);
    if (!Number.isFinite(off)) return result("unknown", "time not readable");
    const limit = threshold(config, "clockDriftSeconds");
    if (Math.abs(off) > limit) return result("issue", `clock off by ${Math.abs(Math.round(off))} s`);
    return result("ok", `clock within ${limit} s`);
  }
};
