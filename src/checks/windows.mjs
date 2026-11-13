import { result } from "../states.mjs";

// Failed Windows Update events come from the event log, which is collected
// in phase 3. Until then this check is honest about not knowing.
export const windowsFailedUpdates = {
  id: "windows_failed_updates",
  title: "Windows updates installing",
  requires: ["wazuh.os"],
  appliesTo: (asset) => ["host", "guest", "roaming"].includes(asset.class) && Boolean(asset.sources?.wazuh),
  evaluate({ "wazuh.os": os }) {
    if (String(os.value.platform ?? "").toLowerCase() !== "windows") return result("not_applicable", "not a Windows host");
    return result("unknown", "failed-update events are collected from phase 3");
  }
};
