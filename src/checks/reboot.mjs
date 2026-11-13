import { result } from "../states.mjs";
import { compareVersions } from "../version.mjs";
import { HOST_CLASSES } from "./runner.mjs";

// Debian/Proxmox kernel packages carry the full release in the name, e.g.
// proxmox-kernel-6.8.12-4-pve-signed, pve-kernel-5.15.108-1-pve,
// linux-image-6.1.0-26-amd64. Meta packages (proxmox-kernel-6.8,
// linux-image-amd64) don't match because they lack the x.y.z-n release.
const DEB_KERNEL = /^(?:linux-image|proxmox-kernel|pve-kernel)-(\d+\.\d+\.\d+-[\w.+-]+?)(?:-signed)?$/u;

export function newestKernel(packages, platform) {
  const releases = [];
  for (const p of packages ?? []) {
    if (platform === "fedora") {
      if (p.name === "kernel-core" && p.version) releases.push(p.architecture ? `${p.version}.${p.architecture}` : p.version);
    } else {
      const m = DEB_KERNEL.exec(p.name ?? "");
      if (m) releases.push(m[1]);
    }
  }
  if (!releases.length) return null;
  return releases.reduce((a, b) => (compareVersions(a, b) >= 0 ? a : b));
}

export const pendingReboot = {
  id: "pending_reboot",
  title: "No reboot pending",
  requires: ["wazuh.os", "wazuh.packages"],
  appliesTo: (asset) => HOST_CLASSES.includes(asset.class) && asset.sources?.pve?.type !== "lxc",
  notApplicableReason: (asset) => (asset.sources?.pve?.type === "lxc" ? "containers run on the host's kernel" : null),
  evaluate({ "wazuh.os": os, "wazuh.packages": pk }) {
    const platform = String(os.value.platform ?? "").toLowerCase();
    if (platform === "darwin" || platform === "macos") return result("not_applicable", "kernel updates not tracked on macOS");
    if (platform === "windows") return result("unknown", "Windows pending-reboot state is collected from phase 3");
    if (pk.value.scanned === false) return result("unknown", "no inventory yet");
    const newest = newestKernel(pk.value.items, platform);
    if (!newest) return result("unknown", "no kernel packages in inventory");
    const running = os.value.kernelRelease;
    if (!running) return result("unknown", "running kernel not reported");
    if (newest !== running) return result("issue", `running ${running}, newest installed ${newest}`);
    return result("ok", `running newest kernel ${running}`);
  }
};
