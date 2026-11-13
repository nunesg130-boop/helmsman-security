import { result } from "../states.mjs";
import { HOST_CLASSES } from "./runner.mjs";

export const OS_PRODUCT = Object.freeze({ debian: "debian", ubuntu: "ubuntu", fedora: "fedora", darwin: "macos", macos: "macos" });
export const DEFAULT_SOFTWARE = Object.freeze([
  { product: "docker-engine", packages: ["docker-ce"] },
  { product: "proxmox-ve", packages: ["pve-manager"] }
]);

function versionParts(version) {
  const s = String(version ?? "").replace(/^\d+:/u, "");
  const m = s.match(/^(\d+)(?:\.(\d+))?/u);
  if (!m) return [];
  return m[2] !== undefined ? [`${m[1]}.${m[2]}`, m[1]] : [m[1]];
}

// Exact major.minor, then exact major. Never the "closest" release.
export function eolCycle(releases, version) {
  for (const candidate of versionParts(version)) {
    const hit = releases.find((r) => r.name === candidate);
    if (hit) return hit;
  }
  return null;
}

function isPastEol(release, now) {
  return release.isEol === true || (typeof release.eolFrom === "string" && Date.parse(release.eolFrom) <= now);
}

export const osEol = {
  id: "os_eol",
  title: "Operating system still supported",
  requires: ["wazuh.os", "eol.dataset"],
  appliesTo: (asset) => HOST_CLASSES.includes(asset.class),
  evaluate({ "wazuh.os": os, "eol.dataset": ds }, { asset, holds, now }) {
    const product = OS_PRODUCT[String(os.value.platform ?? "").toLowerCase()];
    if (!product) return result("unknown", `OS ${os.value.name ?? os.value.platform ?? "?"} not tracked by endoflife.date`);
    const releases = ds.value.products[product];
    if (!releases) return result("unknown", `EOL data for ${product} not downloaded`);
    const version = os.value.minor ? `${os.value.major}.${os.value.minor}` : String(os.value.major ?? os.value.version ?? "");
    const cycle = eolCycle(releases, version);
    if (!cycle) return result("unknown", `no EOL entry for ${product} ${version}`);
    if (!isPastEol(cycle, now)) return result("ok", `${product} ${cycle.name} supported${cycle.eolFrom ? ` until ${cycle.eolFrom}` : ""}`);
    const hold = holds?.activeHold?.(asset.assetKey, product, version, now);
    if (hold) return result("ok", `${product} ${cycle.name} past end of life, held: ${hold.reason}`);
    return result("issue", `${product} ${cycle.name} reached end of life on ${cycle.eolFrom ?? "an unpublished date"}`);
  }
};

export const softwareEol = {
  id: "software_eol",
  title: "Tracked software still supported",
  requires: ["wazuh.packages", "eol.dataset"],
  appliesTo: (asset) => HOST_CLASSES.includes(asset.class),
  evaluate({ "wazuh.packages": pk, "eol.dataset": ds }, { asset, holds, config, now }) {
    if (pk.value.scanned === false) return result("unknown", "no inventory yet");
    const tracked = config?.eol?.software ?? DEFAULT_SOFTWARE;
    const eol = [];
    const unmatched = [];
    let present = 0;
    for (const { product, packages } of tracked) {
      for (const p of pk.value.items ?? []) {
        if (!packages.includes(p.name)) continue;
        present += 1;
        const releases = ds.value.products[product];
        const cycle = releases ? eolCycle(releases, p.version) : null;
        if (!cycle) { unmatched.push(`${product} ${versionParts(p.version)[0] ?? p.version}`); continue; }
        if (isPastEol(cycle, now) && !holds?.activeHold?.(asset.assetKey, product, p.version, now)) {
          eol.push(`${product} ${cycle.name} (${p.name} ${p.version}) reached end of life on ${cycle.eolFrom ?? "an unpublished date"}`);
        }
      }
    }
    const note = unmatched.length ? `; no EOL entry for ${unmatched.join(", ")}` : "";
    if (eol.length) return result("issue", `${eol.join("; ")}${note}`);
    if (present === 0) return result("ok", "no tracked products installed");
    if (unmatched.length === present) return result("unknown", `no EOL entry for ${unmatched.join(", ")}`);
    return result("ok", `tracked products supported${note}`);
  }
};
