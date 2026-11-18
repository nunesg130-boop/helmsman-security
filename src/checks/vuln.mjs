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

// Coverage of container images: has every image used by a running container
// on this machine been scanned, against a current database? Any image that
// wasn't is named with its reason. A machine with Docker but no read-only
// gate can't have its images listed at all, so it is unknown too.
const RUNTIMES = new Set(["docker-ce", "docker.io", "docker", "moby-engine", "containerd", "containerd.io", "podman"]);
const imageKey = (i) => i.repo ?? String(i.imageRef ?? "").split(":")[0];

export const vulnCoverageImages = {
  id: "vuln_coverage_images",
  title: "Container image scan coverage",
  requires: (asset) => (asset.sources?.docker ? ["grype.images", "grype.db"] : ["wazuh.packages"]),
  // Every machine: one without an agent can't be shown to be free of Docker.
  appliesTo: (asset, config) => Boolean(config?.images?.enabled) && HOST_CLASSES.includes(asset.class),
  notApplicableReason: (asset, config) => (config?.images?.enabled ? "no Docker on this machine" : "container image scanning not configured"),
  evaluate(inputs, { asset, holds, now }) {
    if (!asset.sources?.docker) {
      const pkgs = inputs["wazuh.packages"].value;
      if (!pkgs?.scanned) return result("unknown", "package inventory not scanned; can't tell whether Docker is installed");
      const hasRuntime = (pkgs.items ?? []).some((p) => RUNTIMES.has(String(p.name).toLowerCase()));
      return hasRuntime ? result("unknown", "Docker is installed but has no read-only gate; its images can't be listed") : result("not_applicable", "no Docker on this machine");
    }
    const { listing, images } = inputs["grype.images"].value;
    if (listing === "missing") return result("unknown", "no container list for this machine yet");
    if (listing === "stale") return result("unknown", "the container list is out of date");
    const db = inputs["grype.db"].value;
    if (!db.built) return result("unknown", db.reason ?? "the scanner hasn't reported a vulnerability database");
    if (!images.length) return result("ok", "no running containers");
    const excluded = [], open = [], scanned = [];
    for (const i of images) {
      const ex = holds?.activeExclusion?.(asset.assetKey, `image:${imageKey(i)}`, now);
      if (ex) excluded.push(`${i.container} (${ex.reason})`);
      else if (i.status === "scanned") scanned.push(i);
      else open.push(`${i.container} (${i.reason ?? i.status})`);
    }
    const tail = excluded.length ? `; excluded: ${excluded.join(", ")}` : "";
    if (open.length) return result("unknown", `not covered: ${open.join(", ")}${tail}`);
    const findings = scanned.reduce((n, i) => n + (i.findings ?? 0), 0);
    return result("ok", `${scanned.length} image${scanned.length === 1 ? "" : "s"} scanned, ${findings} finding${findings === 1 ? "" : "s"}${tail}`);
  }
};
