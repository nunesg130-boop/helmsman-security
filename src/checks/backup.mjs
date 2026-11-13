import { result } from "../states.mjs";
import { formatAge } from "./runner.mjs";
import { threshold } from "./thresholds.mjs";

export const backupJobs = {
  id: "backup_jobs",
  title: "Guest backed up recently",
  requires: ["pve.backups"],
  appliesTo: (asset) => asset.class === "guest" || (asset.class === "appliance" && Boolean(asset.sources?.pve?.vmid)),
  evaluate({ "pve.backups": ev }, { config, now }) {
    const b = ev.value;
    const problems = [];
    if (b.coveredByJob === false) problems.push("not in any enabled backup job");
    if (b.newestBackupAt == null) problems.push("no backup found on backup storage");
    else if (now - b.newestBackupAt > threshold(config, "backupMaxAgeDays") * 86400_000) problems.push(`last backup ${formatAge(now - b.newestBackupAt)} ago`);
    if (b.lastTask && String(b.lastTask.status).toUpperCase() !== "OK") problems.push(`last backup task: ${b.lastTask.status}`);
    if (problems.length) return result("issue", problems.join("; "));
    return result("ok", `last backup ${formatAge(now - b.newestBackupAt)} ago`);
  }
};

export const backupStorage = {
  id: "backup_storage",
  title: "Backup storage available",
  requires: ["pve.storage"],
  appliesTo: (asset, config) => asset.class === "host" && Boolean(asset.sources?.pve?.node) && Boolean(config?.proxmox?.backupStorage),
  notApplicableReason: () => "no backup storage configured",
  evaluate({ "pve.storage": ev }, { config }) {
    const id = config.proxmox.backupStorage;
    const s = (Array.isArray(ev.value) ? ev.value : []).find((x) => x.storage === id);
    if (!s) return result("issue", `backup storage ${id} missing on this node`);
    if (Number(s.enabled) === 0) return result("issue", `backup storage ${id} disabled`);
    if (Number(s.active) !== 1) return result("issue", `backup storage ${id} offline`);
    if (!(Number(s.total) > 0)) return result("unknown", `backup storage ${id} size not reported`);
    const pct = Math.round((Number(s.used) / Number(s.total)) * 100);
    if (pct >= threshold(config, "storageFillPct")) return result("issue", `backup storage ${id} ${pct}% full`);
    return result("ok", `backup storage ${id} online, ${pct}% full`);
  }
};
