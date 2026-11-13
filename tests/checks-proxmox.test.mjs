import test from "node:test";
import assert from "node:assert/strict";
import { diskHealth } from "../src/checks/disk.mjs";
import { backupJobs, backupStorage } from "../src/checks/backup.mjs";
import { clockDrift } from "../src/checks/clock.mjs";
import { runCheck } from "../src/checks/runner.mjs";
import { memoryStore, putOk, noHolds } from "./helpers/stores.mjs";

const NOW = 100 * 86400_000;
const DAY = 86400_000;
const node = { assetKey: "pve:node:norco", class: "host", name: "norco", sources: { pve: { node: "norco" } } };
const guest = { assetKey: "pve:guest:109", class: "guest", name: "docker", sources: { pve: { vmid: 109 } } };
const CONFIG = { thresholds: { ssdLifeRemainingPct: 10, backupMaxAgeDays: 2, storageFillPct: 85, clockDriftSeconds: 5 }, proxmox: { backupStorage: "backups" } };
function run(check, asset, kind, value, config = CONFIG) {
  const s = memoryStore();
  putOk(s, "proxmox", [{ assetKey: asset.assetKey, kind, value }], NOW);
  return runCheck(check, asset, { store: s, holds: noHolds, config, now: NOW });
}
const disk = (devpath, health, wearout = "N/A", type = wearout === "N/A" ? "hdd" : "ssd") => ({ devpath, model: "X", health, wearout, type });

test("all disks PASSED is ok", () => assert.equal(run(diskHealth, node, "pve.disks", [disk("/dev/sda", "PASSED", 90), disk("/dev/sdb", "OK")]).state, "ok"));
test("a FAILED disk is an issue naming it", () => {
  const r = run(diskHealth, node, "pve.disks", [disk("/dev/sda", "PASSED", 90), disk("/dev/sdb", "FAILED")]);
  assert.equal(r.state, "issue");
  assert.match(r.reason, /\/dev\/sdb/u);
});
test("worn SSD at or below threshold is an issue", () => {
  const r = run(diskHealth, node, "pve.disks", [disk("/dev/nvme0n1", "PASSED", 10)]);
  assert.equal(r.state, "issue");
  assert.match(r.reason, /10% life left/u);
});
test("negative wearout (past rated life) is an issue", () => assert.equal(run(diskHealth, node, "pve.disks", [disk("/dev/sda", "PASSED", -140)]).state, "issue"));
test("disk with UNKNOWN health plus a good disk is unknown", () => {
  const r = run(diskHealth, node, "pve.disks", [disk("/dev/sda", "PASSED", 90), disk("/dev/sdc", "UNKNOWN")]);
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /\/dev\/sdc/u);
});
test("wearout N/A on a PASSED HDD is ok", () => assert.equal(run(diskHealth, node, "pve.disks", [disk("/dev/sda", "PASSED", "N/A")]).state, "ok"));
test("no disks reported is unknown", () => assert.equal(run(diskHealth, node, "pve.disks", []).state, "unknown"));

const bk = (over) => ({ coveredByJob: true, jobIds: ["daily"], newestBackupAt: NOW - DAY, lastTask: { status: "OK", endtime: NOW - DAY }, ...over });
test("recent backup is ok", () => assert.equal(run(backupJobs, guest, "pve.backups", bk({})).state, "ok"));
test("guest in no job is an issue", () => assert.match(run(backupJobs, guest, "pve.backups", bk({ coveredByJob: false })).reason, /not in any enabled backup job/u));
test("no backup file is an issue", () => assert.match(run(backupJobs, guest, "pve.backups", bk({ newestBackupAt: null })).reason, /no backup found/u));
test("old backup is an issue", () => assert.match(run(backupJobs, guest, "pve.backups", bk({ newestBackupAt: NOW - 3 * DAY })).reason, /last backup 3 d ago/u));
test("failed last task is an issue", () => assert.match(run(backupJobs, guest, "pve.backups", bk({ lastTask: { status: "job errors", endtime: NOW } })).reason, /last backup task: job errors/u));
test("backup_jobs does not apply to nodes", () => assert.equal(run(backupJobs, node, "pve.backups", bk({})).state, "not_applicable"));

const st = (over) => [{ storage: "backups", active: 1, enabled: 1, used: 100, total: 1000, shared: 1, ...over }];
test("healthy backup storage is ok", () => assert.equal(run(backupStorage, node, "pve.storage", st({})).state, "ok"));
test("storage missing on a node is an issue", () => assert.match(run(backupStorage, node, "pve.storage", [{ storage: "local", active: 1, enabled: 1, used: 1, total: 2 }]).reason, /missing/u));
test("inactive storage is an issue", () => assert.equal(run(backupStorage, node, "pve.storage", st({ active: 0 })).state, "issue"));
test("full storage is an issue", () => assert.match(run(backupStorage, node, "pve.storage", st({ used: 900 })).reason, /90% full/u));
test("size not reported is unknown", () => assert.equal(run(backupStorage, node, "pve.storage", st({ total: 0 })).state, "unknown"));
test("backup_storage does not apply without configured storage", () => assert.equal(run(backupStorage, node, "pve.storage", st({}), { thresholds: CONFIG.thresholds, proxmox: {} }).state, "not_applicable"));

test("small clock offset is ok", () => assert.equal(run(clockDrift, node, "pve.time", { offsetSeconds: 2 }).state, "ok"));
test("large clock offset is an issue", () => assert.match(run(clockDrift, node, "pve.time", { offsetSeconds: -9 }).reason, /clock off by 9 s/u));
