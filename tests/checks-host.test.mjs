import test from "node:test";
import assert from "node:assert/strict";
import { newestKernel, pendingReboot } from "../src/checks/reboot.mjs";
import { windowsFailedUpdates } from "../src/checks/windows.mjs";
import { runCheck } from "../src/checks/runner.mjs";
import { memoryStore, putOk, noHolds } from "./helpers/stores.mjs";

const NOW = 1_000_000;
const asset = { assetKey: "pve:node:norco", class: "host", name: "norco", sources: { wazuh: { id: "001" } } };
function run(check, os, items) {
  const s = memoryStore();
  putOk(s, "wazuh", [
    { assetKey: "wazuh:agent:001", kind: "wazuh.os", value: os },
    { assetKey: "wazuh:agent:001", kind: "wazuh.packages", value: { items, scanned: true } }
  ], NOW);
  return runCheck(check, asset, { store: s, holds: noHolds, config: {}, now: NOW });
}
const pve = (release) => ({ platform: "debian", name: "Debian GNU/Linux", major: "12", minor: "8", kernelRelease: release });
const pkg = (name, version = "1", architecture = "amd64") => ({ name, version, architecture });

test("newestKernel ignores meta packages and picks the max", () => {
  const items = [pkg("proxmox-kernel-6.8"), pkg("proxmox-kernel-6.8.12-4-pve-signed"), pkg("proxmox-kernel-6.8.12-10-pve-signed"), pkg("pve-kernel-5.15.108-1-pve"), pkg("linux-image-amd64")];
  assert.equal(newestKernel(items, "debian"), "6.8.12-10-pve");
});

test("fedora kernel-core uses version.architecture", () => {
  const items = [pkg("kernel-core", "6.11.4-301.fc41", "x86_64"), pkg("kernel-core", "6.11.10-300.fc41", "x86_64")];
  assert.equal(newestKernel(items, "fedora"), "6.11.10-300.fc41.x86_64");
});

test("proxmox newer kernel installed is an issue", () => {
  const r = run(pendingReboot, pve("6.8.12-4-pve"), [pkg("proxmox-kernel-6.8.12-4-pve-signed"), pkg("proxmox-kernel-6.8.12-10-pve-signed")]);
  assert.equal(r.state, "issue");
  assert.equal(r.reason, "running 6.8.12-4-pve, newest installed 6.8.12-10-pve");
});

test("matching kernel is ok", () => {
  assert.equal(run(pendingReboot, pve("6.1.0-26-amd64"), [pkg("linux-image-6.1.0-26-amd64"), pkg("linux-image-6.1.0-25-amd64")]).state, "ok");
});

test("no kernel packages is unknown", () => {
  const r = run(pendingReboot, pve("6.1.0-26-amd64"), [pkg("bash")]);
  assert.deepEqual([r.state, r.reason], ["unknown", "no kernel packages in inventory"]);
});

test("missing running kernel is unknown", () => {
  assert.equal(run(pendingReboot, pve(undefined), [pkg("linux-image-6.1.0-26-amd64")]).state, "unknown");
});

test("macOS is not_applicable for pending reboot", () => {
  const r = run(pendingReboot, { platform: "darwin", name: "macOS", major: "15", minor: "1" }, []);
  assert.deepEqual([r.state, r.reason], ["not_applicable", "kernel updates not tracked on macOS"]);
});

test("windows check is not_applicable on debian", () => assert.equal(run(windowsFailedUpdates, pve("6.1.0-26-amd64"), []).state, "not_applicable"));

test("windows check is honest about phase 3 on windows", () => {
  const r = run(windowsFailedUpdates, { platform: "windows", name: "Microsoft Windows 11 Pro", major: "10", minor: "0" }, []);
  assert.deepEqual([r.state, r.reason], ["unknown", "failed-update events are collected from phase 3"]);
});
