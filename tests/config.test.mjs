import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, parseConfig } from "../src/config.mjs";

const minimal = { listen: { adminAllowIp: "192.168.0.105" }, owner: { authentikUser: "owner", adminOrigin: "https://security.lan" } };

test("defaults applied", () => {
  const c = parseConfig(minimal);
  assert.equal(c.tenant, "default");
  assert.equal(c.thresholds.backupMaxAgeDays, 2);
  assert.equal(c.thresholds.collectMinutes, 15);
  assert.equal(c.listen.apiPort, 8443);
  assert.ok(c.eol.products.includes("debian"));
  assert.deepEqual(c.docker, []);
});

test("overrides merge onto defaults", () => {
  const c = parseConfig({ ...minimal, thresholds: { backupMaxAgeDays: 3 } });
  assert.equal(c.thresholds.backupMaxAgeDays, 3);
  assert.equal(c.thresholds.clockDriftSeconds, 5);
});

test("config rejects an inline secret but allows tokenId", () => {
  assert.throws(() => parseConfig({ ...minimal, wazuh: { baseUrl: "https://w", user: "u", password: "p" } }), /secret.*wazuh\.password/u);
  assert.throws(() => parseConfig({ ...minimal, proxmox: { baseUrl: "https://p", tokenId: "a@pam!b", tokenSecret: "x" } }), /proxmox\.tokenSecret/u);
  assert.equal(parseConfig({ ...minimal, proxmox: { baseUrl: "https://p:8006", tokenId: "a@pam!b", certSha256: "ab" } }).proxmox.tokenId, "a@pam!b");
});

test("admin allow IP and owner are required", () => {
  assert.throws(() => parseConfig({ owner: minimal.owner }), /adminAllowIp/u);
  assert.throws(() => parseConfig({ listen: minimal.listen }), /authentikUser/u);
});

test("wrong types are rejected", () => {
  assert.throws(() => parseConfig({ ...minimal, thresholds: { backupMaxAgeDays: "two" } }), /backupMaxAgeDays/u);
  assert.throws(() => parseConfig({ ...minimal, docker: [{ name: "d" }] }), /docker\[0\]/u);
});

test("loadConfig reads a JSON file", () => {
  const f = join(mkdtempSync(join(tmpdir(), "hs-cfg-")), "config.json");
  writeFileSync(f, JSON.stringify(minimal));
  assert.equal(loadConfig(f).owner.authentikUser, "owner");
});
