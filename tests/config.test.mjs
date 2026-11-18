import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, parseConfig, egressHosts } from "../src/config.mjs";

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

test("proxmox.backupStorage accepts a per-node map of storage names", () => {
  const c = parseConfig({ ...minimal, proxmox: { baseUrl: "https://10.0.0.1:8006", tokenId: "a@pve!b", backupStorage: { norco: "x", Main: "y" } } });
  assert.deepEqual(c.proxmox.backupStorage, { norco: "x", Main: "y" });
});
test("proxmox.backupStorage rejects a map with a non-string value", () => {
  assert.throws(() => parseConfig({ ...minimal, proxmox: { baseUrl: "https://10.0.0.1:8006", tokenId: "a@pve!b", backupStorage: { norco: 3 } } }), /backupStorage/u);
});

test("wazuh.requestsPerMinute must be a positive number", () => {
  const w = { baseUrl: "https://10.0.0.2:55000", user: "u" };
  assert.equal(parseConfig({ ...minimal, wazuh: { ...w, requestsPerMinute: 60 } }).wazuh.requestsPerMinute, 60);
  assert.throws(() => parseConfig({ ...minimal, wazuh: { ...w, requestsPerMinute: 0 } }), /requestsPerMinute/u);
});

const WZ = { baseUrl: "https://10.0.0.2:55000", user: "u" };
test("wazuh.indexer needs baseUrl and user", () => {
  assert.throws(() => parseConfig({ ...minimal, wazuh: { ...WZ, indexer: { baseUrl: "https://10.0.0.2:9200" } } }), /indexer/u);
  assert.equal(parseConfig({ ...minimal, wazuh: { ...WZ, indexer: { baseUrl: "https://10.0.0.2:9200", user: "ro", certSha256: "ab".repeat(32) } } }).wazuh.indexer.user, "ro");
});
test("egress includes the indexer and feed hosts only when an indexer is configured", () => {
  assert.ok(!egressHosts(parseConfig({ ...minimal, wazuh: WZ })).allowHosts.includes("www.cisa.gov"));
  const hosts = egressHosts(parseConfig({ ...minimal, wazuh: { ...WZ, indexer: { baseUrl: "https://10.0.0.9:9200", user: "ro", certSha256: "ab".repeat(32) } } })).allowHosts;
  for (const h of ["10.0.0.9", "www.cisa.gov", "epss.empiricalsecurity.com"]) assert.ok(hosts.includes(h), h);
});
test("defaults include the vulnerability thresholds", () => {
  const t = parseConfig(minimal).thresholds;
  assert.deepEqual([t.vulnsRefreshMinutes, t.threatFeedRefreshHours, t.threatFeedMaxAgeDays], [60, 24, 7]);
});

test("the indexer must be https, pinned, and its user can't contain a colon", () => {
  const ix = { baseUrl: "https://10.0.0.9:9201", user: "ro", certSha256: "ab".repeat(32) };
  assert.equal(parseConfig({ ...minimal, wazuh: { ...WZ, indexer: ix } }).wazuh.indexer.user, "ro");
  assert.throws(() => parseConfig({ ...minimal, wazuh: { ...WZ, indexer: { ...ix, baseUrl: "http://10.0.0.9:9201" } } }), /https/u);
  assert.throws(() => parseConfig({ ...minimal, wazuh: { ...WZ, indexer: { ...ix, certSha256: undefined } } }), /certSha256/u);
  assert.throws(() => parseConfig({ ...minimal, wazuh: { ...WZ, indexer: { ...ix, user: "a:b" } } }), /colon/u);
});

// --- exposure (phase 2B) ---
const EXPO = {
  caddy: { url: "http://192.168.0.105:2020/shape.json", assetKey: "pve:guest:105", address: "192.168.0.105" },
  cloudflare: { accountId: "acc", zoneId: "zone", tunnelIds: ["t1"], assetKey: "pve:guest:107", connectorAddress: "192.168.0.108" },
  expectedPrivate: ["paperless.jellofin.com"]
};
const NET = [{ name: "er605", portForwards: [{ wanPort: 443, lanIp: "192.168.0.105", lanPort: 443, protocol: "tcp" }], upnp: false, dmz: false, ipv6Inbound: false }];

test("exposure config parses with defaults", () => {
  const c = parseConfig({ ...minimal, exposure: EXPO, network: NET });
  assert.equal(c.exposure.caddy.maxAgeMinutes, 30);
  assert.deepEqual(c.exposure.caddy.trustedClientIpHeaders, ["Cf-Connecting-Ip"]);
  assert.deepEqual(c.exposure.expectedPrivate, ["paperless.jellofin.com"]);
  assert.equal(c.network[0].portForwards[0].lanIp, "192.168.0.105");
  assert.equal(parseConfig(minimal).exposure, null);
});
test("exposure config is validated", () => {
  const bad = (exposure, re, network = NET) => assert.throws(() => parseConfig({ ...minimal, exposure, network }), re);
  bad({ ...EXPO, caddy: { ...EXPO.caddy, url: "ftp://x/shape.json" } }, /exposure\.caddy\.url/u);
  bad({ ...EXPO, caddy: { ...EXPO.caddy, address: "caddy" } }, /exposure\.caddy\.address/u);
  bad({ ...EXPO, caddy: { ...EXPO.caddy, assetKey: "" } }, /assetKey/u);
  bad({ ...EXPO, cloudflare: { ...EXPO.cloudflare, tunnelIds: [] } }, /tunnelIds/u);
  bad({ ...EXPO, cloudflare: { ...EXPO.cloudflare, connectorAddress: "x" } }, /connectorAddress/u);
  bad({ ...EXPO, expectedPrivate: "paperless" }, /expectedPrivate/u);
  bad(EXPO, /portForwards/u, [{ name: "r", portForwards: [{ wanPort: 70000, lanIp: "192.168.0.105", lanPort: 443, protocol: "tcp" }] }]);
  bad(EXPO, /portForwards/u, [{ name: "r", portForwards: [{ wanPort: 443, lanIp: "nope", lanPort: 443, protocol: "tcp" }] }]);
  bad(EXPO, /portForwards/u, [{ name: "r", portForwards: [{ wanPort: 443, lanIp: "192.168.0.105", lanPort: 443, protocol: "icmp" }] }]);
  bad(EXPO, /upnp/u, [{ name: "r", upnp: "off" }]);
  bad(EXPO, /dmz/u, [{ name: "r", dmz: "somewhere" }]);
});
test("egress adds the Caddy host (http) and Cloudflare's API only when configured", () => {
  const none = egressHosts(parseConfig(minimal));
  assert.ok(!none.allowHosts.includes("api.cloudflare.com") && !none.allowHttpHosts.includes("192.168.0.105"));
  const some = egressHosts(parseConfig({ ...minimal, exposure: EXPO }));
  assert.ok(some.allowHosts.includes("api.cloudflare.com") && some.allowHttpHosts.includes("192.168.0.105"));
  const caddyOnly = egressHosts(parseConfig({ ...minimal, exposure: { caddy: EXPO.caddy } }));
  assert.ok(!caddyOnly.allowHosts.includes("api.cloudflare.com"));
});
test("exposure.cloudflare.connectors maps listed tunnels to IPv4 addresses", async () => {
  const { parseConfig: parse } = await import("../src/config.mjs");
  const base = { listen: { adminAllowIp: "192.168.0.105" }, owner: { authentikUser: "o" } };
  const cf = { accountId: "a", zoneId: "z", assetKey: "pve:guest:151", connectorAddress: "192.168.0.151", tunnelIds: ["t1", "t2"] };
  assert.deepEqual(parse({ ...base, exposure: { cloudflare: { ...cf, connectors: { t2: "192.168.0.197" } } } }).exposure.cloudflare.connectors, { t2: "192.168.0.197" });
  assert.throws(() => parse({ ...base, exposure: { cloudflare: { ...cf, connectors: { t2: "nope" } } } }), /connectors/u);
  assert.throws(() => parse({ ...base, exposure: { cloudflare: { ...cf, connectors: { t9: "192.168.0.9" } } } }), /connectors/u);
});
