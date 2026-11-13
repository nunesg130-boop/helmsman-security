import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { collectEolDataset } from "../src/collectors/eol-dataset.mjs";
import { eolCycle, osEol, softwareEol } from "../src/checks/eol.mjs";
import { runCheck } from "../src/checks/runner.mjs";
import { memoryStore, putOk, noHolds } from "./helpers/stores.mjs";

const NOW = Date.parse("2026-11-12T12:00:00Z");
const fixture = (slug) => JSON.parse(readFileSync(new URL(`./fixtures/eol/${slug}.json`, import.meta.url)));
const fakeFetch = (fail = []) => async (url) => {
  const slug = url.split("/").pop();
  if (fail.includes(slug)) throw Object.assign(new Error("http 503"), { code: "http" });
  return fixture(slug);
};
const PRODUCTS = ["debian", "ubuntu", "proxmox-ve", "macos", "fedora", "docker-engine"];

async function dataset() {
  const out = await collectEolDataset({ fetchJson: fakeFetch(), products: PRODUCTS, now: () => NOW, maxAgeMs: 7 * 86400_000 });
  return out.evidence[0].value;
}

test("collector reads result.releases from the v1 API", async () => {
  const urls = [];
  const out = await collectEolDataset({ fetchJson: async (u) => { urls.push(u); return fixture(u.split("/").pop()); }, products: ["debian"], now: () => NOW, maxAgeMs: 1 });
  assert.deepEqual(urls, ["https://endoflife.date/api/v1/products/debian"]);
  const ev = out.evidence[0];
  assert.equal(ev.assetKey, "_global");
  assert.equal(ev.kind, "eol.dataset");
  assert.equal(ev.staleAfterMs, 1);
  assert.deepEqual(ev.value.products.debian[2], { name: "11", isEol: true, eolFrom: "2024-08-14" });
});

test("one failed product fails the whole run", async () => {
  await assert.rejects(collectEolDataset({ fetchJson: fakeFetch(["ubuntu"]), products: PRODUCTS, now: () => NOW, maxAgeMs: 1 }), /ubuntu/u);
});

test("eolCycle prefers major.minor, then major, and never guesses", () => {
  const r = [{ name: "24.04" }, { name: "24" }, { name: "12" }];
  assert.equal(eolCycle(r, "24.04").name, "24.04");
  assert.equal(eolCycle(r, "12.8").name, "12");
  assert.equal(eolCycle(r, "5:12.1-1~deb12").name, "12");
  assert.equal(eolCycle(r, "13.1"), null);
  assert.equal(eolCycle(r, "garbage"), null);
});

const host = { assetKey: "pve:guest:109", class: "guest", name: "docker", sources: { wazuh: { id: "003" } } };
function storeWith({ os, packages }, ds) {
  const s = memoryStore();
  const items = [];
  if (os) items.push({ assetKey: "wazuh:agent:003", kind: "wazuh.os", value: os });
  if (packages) items.push({ assetKey: "wazuh:agent:003", kind: "wazuh.packages", value: packages });
  putOk(s, "wazuh", items, NOW);
  if (ds) putOk(s, "eol", [{ assetKey: "_global", kind: "eol.dataset", value: ds, staleAfterMs: 7 * 86400_000 }], ds.fetchedAt);
  return s;
}
const run = (check, s, holds = noHolds) => runCheck(check, host, { store: s, holds, config: {}, now: NOW });
const debian = (major) => ({ platform: "debian", name: "Debian GNU/Linux", version: `${major}.8`, major: String(major), minor: "8", kernelRelease: "6.1.0" });

test("debian 11 is an issue with its EOL date", async () => {
  const r = run(osEol, storeWith({ os: debian(11) }, await dataset()));
  assert.equal(r.state, "issue");
  assert.match(r.reason, /debian 11 reached end of life on 2024-08-14/u);
});

test("debian 13 is ok", async () => assert.equal(run(osEol, storeWith({ os: debian(13) }, await dataset())).state, "ok"));

test("an eolFrom date in the past counts even if isEol was false at fetch time", async () => {
  const ds = await dataset();
  ds.products.debian[0] = { name: "13", isEol: false, eolFrom: "2026-11-01" };
  assert.equal(run(osEol, storeWith({ os: debian(13) }, ds)).state, "issue");
});

test("untracked OS is unknown", async () => {
  const r = run(osEol, storeWith({ os: { platform: "arch", name: "Arch Linux", version: "rolling", major: "", minor: "" } }, await dataset()));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /not tracked/u);
});

test("unmatched cycle is unknown", async () => {
  const r = run(osEol, storeWith({ os: debian(14) }, await dataset()));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /no EOL entry for debian 14/u);
});

test("held OS version is not an issue", async () => {
  const holds = { ...noHolds, activeHold: (a, product, version) => (product === "debian" && version === "11.8" ? { reason: "migrating next month" } : null) };
  const r = run(osEol, storeWith({ os: debian(11) }, await dataset()), holds);
  assert.equal(r.state, "ok");
  assert.match(r.reason, /held: migrating next month/u);
});

test("dataset older than eolMaxAgeDays is unknown", async () => {
  const ds = await dataset();
  ds.fetchedAt = NOW - 8 * 86400_000;
  const r = run(osEol, storeWith({ os: debian(13) }, ds));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /eol\.dataset last confirmed 8 d ago/u);
});

const pkgs = (items, scanned = true) => ({ items, scanned });

test("unscanned packages are unknown", async () => {
  const r = run(softwareEol, storeWith({ packages: pkgs([], false) }, await dataset()));
  assert.deepEqual([r.state, r.reason], ["unknown", "no inventory yet"]);
});

test("EOL docker-ce is an issue", async () => {
  const r = run(softwareEol, storeWith({ packages: pkgs([{ name: "docker-ce", version: "5:26.1.4-1~debian.12~bookworm" }]) }, await dataset()));
  assert.equal(r.state, "issue");
  assert.match(r.reason, /docker-engine 26/u);
});

test("no tracked products installed is ok", async () => {
  const r = run(softwareEol, storeWith({ packages: pkgs([{ name: "nginx", version: "1.22" }]) }, await dataset()));
  assert.deepEqual([r.state, r.reason], ["ok", "no tracked products installed"]);
});

test("all tracked packages unmatched is unknown", async () => {
  const r = run(softwareEol, storeWith({ packages: pkgs([{ name: "pve-manager", version: "10.0.1" }]) }, await dataset()));
  assert.equal(r.state, "unknown");
  assert.match(r.reason, /proxmox-ve 10/u);
});
