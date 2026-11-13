import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDb } from "../src/db.mjs";
import { EvidenceStore } from "../src/evidence.mjs";
import { start } from "../src/main.mjs";

function setupDir() {
  const dir = mkdtempSync(join(tmpdir(), "hs-main-"));
  const config = join(dir, "config.json");
  writeFileSync(config, JSON.stringify({
    listen: { apiHost: "127.0.0.1", apiPort: 0, adminHost: "127.0.0.1", adminPort: 0, adminAllowIp: "127.0.0.1" },
    owner: { authentikUser: "owner", adminOrigin: "https://security.lan" },
    eol: { products: [] }
  }));
  const key = join(dir, "master.key");
  writeFileSync(key, randomBytes(32).toString("hex"));
  chmodSync(key, 0o600);
  mkdirSync(join(dir, "tls"));
  copyFileSync(new URL("./fixtures/tls/key.pem", import.meta.url), join(dir, "tls", "key.pem"));
  copyFileSync(new URL("./fixtures/tls/cert.pem", import.meta.url), join(dir, "tls", "cert.pem"));
  return { dir, config, key };
}

test("main recovers an interrupted run on start and prints a new API token once", async () => {
  const { dir, config, key } = setupDir();
  const s = new EvidenceStore(openDb(join(dir, "engine.db")), "default");
  s.beginRun("proxmox", 1);
  const logs = [];
  const engine = await start({ configPath: config, keyPath: key, dataDir: dir, log: (m) => logs.push(m) });
  try {
    assert.ok(logs.some((l) => /1 interrupted run/u.test(l)), logs.join("\n"));
    assert.ok(logs.some((l) => /Helmsman API token/u.test(l)));
    assert.ok(logs.some((l) => /fingerprint/u.test(l)));
    assert.equal(engine.store.lastRun("proxmox").status, "failed");
  } finally { await engine.stop(); }

  const logs2 = [];
  const again = await start({ configPath: config, keyPath: key, dataDir: dir, log: (m) => logs2.push(m) });
  try { assert.ok(!logs2.some((l) => /Helmsman API token/u.test(l)), "token printed only on first start"); }
  finally { await again.stop(); }
});

test("a configured collector without its credential fails visibly", async () => {
  const { dir, key } = setupDir();
  const config = join(dir, "config2.json");
  writeFileSync(config, JSON.stringify({
    listen: { apiHost: "127.0.0.1", apiPort: 0, adminHost: "127.0.0.1", adminPort: 0, adminAllowIp: "127.0.0.1" },
    owner: { authentikUser: "owner", adminOrigin: "https://x" },
    proxmox: { baseUrl: "https://127.0.0.1:1", tokenId: "a@pam!b", certSha256: "00" },
    eol: { products: [] }
  }));
  const engine = await start({ configPath: config, keyPath: key, dataDir: dir, log: () => {}, schedule: false });
  try {
    await engine.collect();
    const r = engine.store.lastRun("proxmox");
    assert.equal(r.status, "failed");
    assert.match(r.error, /proxmox\.tokenSecret is not set/u);
  } finally { await engine.stop(); }
});
