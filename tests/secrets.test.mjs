import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSecretBox, CredentialStore, loadMasterKey } from "../src/secrets.mjs";
import { openDb } from "../src/db.mjs";

test("seal/open round-trip with a random IV", () => {
  const box = createSecretBox(randomBytes(32));
  const a = box.seal("hunter2");
  assert.match(a, /^v1\.[\w-]+\.[\w-]+\.[\w-]+$/u);
  assert.notEqual(a, box.seal("hunter2"));
  assert.equal(box.open(a), "hunter2");
});

test("tampered ciphertext throws", () => {
  const box = createSecretBox(randomBytes(32));
  const s = box.seal("x").split(".");
  s[3] = Buffer.from("tampered").toString("base64url");
  assert.throws(() => box.open(s.join(".")));
});

test("wrong key length is refused", () => assert.throws(() => createSecretBox(randomBytes(16)), TypeError));

test("credential store only accepts known names and never stores plaintext", () => {
  const db = openDb(":memory:");
  const creds = new CredentialStore(db, "t", createSecretBox(randomBytes(32)));
  creds.set("wazuh.password", "pw-123", 1);
  assert.equal(creds.get("wazuh.password"), "pw-123");
  assert.equal(creds.has("proxmox.tokenSecret"), false);
  assert.throws(() => creds.set("root.password", "x", 1), TypeError);
  assert.ok(!JSON.stringify(db.prepare("SELECT * FROM credentials").all()).includes("pw-123"));
  assert.deepEqual(creds.list().map((c) => c.name), ["wazuh.password"]);
});

test("master key: hex file with 0600 accepted, world-readable refused", () => {
  const dir = mkdtempSync(join(tmpdir(), "hs-key-"));
  const file = join(dir, "master.key");
  writeFileSync(file, `${randomBytes(32).toString("hex")}\n`);
  chmodSync(file, 0o600);
  assert.equal(loadMasterKey(file).length, 32);
  chmodSync(file, 0o644);
  assert.throws(() => loadMasterKey(file), /readable/u);
});
