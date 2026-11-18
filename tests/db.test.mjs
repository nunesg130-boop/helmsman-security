import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb, SCHEMA_VERSION } from "../src/db.mjs";

const tmp = () => join(mkdtempSync(join(tmpdir(), "hs-db-")), "engine.db");

test("openDb sets WAL and foreign keys", () => {
  const db = openDb(tmp());
  assert.equal(db.prepare("PRAGMA journal_mode").get().journal_mode, "wal");
  assert.equal(db.prepare("PRAGMA foreign_keys").get().foreign_keys, 1);
  db.close();
});

test("migrations are idempotent", () => {
  const file = tmp();
  openDb(file).close();
  const db = openDb(file);
  assert.equal(db.prepare("PRAGMA user_version").get().user_version, SCHEMA_VERSION);
  db.close();
});

test("every table has tenant_id", () => {
  const db = openDb(tmp());
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
  assert.ok(tables.length >= 7);
  for (const { name } of tables) {
    const cols = db.prepare(`PRAGMA table_info(${name})`).all().map((c) => c.name);
    assert.ok(cols.includes("tenant_id"), `${name} lacks tenant_id`);
  }
  db.close();
});

test("result state column rejects unknown states", () => {
  const db = openDb(tmp());
  assert.throws(() => db.prepare(
    "INSERT INTO ledger (tenant_id, asset_key, check_id, state, reason, evidence_json, evaluated_at, state_since) VALUES ('t','a','c','green','r','[]',1,1)"
  ).run());
  db.close();
});

test("a version 1 database is migrated to the current schema with its data kept", async () => {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { DatabaseSync } = await import("node:sqlite");
  const file = join(mkdtempSync(join(tmpdir(), "hs-mig-")), "engine.db");
  openDb(file).close();
  const raw = new DatabaseSync(file);
  raw.exec("DROP TABLE findings; DROP TABLE kev; DROP TABLE epss; DROP TABLE feeds; PRAGMA user_version = 1;");
  raw.prepare("INSERT INTO credentials (tenant_id, name, sealed, updated_at) VALUES ('t', 'wazuh.password', 'x', 1)").run();
  raw.close();
  const db = openDb(file);
  assert.equal(db.prepare("PRAGMA user_version").get().user_version, SCHEMA_VERSION);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM credentials").get().n, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM findings").get().n, 0);
  db.close();
});
test("a version 3 database migrates to version 4 keeping findings, with per-container rows possible", async () => {
  const { DatabaseSync } = await import("node:sqlite");
  const file = tmp();
  openDb(file).close();
  const raw = new DatabaseSync(file);
  raw.exec(`DROP TABLE findings;
    CREATE TABLE findings (tenant_id TEXT NOT NULL, source TEXT NOT NULL, asset_key TEXT NOT NULL, cve TEXT NOT NULL, pkg_name TEXT NOT NULL, pkg_version TEXT NOT NULL, pkg_arch TEXT NOT NULL,
      pkg_type TEXT, severity TEXT NOT NULL, cvss REAL, fix_state TEXT NOT NULL, fixed_version TEXT, low_confidence INTEGER NOT NULL DEFAULT 0, condition TEXT,
      recognised_condition INTEGER NOT NULL DEFAULT 0, detected_at INTEGER, first_seen_at INTEGER NOT NULL, last_confirmed_at INTEGER NOT NULL,
      PRIMARY KEY (tenant_id, source, asset_key, cve, pkg_name, pkg_version, pkg_arch));
    INSERT INTO findings VALUES ('default','wazuh','pve:guest:100','CVE-1','openssl','3','amd64','deb','high',7.5,'unknown',NULL,0,NULL,0,NULL,1,2);
    PRAGMA user_version = 3;`);
  raw.close();
  const db = openDb(file);
  assert.equal(db.prepare("PRAGMA user_version").get().user_version, SCHEMA_VERSION);
  assert.ok(SCHEMA_VERSION >= 4);
  const row = db.prepare("SELECT cve, container, image, first_seen_at FROM findings").get();
  assert.deepEqual({ ...row }, { cve: "CVE-1", container: "", image: null, first_seen_at: 1 });
  const ins = db.prepare("INSERT INTO findings (tenant_id, source, asset_key, container, image, cve, pkg_name, pkg_version, pkg_arch, severity, fix_state, first_seen_at, last_confirmed_at) VALUES ('default','grype','pve:guest:201',?,'ghcr.io/goauthentik/server','CVE-2','libx','1','','high','unknown',1,1)");
  ins.run("authentik-server-1"); ins.run("authentik-worker-1");
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM findings WHERE source = 'grype'").get().n, 2);
  db.close();
});
