import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

// Every table carries tenant_id; every store filters by it.
const MIGRATIONS = [
  // v1
  `
  CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    status TEXT NOT NULL CHECK (status IN ('running','ok','failed')),
    error TEXT,
    warnings_json TEXT NOT NULL DEFAULT '[]'
  );
  CREATE INDEX runs_by_collector ON runs (tenant_id, collector, id);

  CREATE TABLE evidence (
    tenant_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    run_id INTEGER NOT NULL,
    collected_at INTEGER NOT NULL,
    stale_after_ms INTEGER NOT NULL,
    payload_hash TEXT NOT NULL,
    value_json TEXT NOT NULL,
    PRIMARY KEY (tenant_id, asset_key, kind, source)
  );

  CREATE TABLE assets (
    tenant_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('host','guest','roaming','appliance','container','network')),
    name TEXT NOT NULL,
    sources_json TEXT NOT NULL DEFAULT '{}',
    ambiguous_reason TEXT,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, asset_key)
  );

  CREATE TABLE holds (
    id INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('hold','exclusion')),
    asset_key TEXT NOT NULL,
    check_id TEXT,
    product TEXT,
    version TEXT,
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    expires_at INTEGER,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE manual_links (
    tenant_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, source, source_id)
  );

  CREATE TABLE ledger (
    tenant_id TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    check_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ok','issue','unknown','not_applicable','excluded')),
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    roaming INTEGER NOT NULL DEFAULT 0,
    evaluated_at INTEGER NOT NULL,
    last_ok_at INTEGER,
    state_since INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, asset_key, check_id)
  );

  CREATE TABLE credentials (
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    sealed TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, name)
  );
  `
];

export const SCHEMA_VERSION = MIGRATIONS.length;

export function openDb(file) {
  if (file !== ":memory:") mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = FULL;");
  let version = db.prepare("PRAGMA user_version").get().user_version;
  while (version < MIGRATIONS.length) {
    db.exec("BEGIN IMMEDIATE");
    try {
      db.exec(MIGRATIONS[version]);
      version += 1;
      db.exec(`PRAGMA user_version = ${version}`);
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }
  return db;
}
