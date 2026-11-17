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
  `,
  // v2: vulnerability findings and threat feeds
  `
  CREATE TABLE findings (
    tenant_id TEXT NOT NULL,
    source TEXT NOT NULL,
    asset_key TEXT NOT NULL,
    cve TEXT NOT NULL,
    pkg_name TEXT NOT NULL,
    pkg_version TEXT NOT NULL,
    pkg_arch TEXT NOT NULL,
    pkg_type TEXT,
    severity TEXT NOT NULL,
    cvss REAL,
    fix_state TEXT NOT NULL CHECK (fix_state IN ('fix-available-not-applied','no-fix-exists','unknown')),
    fixed_version TEXT,
    low_confidence INTEGER NOT NULL DEFAULT 0,
    condition TEXT,
    recognised_condition INTEGER NOT NULL DEFAULT 0,
    detected_at INTEGER,
    first_seen_at INTEGER NOT NULL,
    last_confirmed_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, source, asset_key, cve, pkg_name, pkg_version, pkg_arch)
  );
  CREATE INDEX findings_by_asset ON findings (tenant_id, asset_key);
  CREATE INDEX findings_by_cve ON findings (tenant_id, cve);

  CREATE TABLE kev (
    tenant_id TEXT NOT NULL,
    cve TEXT NOT NULL,
    date_added TEXT,
    ransomware INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, cve)
  );
  CREATE TABLE epss (
    tenant_id TEXT NOT NULL,
    cve TEXT NOT NULL,
    score REAL NOT NULL,
    percentile REAL NOT NULL,
    PRIMARY KEY (tenant_id, cve)
  );
  CREATE TABLE feeds (
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, name)
  );
  `,
  // v3: risk acceptances (a third kind of hold, with the context it was made in)
  `
  CREATE TABLE holds_v3 (
    id INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('hold','exclusion','acceptance')),
    asset_key TEXT NOT NULL,
    check_id TEXT,
    product TEXT,
    version TEXT,
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    context_json TEXT
  );
  INSERT INTO holds_v3 (id, tenant_id, kind, asset_key, check_id, product, version, reason, expires_at, created_at)
    SELECT id, tenant_id, kind, asset_key, check_id, product, version, reason, expires_at, created_at FROM holds;
  DROP TABLE holds;
  ALTER TABLE holds_v3 RENAME TO holds;
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
