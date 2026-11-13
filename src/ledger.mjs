import { runCheck } from "./checks/runner.mjs";
import { CHECKS } from "./checks/index.mjs";
import { result } from "./states.mjs";

export const ASSET_RETENTION_MS = 7 * 86400_000;

export function evaluateAll({ store, holds, assets, config, now, checks = CHECKS }) {
  const rows = [];
  for (const asset of assets) {
    for (const check of checks) {
      let r;
      if (asset.ambiguous && check.appliesTo(asset, config)) r = result("unknown", asset.ambiguousReason ?? "can't tell which agent belongs to this machine");
      else r = runCheck(check, asset, { store, holds, config, now });
      rows.push({
        assetKey: asset.assetKey,
        checkId: check.id,
        state: r.state,
        reason: r.reason,
        evidence: r.evidence ?? [],
        roaming: Boolean(r.roaming) || (asset.class === "roaming" && r.state === "unknown")
      });
    }
  }
  return rows;
}

const rowOut = (r) => ({
  assetKey: r.asset_key, assetName: r.name ?? r.asset_key, assetClass: r.class ?? null, checkId: r.check_id, state: r.state, reason: r.reason,
  evidence: JSON.parse(r.evidence_json), roaming: r.roaming === 1, evaluatedAt: r.evaluated_at, lastOkAt: r.last_ok_at, stateSince: r.state_since
});

export class LedgerStore {
  constructor(db, tenantId) {
    if (!tenantId) throw new TypeError("tenantId is required");
    this.db = db;
    this.tenantId = tenantId;
  }

  write(rows, now) {
    const db = this.db;
    const upsert = db.prepare(
      `INSERT INTO ledger (tenant_id, asset_key, check_id, state, reason, evidence_json, roaming, evaluated_at, last_ok_at, state_since)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (tenant_id, asset_key, check_id) DO UPDATE SET
         state_since = CASE WHEN ledger.state = excluded.state THEN ledger.state_since ELSE excluded.state_since END,
         last_ok_at = CASE WHEN excluded.state = 'ok' THEN excluded.evaluated_at ELSE ledger.last_ok_at END,
         state = excluded.state, reason = excluded.reason, evidence_json = excluded.evidence_json,
         roaming = excluded.roaming, evaluated_at = excluded.evaluated_at`
    );
    db.exec("BEGIN IMMEDIATE");
    try {
      const touched = new Map();
      for (const r of rows) {
        upsert.run(this.tenantId, r.assetKey, r.checkId, r.state, r.reason, JSON.stringify(r.evidence ?? []), r.roaming ? 1 : 0, now, r.state === "ok" ? now : null, now);
        if (!touched.has(r.assetKey)) touched.set(r.assetKey, new Set());
        touched.get(r.assetKey).add(r.checkId);
      }
      const del = db.prepare("DELETE FROM ledger WHERE tenant_id = ? AND asset_key = ? AND check_id = ?");
      for (const [assetKey, ids] of touched) {
        for (const { check_id: id } of db.prepare("SELECT check_id FROM ledger WHERE tenant_id = ? AND asset_key = ?").all(this.tenantId, assetKey)) {
          if (!ids.has(id)) del.run(this.tenantId, assetKey, id);
        }
      }
      const cutoff = now - ASSET_RETENTION_MS;
      db.prepare("DELETE FROM ledger WHERE tenant_id = ? AND asset_key IN (SELECT asset_key FROM assets WHERE tenant_id = ? AND last_seen_at < ?)").run(this.tenantId, this.tenantId, cutoff);
      db.prepare("DELETE FROM assets WHERE tenant_id = ? AND last_seen_at < ?").run(this.tenantId, cutoff);
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }

  #rows(where = "", params = []) {
    return this.db.prepare(
      `SELECT l.*, a.name, a.class FROM ledger l LEFT JOIN assets a ON a.tenant_id = l.tenant_id AND a.asset_key = l.asset_key
       WHERE l.tenant_id = ? ${where} ORDER BY l.asset_key, l.check_id`
    ).all(this.tenantId, ...params).map(rowOut);
  }

  counts() {
    const out = { ok: 0, issue: 0, unknown: 0, not_applicable: 0, excluded: 0, roamingAway: 0 };
    for (const r of this.db.prepare("SELECT state, roaming, COUNT(*) AS n FROM ledger WHERE tenant_id = ? GROUP BY state, roaming").all(this.tenantId)) {
      if (r.state === "unknown" && r.roaming === 1) out.roamingAway += r.n;
      else out[r.state] += r.n;
    }
    return out;
  }

  issues() { return this.#rows("AND l.state = 'issue'"); }
  unknowns() { return this.#rows("AND l.state = 'unknown'"); }
  forAsset(assetKey) { return this.#rows("AND l.asset_key = ?", [assetKey]); }
  all() { return this.#rows(); }
}
