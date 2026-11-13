// Holds (deliberately pinned software versions) and check exclusions
// ("this guest is intentionally not backed up"). Both need a reason, both
// are always shown, and an expired entry stops having any effect.
export class HoldStore {
  constructor(db, tenantId) {
    if (!tenantId) throw new TypeError("tenantId is required");
    this.db = db;
    this.tenantId = tenantId;
  }

  add({ kind, assetKey, checkId = null, product = null, version = null, reason, expiresAt = null }, now) {
    if (kind !== "hold" && kind !== "exclusion") throw new TypeError("kind must be hold or exclusion");
    if (typeof assetKey !== "string" || !assetKey) throw new TypeError("assetKey is required");
    if (typeof reason !== "string" || !reason.trim()) throw new TypeError("a reason is required");
    if (kind === "exclusion" && !checkId) throw new TypeError("an exclusion needs a checkId");
    if (kind === "hold" && (!product || !version)) throw new TypeError("a hold needs product and version");
    if (expiresAt != null && !Number.isFinite(expiresAt)) throw new TypeError("expiresAt must be a timestamp");
    const r = this.db.prepare(
      "INSERT INTO holds (tenant_id, kind, asset_key, check_id, product, version, reason, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(this.tenantId, kind, assetKey, checkId, product, version, reason.trim(), expiresAt, now);
    return Number(r.lastInsertRowid);
  }

  remove(id) {
    return Number(this.db.prepare("DELETE FROM holds WHERE tenant_id = ? AND id = ?").run(this.tenantId, id).changes);
  }

  list(now = Date.now()) {
    return this.db.prepare("SELECT * FROM holds WHERE tenant_id = ? ORDER BY id").all(this.tenantId).map((r) => ({
      id: r.id, kind: r.kind, assetKey: r.asset_key, checkId: r.check_id, product: r.product, version: r.version,
      reason: r.reason, expiresAt: r.expires_at, createdAt: r.created_at, expired: r.expires_at != null && r.expires_at <= now
    }));
  }

  #active(sql, params, now) {
    const r = this.db.prepare(`SELECT * FROM holds WHERE tenant_id = ? AND ${sql} AND (expires_at IS NULL OR expires_at > ?) ORDER BY id LIMIT 1`).get(this.tenantId, ...params, now);
    return r ? { id: r.id, kind: r.kind, reason: r.reason, expiresAt: r.expires_at } : null;
  }

  activeExclusion(assetKey, checkId, now) {
    return this.#active("kind = 'exclusion' AND asset_key = ? AND check_id = ?", [assetKey, checkId], now);
  }

  activeHold(assetKey, product, version, now) {
    return this.#active("kind = 'hold' AND asset_key = ? AND product = ? AND version = ?", [assetKey, product, String(version)], now);
  }
}
