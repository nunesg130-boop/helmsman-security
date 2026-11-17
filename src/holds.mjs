// Holds (deliberately pinned software versions), check exclusions ("this guest
// is intentionally not backed up"; check "*" = every check on that machine)
// and risk acceptances (one CVE in one package version on one machine).
// All need a reason, all are always shown, and an expired entry stops having
// any effect. An acceptance also records the situation it was made in, and
// stops applying when that situation gets worse.
import { EXPOSURE_RANK } from "./vuln/urgency.mjs";

const VERIFIED_GATES = new Set(["authentik", "cloudflare-access", "verified-mixed"]);
const GATES = new Set([...VERIFIED_GATES, "none", "unknown"]);

function validContext(c) {
  return c && typeof c === "object" && (c.kev === true || c.kev === false || c.kev === null) && Object.hasOwn(EXPOSURE_RANK, c.exposure) && (c.gate === null || GATES.has(c.gate));
}

// Does an acceptance made in situation `then` still cover situation `current`?
function stillCovers(then, current) {
  if (current.kev !== false && then.kev !== true) return false; // now exploited, or can't tell
  if ((EXPOSURE_RANK[current.exposure] ?? Infinity) > (EXPOSURE_RANK[then.exposure] ?? -1)) return false; // more exposed
  if (VERIFIED_GATES.has(then.gate) && (current.gate === "none" || current.gate === "unknown")) return false; // lost its gate
  return true;
}

export class HoldStore {
  constructor(db, tenantId) {
    if (!tenantId) throw new TypeError("tenantId is required");
    this.db = db;
    this.tenantId = tenantId;
  }

  add({ kind, assetKey, checkId = null, product = null, version = null, reason, expiresAt = null, context = null }, now) {
    if (!["hold", "exclusion", "acceptance"].includes(kind)) throw new TypeError("kind must be hold, exclusion or acceptance");
    if (typeof assetKey !== "string" || !assetKey) throw new TypeError("assetKey is required");
    if (typeof reason !== "string" || !reason.trim()) throw new TypeError("a reason is required");
    if (kind === "exclusion" && !checkId) throw new TypeError("an exclusion needs a checkId");
    if (kind === "hold" && (!product || !version)) throw new TypeError("a hold needs product and version");
    if (kind === "acceptance") {
      if (!checkId || !product || !version) throw new TypeError("an acceptance needs a CVE, a package and its version");
      if (!validContext(context)) throw new TypeError("an acceptance needs the finding's current KEV, exposure and gate");
    }
    if (expiresAt != null && !Number.isFinite(expiresAt)) throw new TypeError("expiresAt must be a timestamp");
    const ctx = kind === "acceptance" ? JSON.stringify({ kev: context.kev, exposure: context.exposure, gate: context.gate }) : null;
    const r = this.db.prepare(
      "INSERT INTO holds (tenant_id, kind, asset_key, check_id, product, version, reason, expires_at, created_at, context_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(this.tenantId, kind, assetKey, checkId, product, version == null ? null : String(version), reason.trim(), expiresAt, now, ctx);
    return Number(r.lastInsertRowid);
  }

  remove(id) {
    return Number(this.db.prepare("DELETE FROM holds WHERE tenant_id = ? AND id = ?").run(this.tenantId, id).changes);
  }

  list(now = Date.now()) {
    return this.db.prepare("SELECT * FROM holds WHERE tenant_id = ? ORDER BY id").all(this.tenantId).map((r) => ({
      id: r.id, kind: r.kind, assetKey: r.asset_key, checkId: r.check_id, product: r.product, version: r.version,
      reason: r.reason, expiresAt: r.expires_at, createdAt: r.created_at, expired: r.expires_at != null && r.expires_at <= now,
      context: r.context_json ? JSON.parse(r.context_json) : null
    }));
  }

  #active(sql, params, now, order = "id") {
    const r = this.db.prepare(`SELECT * FROM holds WHERE tenant_id = ? AND ${sql} AND (expires_at IS NULL OR expires_at > ?) ORDER BY ${order} LIMIT 1`).get(this.tenantId, ...params, now);
    return r ? { id: r.id, kind: r.kind, reason: r.reason, expiresAt: r.expires_at } : null;
  }

  // checkId "*" excludes the whole machine; a per-check exclusion's reason wins.
  activeExclusion(assetKey, checkId, now) {
    return this.#active("kind = 'exclusion' AND asset_key = ? AND (check_id = ? OR check_id = '*')", [assetKey, checkId], now, "check_id = '*', id");
  }

  activeHold(assetKey, product, version, now) {
    return this.#active("kind = 'hold' AND asset_key = ? AND product = ? AND version = ?", [assetKey, product, String(version)], now);
  }

  // One read of every live acceptance, then an in-memory answer per finding.
  acceptanceLookup(now) {
    const rows = this.db.prepare("SELECT id, asset_key, check_id, product, version, reason, context_json FROM holds WHERE tenant_id = ? AND kind = 'acceptance' AND (expires_at IS NULL OR expires_at > ?) ORDER BY id")
      .all(this.tenantId, now);
    const index = new Map();
    const keyOf = (...parts) => parts.join("\u0000");
    for (const r of rows) {
      const k = keyOf(r.asset_key, r.check_id, r.product, r.version);
      index.set(k, [...(index.get(k) ?? []), { id: r.id, reason: r.reason, context: r.context_json ? JSON.parse(r.context_json) : null }]);
    }
    return (assetKey, cve, pkg, version, current) => {
      const hit = (index.get(keyOf(assetKey, cve, pkg, String(version))) ?? []).find((a) => validContext(a.context) && stillCovers(a.context, current));
      return hit ? { id: hit.id, reason: hit.reason } : null;
    };
  }

  // Null when the version differs, the finding became known-exploited, its
  // exposure rose, or its verified gate became none or unknown.
  activeAcceptance(assetKey, cve, pkg, version, current, now) {
    return this.acceptanceLookup(now)(assetKey, cve, pkg, version, current);
  }
}
