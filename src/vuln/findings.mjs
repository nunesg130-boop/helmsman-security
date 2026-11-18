// Vulnerability findings plus the two threat feeds (CISA KEV, EPSS). Feeds
// are joined at read time and only while fresh: a stale or missing feed
// reads as null ("don't know"), never as "not exploited".
const FIX_COLUMNS = { "fix-available-not-applied": "fixAvailable", "no-fix-exists": "noFix", unknown: "fixUnknown" };

export class FindingStore {
  constructor(db, tenantId) {
    if (!tenantId) throw new TypeError("tenantId is required");
    this.db = db;
    this.tenantId = tenantId;
  }

  #tx(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try { const r = fn(); this.db.exec("COMMIT"); return r; }
    catch (e) { this.db.exec("ROLLBACK"); throw e; }
  }

  // Replace everything one source reported. A finding that persists keeps
  // its first_seen_at; one the source no longer reports is removed.
  // Pass { transaction: false } when the caller already holds a transaction.
  replaceSource(source, findings, now, { transaction = true } = {}) {
    const upsert = this.db.prepare(
      `INSERT INTO findings (tenant_id, source, asset_key, cve, pkg_name, pkg_version, pkg_arch, pkg_type, severity, cvss, fix_state, fixed_version,
         low_confidence, condition, recognised_condition, detected_at, first_seen_at, last_confirmed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (tenant_id, source, asset_key, cve, pkg_name, pkg_version, pkg_arch) DO UPDATE SET
         pkg_type = excluded.pkg_type, severity = excluded.severity, cvss = excluded.cvss, fix_state = excluded.fix_state,
         fixed_version = excluded.fixed_version, low_confidence = excluded.low_confidence, condition = excluded.condition,
         recognised_condition = excluded.recognised_condition, detected_at = excluded.detected_at, last_confirmed_at = excluded.last_confirmed_at`
    );
    const run = transaction ? (fn) => this.#tx(fn) : (fn) => fn();
    return run(() => {
      // Mark, re-confirm, sweep: whatever isn't re-confirmed is gone.
      this.db.prepare("UPDATE findings SET last_confirmed_at = -1 WHERE tenant_id = ? AND source = ?").run(this.tenantId, source);
      for (const f of findings) {
        for (const [k, v] of Object.entries({ assetKey: f.assetKey, cve: f.cve, package: f.pkg?.name })) {
          if (typeof v !== "string" || !v) throw new TypeError(`finding ${k} is required`);
        }
        upsert.run(this.tenantId, source, f.assetKey, f.cve, f.pkg.name, String(f.pkg.version ?? ""), String(f.pkg.arch ?? ""), f.pkg.type ?? null,
          f.severity, Number.isFinite(f.cvss) ? f.cvss : null, f.fixState, f.fixedVersion ?? null, f.lowConfidence ? 1 : 0, f.condition ?? null,
          f.recognisedCondition ? 1 : 0, Number.isFinite(f.detectedAt) ? f.detectedAt : null, now, now);
      }
      this.db.prepare("DELETE FROM findings WHERE tenant_id = ? AND source = ? AND last_confirmed_at = -1").run(this.tenantId, source);
      return findings.length;
    });
  }

  #replaceFeed(name, table, rows, insertSql, toParams, now) {
    this.#tx(() => {
      this.db.prepare(`DELETE FROM ${table} WHERE tenant_id = ?`).run(this.tenantId);
      const ins = this.db.prepare(insertSql);
      for (const r of rows) {
        if (typeof r?.cve !== "string" || !r.cve) throw new TypeError(`${name} row without a CVE id`);
        ins.run(this.tenantId, ...toParams(r));
      }
      this.db.prepare(
        "INSERT INTO feeds (tenant_id, name, fetched_at, count) VALUES (?, ?, ?, ?) ON CONFLICT (tenant_id, name) DO UPDATE SET fetched_at = excluded.fetched_at, count = excluded.count"
      ).run(this.tenantId, name, now, rows.length);
    });
  }

  replaceKev(entries, now) {
    this.#replaceFeed("kev", "kev", entries, "INSERT OR REPLACE INTO kev (tenant_id, cve, date_added, ransomware) VALUES (?, ?, ?, ?)",
      (r) => [r.cve, r.dateAdded ?? null, r.ransomware ? 1 : 0], now);
  }

  replaceEpss(rows, now) {
    this.#replaceFeed("epss", "epss", rows, "INSERT OR REPLACE INTO epss (tenant_id, cve, score, percentile) VALUES (?, ?, ?, ?)",
      (r) => [r.cve, r.score, r.percentile], now);
  }

  feed(name) {
    const r = this.db.prepare("SELECT fetched_at, count FROM feeds WHERE tenant_id = ? AND name = ?").get(this.tenantId, name);
    return r ? { fetchedAt: r.fetched_at, count: r.count } : null;
  }

  #fresh(name, now, maxFeedAgeMs) {
    const f = this.feed(name);
    return Boolean(f) && now - f.fetchedAt <= maxFeedAgeMs && f.fetchedAt <= now + 60_000;
  }

  // The one place that decides whether a threat feed can be relied on.
  freshness({ now, maxFeedAgeMs }) {
    return { kev: this.#fresh("kev", now, maxFeedAgeMs), epss: this.#fresh("epss", now, maxFeedAgeMs) };
  }

  list({ assetKey, cve, pkgName, pkgVersion, kev, fixState, severity, limit = 100, offset = 0 } = {}, { now, maxFeedAgeMs }) {
    const kevFresh = this.#fresh("kev", now, maxFeedAgeMs);
    const epssFresh = this.#fresh("epss", now, maxFeedAgeMs);
    const where = ["f.tenant_id = ?"];
    const params = [this.tenantId];
    if (assetKey) { where.push("f.asset_key = ?"); params.push(assetKey); }
    if (cve) { where.push("f.cve = ?"); params.push(cve); }
    if (pkgName) { where.push("f.pkg_name = ?"); params.push(pkgName); }
    if (pkgVersion != null) { where.push("f.pkg_version = ?"); params.push(String(pkgVersion)); }
    if (fixState) { where.push("f.fix_state = ?"); params.push(fixState); }
    if (severity) { where.push("f.severity = ?"); params.push(severity); }
    if (kev === true || kev === false) {
      // Without a fresh KEV list neither answer can be given.
      if (!kevFresh) return { items: [], total: 0, kevFresh, epssFresh };
      where.push(kev ? "k.cve IS NOT NULL" : "k.cve IS NULL");
    }
    const from = `FROM findings f
      LEFT JOIN kev k ON k.tenant_id = f.tenant_id AND k.cve = f.cve
      LEFT JOIN epss e ON e.tenant_id = f.tenant_id AND e.cve = f.cve
      WHERE ${where.join(" AND ")}`;
    const total = this.db.prepare(`SELECT COUNT(*) AS n ${from}`).get(...params).n;
    const order = `${kevFresh ? "(k.cve IS NOT NULL) DESC, " : ""}(f.cvss IS NULL), f.cvss DESC, f.cve, f.asset_key, f.pkg_name`;
    const rows = this.db.prepare(`SELECT f.*, k.cve AS kev_cve, k.ransomware AS kev_ransomware, e.score AS epss_score ${from} ORDER BY ${order} LIMIT ? OFFSET ?`)
      .all(...params, Math.max(1, limit), Math.max(0, offset));
    const items = rows.map((r) => ({
      source: r.source, assetKey: r.asset_key, cve: r.cve,
      pkg: { name: r.pkg_name, version: r.pkg_version, arch: r.pkg_arch, type: r.pkg_type },
      severity: r.severity, cvss: r.cvss, fixState: r.fix_state, fixedVersion: r.fixed_version, lowConfidence: r.low_confidence === 1,
      detectedAt: r.detected_at, firstSeenAt: r.first_seen_at, lastConfirmedAt: r.last_confirmed_at,
      kev: kevFresh ? r.kev_cve != null : null,
      ransomware: kevFresh && r.kev_cve != null ? r.kev_ransomware === 1 : null,
      epss: epssFresh ? r.epss_score ?? null : null,
      threatDataStale: !(kevFresh && epssFresh)
    }));
    return { items, total, kevFresh, epssFresh };
  }

  summaryByAsset({ now, maxFeedAgeMs }) {
    const kevFresh = this.#fresh("kev", now, maxFeedAgeMs);
    const rows = this.db.prepare(
      `SELECT f.asset_key, f.severity, f.fix_state, f.low_confidence, f.recognised_condition, (k.cve IS NOT NULL) AS is_kev, COUNT(*) AS n
       FROM findings f LEFT JOIN kev k ON k.tenant_id = f.tenant_id AND k.cve = f.cve
       WHERE f.tenant_id = ? GROUP BY f.asset_key, f.severity, f.fix_state, f.low_confidence, f.recognised_condition, is_kev`
    ).all(this.tenantId);
    const out = new Map();
    for (const r of rows) {
      if (!out.has(r.asset_key)) {
        out.set(r.asset_key, { assetKey: r.asset_key, total: 0, critical: 0, high: 0, medium: 0, low: 0, unknownSeverity: 0, fixAvailable: 0, noFix: 0, fixUnknown: 0, kev: kevFresh ? 0 : null, lowConfidence: 0, unrecognisedCondition: 0 });
      }
      const a = out.get(r.asset_key);
      a.total += r.n;
      a[r.severity === "unknown" ? "unknownSeverity" : r.severity] += r.n;
      a[FIX_COLUMNS[r.fix_state]] += r.n;
      if (r.low_confidence) a.lowConfidence += r.n;
      if (!r.recognised_condition) a.unrecognisedCondition += r.n;
      if (kevFresh && r.is_kev) a.kev += r.n;
    }
    return [...out.values()].sort((x, y) => y.total - x.total || x.assetKey.localeCompare(y.assetKey));
  }
}
