import https from "node:https";
import { createHash, timingSafeEqual } from "node:crypto";
import { LedgerStore } from "../ledger.mjs";
import { evidenceKey } from "../checks/runner.mjs";

// Read-only API for Helmsman. GET only, bearer token required on every
// route, bounded responses, no admin functions on this port at all.
const MAX_BODY = 1024 * 1024;
const MAX_SOFTWARE = 2000;
const STATE_KEYS = ["ok", "issue", "unknown", "not_applicable", "excluded"];
const digest = (s) => createHash("sha256").update(String(s)).digest();

function send(res, status, body) {
  let text = JSON.stringify(body);
  if (Buffer.byteLength(text) > MAX_BODY) { status = 507; text = JSON.stringify({ error: "response too large" }); }
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(text);
}

function paginate(items, url) {
  const page = Math.max(1, Number.parseInt(url.searchParams.get("page") ?? "1", 10) || 1);
  const pageSize = Math.min(200, Math.max(1, Number.parseInt(url.searchParams.get("pageSize") ?? "50", 10) || 50));
  return { items: items.slice((page - 1) * pageSize, page * pageSize), page, pageSize, total: items.length };
}

export function createPublicServer({ db, tenantId, store, credentials, tls, host, port, version }) {
  const ledger = new LedgerStore(db, tenantId);

  function authorized(req) {
    const expected = credentials.get("api.readToken");
    const m = /^Bearer\s+(.+)$/u.exec(req.headers.authorization ?? "");
    if (!expected || !m) return false;
    return timingSafeEqual(digest(m[1].trim()), digest(expected));
  }

  function asset(key) {
    const r = db.prepare("SELECT asset_key, class, name, sources_json, ambiguous_reason, last_seen_at FROM assets WHERE tenant_id = ? AND asset_key = ?").get(tenantId, key);
    return r ? { assetKey: r.asset_key, class: r.class, name: r.name, sources: JSON.parse(r.sources_json), ambiguousReason: r.ambiguous_reason, lastSeenAt: r.last_seen_at } : null;
  }

  const brief = (r) => ({ assetKey: r.assetKey, assetName: r.assetName, checkId: r.checkId, reason: r.reason, since: r.stateSince });

  const routes = {
    "/api/v1/health": () => [200, { ok: true, version }],
    "/api/v1/summary": () => {
      const { roamingAway, ...counts } = ledger.counts();
      const collectors = store.collectors().map((name) => {
        const r = store.lastRun(name);
        return { name, status: r.status, lastSuccessAt: r.lastSuccessAt, lastError: r.status === "failed" ? r.error : null, warnings: r.warnings };
      });
      return [200, { engine: { version, now: Date.now() }, counts, roamingAway, collectors }];
    },
    "/api/v1/issues": (url) => [200, paginate(ledger.issues().map(brief), url)],
    "/api/v1/unknowns": (url) => [200, paginate(ledger.unknowns().map((r) => ({ ...brief(r), roaming: r.roaming })), url)],
    "/api/v1/assets": (url) => {
      const counts = new Map();
      for (const r of ledger.all()) {
        if (!counts.has(r.assetKey)) counts.set(r.assetKey, Object.fromEntries(STATE_KEYS.map((k) => [k, 0])));
        counts.get(r.assetKey)[r.state] += 1;
      }
      const items = db.prepare("SELECT asset_key, class, name FROM assets WHERE tenant_id = ? ORDER BY name").all(tenantId)
        .map((a) => ({ assetKey: a.asset_key, name: a.name, class: a.class, counts: counts.get(a.asset_key) ?? Object.fromEntries(STATE_KEYS.map((k) => [k, 0])) }));
      return [200, paginate(items, url)];
    }
  };

  function detail(key) {
    const a = asset(key);
    if (!a) return [404, { error: "not found" }];
    const ev = (kind) => { const k = evidenceKey(a, kind); return k ? store.get(k, kind) : null; };
    const pk = ev("wazuh.packages");
    const items = pk?.value?.items ?? [];
    return [200, {
      asset: a,
      checks: ledger.forAsset(key),
      software: items.slice(0, MAX_SOFTWARE).map((p) => ({ name: p.name, version: p.version })),
      softwareTruncated: items.length > MAX_SOFTWARE,
      softwareCollectedAt: pk?.collectedAt ?? null,
      ports: ev("wazuh.ports")?.value ?? [],
      containers: ev("docker.containers")?.value ?? []
    }];
  }

  const server = https.createServer({ ...tls, minVersion: "TLSv1.2" }, (req, res) => {
    try {
      if (req.method !== "GET") return send(res, 405, { error: "method not allowed" });
      if (!authorized(req)) return send(res, 401, { error: "unauthorized" });
      const url = new URL(req.url, "https://engine.local");
      const route = routes[url.pathname];
      if (route) return send(res, ...route(url));
      const m = /^\/api\/v1\/assets\/([^/]+)$/u.exec(url.pathname);
      if (m) return send(res, ...detail(decodeURIComponent(m[1])));
      return send(res, 404, { error: "not found" });
    } catch {
      return send(res, 500, { error: "internal error" });
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;

  return new Promise((resolve) => {
    server.listen(port, host, () => resolve({
      port: server.address().port,
      close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); })
    }));
  });
}
