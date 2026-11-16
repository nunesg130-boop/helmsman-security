import https from "node:https";
import { createHash, timingSafeEqual } from "node:crypto";
import { LedgerStore } from "../ledger.mjs";
import { evidenceKey } from "../checks/runner.mjs";
import { FindingStore } from "../vuln/findings.mjs";
import { VULN_COLLECTOR } from "../vuln/cycle.mjs";

// Read-only API for Helmsman. GET only, bearer token required on every
// route, bounded responses, no admin functions on this port at all.
const MAX_BODY = 1024 * 1024;
const MAX_SOFTWARE = 2000;
const STATE_KEYS = ["ok", "issue", "unknown", "not_applicable", "excluded"];
const FIX_STATES = new Set(["fix-available-not-applied", "no-fix-exists", "unknown"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "unknown"]);
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

export function createPublicServer({ db, tenantId, store, credentials, tls, host, port, version, staleAfterMs = 45 * 60_000, vulnStaleAfterMs = 3 * 3600_000, maxFeedAgeMs = 7 * 86400_000, now = Date.now }) {
  const ledger = new LedgerStore(db, tenantId);
  const findings = new FindingStore(db, tenantId);

  // Findings are only as current as the last successful vulnerability read.
  function vulnMeta() {
    const run = store.lastRun(VULN_COLLECTOR);
    const last = run?.lastSuccessAt ?? null;
    const t = now();
    const kev = findings.feed("kev");
    const epss = findings.feed("epss");
    const freshFeed = (f) => Boolean(f) && t - f.fetchedAt <= maxFeedAgeMs;
    return {
      collection: { status: run?.status ?? "never_run", lastSuccessAt: last, lastError: run?.status === "failed" ? run.error : null },
      findingsStale: last == null || t - last > vulnStaleAfterMs || run.status === "failed",
      feeds: { kev, epss },
      threatDataStale: !(freshFeed(kev) && freshFeed(epss))
    };
  }
  const assetNames = () => new Map(db.prepare("SELECT asset_key, name FROM assets WHERE tenant_id = ?").all(tenantId).map((a) => [a.asset_key, a.name]));
  const intParam = (url, name, fallback, max) => {
    const n = Number.parseInt(url.searchParams.get(name) ?? "", 10);
    return Math.min(max, Math.max(0, Number.isFinite(n) ? n : fallback));
  };

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

  const brief = (r) => ({ assetKey: r.assetKey, assetName: r.assetName, checkId: r.checkId, reason: r.reason, since: r.stateSince, evaluatedAt: r.evaluatedAt });

  // A result is only as good as the cycle that produced it. If the engine
  // stopped re-evaluating (stuck collector, crash loop), old results are
  // served as unknown rather than as whatever they last were.
  function aged(rows) {
    const t = now();
    return rows.map((r) => (t - r.evaluatedAt > staleAfterMs
      ? { ...r, state: "unknown", reason: `not re-evaluated since ${new Date(r.evaluatedAt).toISOString()} (engine cycle stalled); last result: ${r.state}`, roaming: false }
      : r));
  }
  const rowsNow = () => aged(ledger.all());
  function countsOf(rows) {
    const c = Object.fromEntries(STATE_KEYS.map((k) => [k, 0]));
    let roamingAway = 0;
    for (const r of rows) {
      if (r.state === "unknown" && r.roaming) roamingAway += 1;
      else c[r.state] += 1;
    }
    return { counts: c, roamingAway };
  }
  const lastCycleAt = () => db.prepare("SELECT MAX(evaluated_at) AS t FROM ledger WHERE tenant_id = ?").get(tenantId)?.t ?? null;
  function evidenceView(ev) {
    if (!ev) return { items: [], collectedAt: null, stale: true };
    return { items: ev.value ?? [], collectedAt: ev.collectedAt, stale: now() - ev.collectedAt > ev.staleAfterMs || ev.collectedAt > now() + 60_000 };
  }

  const routes = {
    "/api/v1/health": () => {
      const last = lastCycleAt();
      if (last == null) return [200, { ok: false, version, lastCycleAt: null, reason: "no completed cycle yet" }];
      if (now() - last > staleAfterMs) return [200, { ok: false, version, lastCycleAt: last, reason: `engine stalled: last cycle ${new Date(last).toISOString()}` }];
      return [200, { ok: true, version, lastCycleAt: last }];
    },
    "/api/v1/summary": () => {
      const { counts, roamingAway } = countsOf(rowsNow());
      const collectors = store.collectors().map((name) => {
        const r = store.lastRun(name);
        return { name, status: r.status, lastSuccessAt: r.lastSuccessAt, lastError: r.status === "failed" ? r.error : null, warnings: r.warnings };
      });
      return [200, { engine: { version, now: now(), lastCycleAt: lastCycleAt() }, counts, roamingAway, collectors }];
    },
    "/api/v1/issues": (url) => [200, paginate(rowsNow().filter((r) => r.state === "issue").map(brief), url)],
    "/api/v1/unknowns": (url) => [200, paginate(rowsNow().filter((r) => r.state === "unknown").map((r) => ({ ...brief(r), roaming: r.roaming })), url)],
    "/api/v1/vulnerabilities": (url) => {
      const q = url.searchParams;
      const fix = q.get("fix");
      const severity = q.get("severity");
      const kev = q.get("kev");
      if (fix && !FIX_STATES.has(fix)) return [400, { error: "fix must be fix-available-not-applied, no-fix-exists or unknown" }];
      if (severity && !SEVERITIES.has(severity)) return [400, { error: "severity must be critical, high, medium, low or unknown" }];
      if (kev && kev !== "true" && kev !== "false") return [400, { error: "kev must be true or false" }];
      const limit = Math.max(1, intParam(url, "limit", 50, 200));
      const offset = intParam(url, "offset", 0, Number.MAX_SAFE_INTEGER);
      const { items, total } = findings.list({ assetKey: q.get("asset") || undefined, kev: kev ? kev === "true" : undefined, fixState: fix || undefined, severity: severity || undefined, limit, offset }, { now: now(), maxFeedAgeMs });
      const names = assetNames();
      return [200, { items: items.map((i) => ({ ...i, assetName: names.get(i.assetKey) ?? i.assetKey })), total, limit, offset, ...vulnMeta() }];
    },
    "/api/v1/vulnerabilities/summary": () => {
      const names = assetNames();
      const assets = findings.summaryByAsset({ now: now(), maxFeedAgeMs }).map((a) => ({ ...a, assetName: names.get(a.assetKey) ?? a.assetKey }));
      const totals = { total: 0, critical: 0, high: 0, medium: 0, low: 0, unknownSeverity: 0, fixAvailable: 0, noFix: 0, fixUnknown: 0, lowConfidence: 0, unrecognisedCondition: 0 };
      for (const a of assets) for (const k of Object.keys(totals)) totals[k] += a[k];
      totals.kev = assets.some((a) => a.kev == null) ? null : assets.reduce((n, a) => n + a.kev, 0);
      return [200, { assets, totals, ...vulnMeta() }];
    },
    "/api/v1/assets": (url) => {
      const counts = new Map();
      for (const r of rowsNow()) {
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
      checks: aged(ledger.forAsset(key)),
      software: items.slice(0, MAX_SOFTWARE).map((p) => ({ name: p.name, version: p.version })),
      softwareTruncated: items.length > MAX_SOFTWARE,
      softwareCollectedAt: pk?.collectedAt ?? null,
      softwareStale: evidenceView(pk).stale,
      ports: evidenceView(ev("wazuh.ports")),
      containers: evidenceView(ev("docker.containers"))
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
