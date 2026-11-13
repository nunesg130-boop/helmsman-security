import { createHash } from "node:crypto";

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

export const INTERRUPTED = "interrupted (engine stopped mid-run)";

export class EvidenceStore {
  constructor(db, tenantId) {
    if (!tenantId) throw new TypeError("tenantId is required");
    this.db = db;
    this.tenantId = tenantId;
  }

  beginRun(collector, now) {
    const r = this.db.prepare(
      "INSERT INTO runs (tenant_id, collector, started_at, status) VALUES (?, ?, ?, 'running')"
    ).run(this.tenantId, collector, now);
    return Number(r.lastInsertRowid);
  }

  finishRun(runId, status, { error = null, warnings = [] } = {}, now) {
    if (status !== "ok" && status !== "failed") throw new TypeError(`bad run status ${status}`);
    this.db.prepare(
      "UPDATE runs SET status = ?, finished_at = ?, error = ?, warnings_json = ? WHERE id = ? AND tenant_id = ?"
    ).run(status, now, error, JSON.stringify(warnings), runId, this.tenantId);
  }

  failOpenRuns(now) {
    const r = this.db.prepare(
      "UPDATE runs SET status = 'failed', finished_at = ?, error = ? WHERE tenant_id = ? AND status = 'running'"
    ).run(now, INTERRUPTED, this.tenantId);
    return Number(r.changes);
  }

  put(runId, { assetKey, kind, source, value, collectedAt, staleAfterMs }) {
    for (const [k, v] of Object.entries({ assetKey, kind, source })) {
      if (typeof v !== "string" || !v) throw new TypeError(`evidence ${k} is required`);
    }
    if (!Number.isFinite(collectedAt) || !Number.isFinite(staleAfterMs)) throw new TypeError("evidence times must be numbers");
    const json = canonical(value);
    const hash = createHash("sha256").update(json).digest("hex");
    this.db.prepare(
      `INSERT INTO evidence (tenant_id, asset_key, kind, source, run_id, collected_at, stale_after_ms, payload_hash, value_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (tenant_id, asset_key, kind, source) DO UPDATE SET
         run_id = excluded.run_id, collected_at = excluded.collected_at, stale_after_ms = excluded.stale_after_ms,
         payload_hash = excluded.payload_hash, value_json = excluded.value_json`
    ).run(this.tenantId, assetKey, kind, source, runId, collectedAt, staleAfterMs, hash, json);
  }

  get(assetKey, kind) {
    const row = this.db.prepare(
      `SELECT asset_key, kind, source, value_json, collected_at, stale_after_ms, run_id FROM evidence
       WHERE tenant_id = ? AND asset_key = ? AND kind = ? ORDER BY collected_at DESC LIMIT 1`
    ).get(this.tenantId, assetKey, kind);
    if (!row) return null;
    return {
      assetKey: row.asset_key,
      kind: row.kind,
      source: row.source,
      value: JSON.parse(row.value_json),
      collectedAt: row.collected_at,
      staleAfterMs: row.stale_after_ms,
      runId: row.run_id
    };
  }

  lastRun(collector) {
    const row = this.db.prepare(
      "SELECT status, started_at, finished_at, error, warnings_json FROM runs WHERE tenant_id = ? AND collector = ? ORDER BY id DESC LIMIT 1"
    ).get(this.tenantId, collector);
    if (!row) return null;
    const ok = this.db.prepare(
      "SELECT MAX(finished_at) AS t FROM runs WHERE tenant_id = ? AND collector = ? AND status = 'ok'"
    ).get(this.tenantId, collector);
    return {
      status: row.status,
      startedAt: row.started_at,
      finishedAt: row.finished_at,
      error: row.error,
      warnings: JSON.parse(row.warnings_json),
      lastSuccessAt: ok?.t ?? null
    };
  }

  collectors() {
    return this.db.prepare("SELECT DISTINCT collector FROM runs WHERE tenant_id = ? ORDER BY collector").all(this.tenantId).map((r) => r.collector);
  }
}
