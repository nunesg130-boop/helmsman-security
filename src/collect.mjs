import { redact } from "./redact.mjs";

// One collector run = beginRun (outside any transaction, so an interrupted
// run stays visible as 'running' and is failed on restart), then either all
// evidence + finishRun('ok') in a single transaction, or finishRun('failed')
// and no evidence at all.
export async function runCollector(store, name, fn, { now = Date.now, staleAfterMs, secrets = [] } = {}) {
  if (!Number.isFinite(staleAfterMs)) throw new TypeError("staleAfterMs is required");
  const runId = store.beginRun(name, now());
  let output;
  try {
    output = await fn();
  } catch (error) {
    store.finishRun(runId, "failed", { error: redact(`${error?.code ? `${error.code}: ` : ""}${error?.message ?? error}`, secrets) }, now());
    return { status: "failed", runId };
  }
  const db = store.db;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const e of output?.evidence ?? []) {
      store.put(runId, { staleAfterMs, ...e, collectedAt: e.collectedAt ?? now() });
    }
    store.finishRun(runId, "ok", { warnings: (output?.warnings ?? []).map((w) => redact(w, secrets)) }, now());
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    store.finishRun(runId, "failed", { error: redact(`could not store evidence: ${error.message}`, secrets) }, now());
    return { status: "failed", runId };
  }
  return { status: "ok", runId, output };
}
