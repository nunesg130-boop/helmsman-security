import { redact } from "./redact.mjs";

// One collector run = beginRun (outside any transaction, so an interrupted
// run stays visible as 'running' and is failed on restart), then either all
// evidence + finishRun('ok') in a single transaction, or finishRun('failed')
// and no evidence at all.
export const COLLECTOR_DEADLINE_MS = 5 * 60_000;

export async function runCollector(store, name, fn, { now = Date.now, staleAfterMs, secrets = [], deadlineMs = COLLECTOR_DEADLINE_MS } = {}) {
  if (!Number.isFinite(staleAfterMs)) throw new TypeError("staleAfterMs is required");
  const runId = store.beginRun(name, now());
  let output;
  let timer;
  try {
    output = await Promise.race([
      fn(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(`${name} did not finish within ${Math.round(deadlineMs / 1000)} s`), { code: "timeout" })), deadlineMs); })
    ]);
  } catch (error) {
    clearTimeout(timer);
    store.finishRun(runId, "failed", { error: redact(`${error?.code ? `${error.code}: ` : ""}${error?.message ?? error}`, secrets) }, now());
    return { status: "failed", runId };
  }
  clearTimeout(timer);
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
