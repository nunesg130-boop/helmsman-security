// Test helpers: an in-memory evidence store with real EvidenceStore semantics.
import { openDb } from "../../src/db.mjs";
import { EvidenceStore } from "../../src/evidence.mjs";

export function memoryStore(tenant = "default") {
  return new EvidenceStore(openDb(":memory:"), tenant);
}

export function putOk(store, collector, items, now) {
  const run = store.beginRun(collector, now);
  for (const i of items) store.put(run, { source: collector, staleAfterMs: 45 * 60_000, collectedAt: now, ...i });
  store.finishRun(run, "ok", {}, now);
}

export const noHolds = { activeExclusion: () => null, activeHold: () => null };
