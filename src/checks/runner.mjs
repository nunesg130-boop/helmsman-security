import { result } from "../states.mjs";

// The one place that decides whether evidence may be used. A check's own
// logic only ever sees fresh evidence from a healthy collector, so it cannot
// turn missing or stale data into "ok".
const FUTURE_TOLERANCE_MS = 60_000;

export function formatAge(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 120) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 120) return `${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h`;
  return `${Math.round(h / 24)} d`;
}

export function evidenceKey(asset, kind) {
  if (kind.startsWith("wazuh.")) {
    const id = asset.sources?.wazuh?.id;
    return id ? `wazuh:agent:${id}` : null;
  }
  return asset.assetKey;
}

function usable(store, asset, kind, now) {
  const key = evidenceKey(asset, kind);
  const ev = key ? store.get(key, kind) : null;
  if (!ev) return { problem: `no ${kind} evidence` };
  if (ev.collectedAt > now + FUTURE_TOLERANCE_MS) return { problem: `${kind} evidence dated in the future (clock moved?)` };
  if (now - ev.collectedAt > ev.staleAfterMs) return { problem: `${kind} last confirmed ${formatAge(now - ev.collectedAt)} ago` };
  const run = store.lastRun(ev.source);
  if (run?.status === "failed") return { problem: `${ev.source} collection failing: ${run.error ?? "unknown error"}` };
  return { ev };
}

export function runCheck(check, asset, { store, holds, config, now }) {
  if (!check.appliesTo(asset, config)) {
    return result("not_applicable", check.notApplicableReason?.(asset) ?? `does not apply to ${asset.class}`);
  }
  const exclusion = holds?.activeExclusion?.(asset.assetKey, check.id, now);
  if (exclusion) return result("excluded", exclusion.reason);

  const inputs = {};
  const problems = [];
  for (const kind of check.requires) {
    const u = usable(store, asset, kind, now);
    if (u.problem) problems.push(u.problem);
    else inputs[kind] = u.ev;
  }
  if (problems.length) return result("unknown", problems.join("; "));

  let r;
  try {
    r = check.evaluate(inputs, { asset, holds, config, now });
  } catch (error) {
    return result("unknown", `check error: ${error.message}`);
  }
  const refs = Object.values(inputs).map((e) => ({ assetKey: e.assetKey, kind: e.kind, source: e.source, collectedAt: e.collectedAt }));
  return { ...r, evidence: refs };
}
