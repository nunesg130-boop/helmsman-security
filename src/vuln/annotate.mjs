// Joins vulnerability findings with the exposure map and the owner's risk
// acceptances. Used by the API, the report and the posture score, so all
// three give the same answer for the same finding.
import { findingExposure, urgency, EXPOSURE_RANK } from "./urgency.mjs";
import { GLOBAL_KEY } from "../checks/runner.mjs";

const FUTURE_TOLERANCE_MS = 60_000;

// The exposure map, only if it is fresh and its last run succeeded.
export function readExposureMap(store, now) {
  const ev = store.get(GLOBAL_KEY, "exposure.map");
  if (store.lastRun("exposure")?.status === "failed") return { map: null, status: "failed" };
  if (!ev) return { map: null, status: "missing" };
  if (ev.collectedAt > now + FUTURE_TOLERANCE_MS || now - ev.collectedAt > ev.staleAfterMs) return { map: null, status: "stale" };
  return { map: ev.value, status: "ok" };
}

// The situation an acceptance is made in: the worst reading of the finding's
// exposure (a "possible" service exposure counts), its gate and KEV status.
export function acceptanceContext(f) {
  const worst = f.possibleExposure && EXPOSURE_RANK[f.possibleExposure] > EXPOSURE_RANK[f.exposure] ? f.possibleExposure : f.exposure;
  return { kev: f.kev ?? null, exposure: worst, gate: f.gate ?? null };
}

export function annotateFindings(items, { map, holds, now }) {
  const machines = new Map((map?.machines ?? []).map((m) => [m.assetKey, m]));
  const services = map?.services ?? [];
  const lookup = holds.acceptanceLookup(now);
  return items.map((item) => {
    const e = findingExposure(item, map ? machines.get(item.assetKey) : undefined, services);
    const base = { ...item, exposure: e.exposure, exposureBasis: e.basis, possibleExposure: e.possible, gate: e.gate, via: e.via };
    const accepted = lookup(item.assetKey, item.cve, item.pkg.name, item.pkg.version, acceptanceContext(base));
    const u = urgency({ exposure: e.exposure, possible: e.possible, kev: item.kev, severity: item.severity, fixState: item.fixState, lowConfidence: item.lowConfidence, accepted: Boolean(accepted) });
    return { ...base, urgent: u.urgent, possiblyUrgent: u.possiblyUrgent, urgencyWhy: u.why, accepted };
  });
}

// The context to record with a new acceptance, from current data. Null when
// no such finding is on record.
export function currentFindingContext({ assetKey, cve, pkg, version }, { findings, store, holds, now, maxFeedAgeMs }) {
  if (![assetKey, cve, pkg].every((v) => typeof v === "string" && v) || version == null) return null;
  const { items } = findings.list({ assetKey, cve, pkgName: pkg, pkgVersion: version, limit: 1 }, { now, maxFeedAgeMs });
  if (!items.length) return null;
  const [annotated] = annotateFindings(items, { map: readExposureMap(store, now).map, holds, now });
  return acceptanceContext(annotated);
}
