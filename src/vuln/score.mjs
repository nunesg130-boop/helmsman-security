// Posture score, rules version 1 (see docs/scoring.md). Two numbers from the
// same findings: one counting only what is confirmed, one also counting what
// would be urgent if every uncertainty went the wrong way. When the inputs
// can't support a number, there is no number.
export const SCORE_RULES = 1;
const URGENT = 10, SEVERE_FIXABLE = 3, MEDIUM_FIXABLE = 0.5, ASSET_CAP = 25, MAX_COVERAGE_GAP = 0.2, MAX_CVES = 20;
const FIX = "fix-available-not-applied";
const REASONS = { urgent: "urgent", severe: "high or critical, fix available", medium: "medium, fix available", possible: "possibly urgent (exposure, gate or KEV status uncertain)" };

function confirmedOf(f) {
  if (f.urgent === true) return [URGENT, REASONS.urgent];
  if (f.fixState === FIX && (f.severity === "high" || f.severity === "critical")) return [SEVERE_FIXABLE, REASONS.severe];
  if (f.fixState === FIX && f.severity === "medium") return [MEDIUM_FIXABLE, REASONS.medium];
  return [0, null];
}
const round = (x) => Math.round(x * 10) / 10;

export function postureScore({ findings, coverage, freshness }) {
  const counted = findings.filter((f) => !f.lowConfidence && !f.accepted);
  const unknowns = {
    urgencyUnknown: counted.filter((f) => f.urgent === null).length,
    exposureUnknown: counted.filter((f) => f.exposure === "unknown").length,
    gateUnknown: counted.filter((f) => f.gate === "unknown").length,
    heuristic: counted.filter((f) => f.possibleExposure != null).length
  };
  const cover = { inScope: coverage?.inScope ?? 0, withoutFreshCoverage: coverage?.withoutFreshCoverage ?? 0 };

  const incompleteReasons = [];
  if (freshness.findingsStale) incompleteReasons.push("vulnerability findings are out of date or were never read");
  if (freshness.kevStale) incompleteReasons.push("the KEV list is missing or more than 7 days old");
  if (freshness.exposureStatus !== "ok") incompleteReasons.push(`the exposure map is ${freshness.exposureStatus ?? "missing"}`);
  if (cover.inScope === 0) incompleteReasons.push("no machines are in scope for vulnerability scanning");
  else if (cover.withoutFreshCoverage / cover.inScope > MAX_COVERAGE_GAP) {
    incompleteReasons.push(`${cover.withoutFreshCoverage} of ${cover.inScope} machines (${(100 * cover.withoutFreshCoverage / cover.inScope).toFixed(1)} %) have no current vulnerability scan; the limit is 20 %`);
  }
  const base = { version: SCORE_RULES, unknowns, coverage: cover };
  if (incompleteReasons.length) return { ...base, state: "incomplete", confirmed: null, pessimistic: null, incompleteReasons, deductions: [] };

  const perAsset = new Map(); // assetKey -> { confirmed, pessimistic }
  const groups = new Map();
  const charge = (assetKey, scenario, reason, points, cve) => {
    const key = `${assetKey}\u0000${scenario}\u0000${reason}`;
    if (!groups.has(key)) groups.set(key, { assetKey, scenario, reason, points: 0, cves: new Set(), findings: 0 });
    const g = groups.get(key);
    g.points += points; g.cves.add(cve); g.findings += 1;
  };
  for (const f of counted) {
    const [weight, reason] = confirmedOf(f);
    // Counted once: the pessimistic scenario adds only the difference.
    const extra = f.urgent !== true && (f.urgent === null || f.possiblyUrgent) ? URGENT - weight : 0;
    if (!weight && !extra) continue;
    const a = perAsset.get(f.assetKey) ?? { confirmed: 0, pessimistic: 0 };
    a.confirmed += weight; a.pessimistic += weight + extra;
    perAsset.set(f.assetKey, a);
    if (weight) charge(f.assetKey, "confirmed", reason, weight, f.cve);
    if (extra) charge(f.assetKey, "pessimistic", REASONS.possible, extra, f.cve);
  }
  const total = (scenario) => [...perAsset.values()].reduce((sum, a) => sum + Math.min(ASSET_CAP, a[scenario]), 0);
  const deductions = [...groups.values()]
    .map((g) => ({ assetKey: g.assetKey, scenario: g.scenario, reason: g.reason, points: round(g.points), cves: [...g.cves].sort().slice(0, MAX_CVES), findings: g.findings }))
    .sort((x, y) => y.points - x.points || x.assetKey.localeCompare(y.assetKey) || x.scenario.localeCompare(y.scenario) || x.reason.localeCompare(y.reason));
  return { ...base, state: "scored", confirmed: round(Math.max(0, 100 - total("confirmed"))), pessimistic: round(Math.max(0, 100 - total("pessimistic"))), incompleteReasons: [], deductions };
}
