// Turns the raw fields of a Wazuh vulnerability record into the engine's
// vocabulary. Anything not positively recognised is "unknown", never a guess.
const LESS_THAN = /^Package less than (\S+)$/u;
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);
// Sources that match on product names (CPE) rather than a vendor's own
// package tracker; treated as lower confidence.
const NAME_BASED_SOURCES = new Set(["national vulnerability database"]);

export function fixStateFromCondition(condition) {
  const text = typeof condition === "string" ? condition.trim() : "";
  const m = LESS_THAN.exec(text);
  if (m) return { fixState: "fix-available-not-applied", fixedVersion: m[1], recognised: true };
  if (text === "Package default status") return { fixState: "no-fix-exists", fixedVersion: null, recognised: true };
  return { fixState: "unknown", fixedVersion: null, recognised: false };
}

export function normaliseSeverity(value) {
  const s = String(value ?? "").trim().toLowerCase();
  return SEVERITIES.has(s) ? s : "unknown";
}

export function isLowConfidence({ source, underEvaluation } = {}) {
  if (underEvaluation === true) return true;
  const s = String(source ?? "").trim().toLowerCase();
  return !s || NAME_BASED_SOURCES.has(s);
}
