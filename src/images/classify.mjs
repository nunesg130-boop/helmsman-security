// Turns one Grype match (as the worker recorded it) into the engine's
// vocabulary. KEV and EPSS are keyed by CVE, so a GHSA advisory is filed
// under its related CVE when it has one.
import { normaliseSeverity } from "../vuln/classify.mjs";

const FIX = { fixed: "fix-available-not-applied", "not-fixed": "no-fix-exists", "wont-fix": "no-fix-exists" };

export function classifyMatch(match) {
  const id = String(match?.id ?? "");
  const related = (match?.relatedCves ?? []).filter((x) => /^CVE-\d{4}-\d+$/u.test(x));
  const cve = /^CVE-\d{4}-\d+$/u.test(id) ? id : related[0] ?? id;
  const aliases = [id, ...related].filter((x) => x && x !== cve);
  const sev = String(match?.severity ?? "").toLowerCase();
  const fixState = FIX[match?.fixState] ?? "unknown";
  return {
    cve,
    aliases: [...new Set(aliases)],
    severity: sev === "negligible" ? "low" : normaliseSeverity(sev),
    cvss: Number.isFinite(match?.cvss) ? match.cvss : null,
    fixState,
    fixedVersion: fixState === "fix-available-not-applied" ? (match.fixVersions?.[0] ?? null) : null,
    lowConfidence: match?.matchType === "cpe-match",
    recognised: fixState !== "unknown"
  };
}
