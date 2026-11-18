// Which findings need attention first. Two separate questions, kept apart:
//   findingExposure: how exposed is the software this finding is in?
//   urgency:         given that, KEV, severity and fix state, is it urgent?
// What is confirmed (from routes) and what is only likely (a package that
// seems to be the one serving a route) are separate fields; the heuristic
// never upgrades or suppresses the confirmed answer.
// v2 (phase 2C): findings inside a container a route lands on get confirmed
// service or gated exposure; the rule itself is unchanged.
export const URGENCY_RULES = 2;

const VERIFIED = new Set(["authentik", "cloudflare-access", "verified-mixed"]);
const GATE_WEAKNESS = { none: 2, unknown: 1 };
const lower = (s) => String(s ?? "").toLowerCase();

function servesIt(pkgName, processName) {
  const pkg = lower(pkgName), proc = lower(processName);
  if (proc.length < 3 || !pkg || pkg.startsWith("linux-image-")) return false;
  return pkg === proc || pkg === `${proc}-server` || pkg.startsWith(proc);
}

export function findingExposure(finding, machine, services = []) {
  const out = (exposure, basis, extra = {}) => ({ exposure, basis, possible: null, gate: null, via: null, ...extra });
  if (!machine || machine.exposure === "unknown") return out("unknown", "unknown");
  if (machine.exposure === "lan") return out("none", "route");
  if (machine.role === "entry" || machine.role === "gate") return out("service", "route", { gate: "none" });
  if (machine.role === "direct") return out("host", "route", { possible: "service" });

  // A container finding: the route's own listener evidence names the
  // container, so its exposure is confirmed, not guessed.
  if (finding?.container) {
    const hits = (machine.services ?? []).map((i) => services[i]).filter((s) => s && s.exposure !== "lan" && s.container === finding.container);
    if (!hits.length) return out("host", "route");
    const weakest = hits.reduce((a, b) => ((GATE_WEAKNESS[b.gate] ?? 0) > (GATE_WEAKNESS[a.gate] ?? 0) ? b : a));
    return out(VERIFIED.has(weakest.gate) ? "gated" : "service", "route", { gate: weakest.gate, via: weakest.hostname });
  }

  // An app machine: the machine is reachable, but which package answers the
  // route is an inference from the listening process name.
  const matches = (machine.services ?? []).map((i) => services[i]).filter((s) => s && s.exposure !== "lan" && servesIt(finding?.pkg?.name, s.process));
  if (!matches.length) return out("host", "route");
  const weakest = matches.reduce((a, b) => ((GATE_WEAKNESS[b.gate] ?? 0) > (GATE_WEAKNESS[a.gate] ?? 0) ? b : a));
  return out("host", "route", { possible: VERIFIED.has(weakest.gate) ? "gated" : "service", gate: weakest.gate, via: weakest.hostname });
}

const SEVERE = new Set(["high", "critical"]);
// The rule itself, for a definite exposure and a definite KEV answer.
function rule(exposure, kev, severity, fixState) {
  if (exposure === "service") return kev || (SEVERE.has(severity) && fixState === "fix-available-not-applied");
  if (exposure === "gated" || exposure === "host") return kev;
  return false;
}

export function urgency({ exposure, possible = null, kev, severity, fixState, lowConfidence = false, accepted = false }) {
  if (accepted) return { urgent: false, possiblyUrgent: false, why: "risk accepted by the owner" };
  if (lowConfidence) return { urgent: false, possiblyUrgent: false, why: "low confidence match; not counted as urgent" };
  const at = (e, k) => rule(e, k, severity, fixState);

  let urgent, why;
  if (exposure === "unknown") { urgent = null; why = "exposure can't be established"; }
  else if (kev === null) {
    // Without a current KEV list: urgent if it is urgent even when not listed,
    // unknown if being listed would make it urgent.
    urgent = at(exposure, false) ? true : at(exposure, true) ? null : false;
    why = urgent === true ? "internet-facing, high or critical, and a fix is available" : urgent === null ? "the KEV list is missing or out of date" : "not exposed to the internet";
  } else {
    urgent = at(exposure, kev);
    why = urgent
      ? (kev ? `actively exploited (KEV) on ${exposure === "service" ? "an internet-facing service" : exposure === "gated" ? "a service behind a login gate" : "an internet-reachable machine"}` : "internet-facing, high or critical, and a fix is available")
      : exposure === "none" ? "not exposed to the internet" : "not known to be exploited" + (exposure === "service" ? ", and no high or critical fix is waiting" : "; the machine is reachable but this software isn't confirmed to be the part that is exposed");
  }

  const worstKev = kev === null ? true : kev;
  const readings = [exposure === "unknown" ? "service" : exposure, possible].filter(Boolean);
  const possiblyUrgent = urgent !== true && readings.some((e) => at(e, worstKev));
  if (possiblyUrgent && urgent === false) {
    why = possible && at(possible, worstKev) ? `this package may be the one serving ${possible === "gated" ? "a gated" : "a public"} route (matched by process name, not confirmed)` : why;
  }
  return { urgent, possiblyUrgent, why };
}

// Order used when deciding whether a finding has become more exposed.
export const EXPOSURE_RANK = Object.freeze({ none: 0, gated: 1, host: 2, service: 3, unknown: 4 });
