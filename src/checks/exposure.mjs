import { result } from "../states.mjs";

// Checks on the machines public traffic enters through. They read the
// exposure map; a missing, stale or failed map makes them unknown before
// any of this logic runs.
const caddyKey = (config) => config?.exposure?.caddy?.assetKey ?? null;
const tunnelKey = (config) => config?.exposure?.cloudflare?.assetKey ?? null;
const originOf = (asset, config) => (asset.assetKey === caddyKey(config) ? "caddy" : asset.assetKey === tunnelKey(config) ? "cloudflare" : null);
const SOURCE_NAME = { caddy: "Caddy routes", cloudflare: "Cloudflare tunnel and Access settings" };
const ISSUE_KINDS = ["dangling_route", "upstream_not_in_inventory", "upstream_unresolvable", "restriction_bypassed_by_tunnel"];
const list = (items, max = 6) => `${items.slice(0, max).join("; ")}${items.length > max ? `; and ${items.length - max} more` : ""}`;
const notEntry = () => "only applies to the machines public traffic enters through";

export const exposureRoutes = {
  id: "exposure_routes",
  title: "Public routes resolve to known, running services",
  requires: ["exposure.map"],
  appliesTo: (asset, config) => originOf(asset, config) != null,
  notApplicableReason: notEntry,
  evaluate({ "exposure.map": map }, { asset, config }) {
    const origin = originOf(asset, config);
    const { services = [], problems = [], sources = {} } = map.value;
    const mine = problems.filter((p) => p.origin === origin);
    const issues = mine.filter((p) => ISSUE_KINDS.includes(p.kind));
    if (issues.length) return result("issue", list(issues.map((p) => `${p.hostname ?? "(no hostname)"}: ${p.reason}`)));
    if (sources[origin] !== "ok") return result("unknown", `${SOURCE_NAME[origin]} are ${sources[origin] ?? "missing"}; routes can't be checked`);
    const blocked = mine.filter((p) => p.kind === "unsupported_condition");
    if (blocked.length) return result("unknown", list(blocked.map((p) => `${p.hostname ?? "(no hostname)"}: ${p.reason}`)));
    const entries = origin === "caddy" ? ["forward", "tunnel-via-caddy"] : ["tunnel-direct", "tunnel-via-caddy"];
    const hostnames = new Set(services.filter((s) => (s.paths ?? []).some((p) => p.reachable === true && entries.includes(p.entry))).map((s) => s.hostname));
    return result("ok", `${hostnames.size} public hostname${hostnames.size === 1 ? "" : "s"}, every route resolved`);
  }
};

export const exposureGates = {
  id: "exposure_gates",
  title: "Login gates in front of public routes are verified",
  requires: ["exposure.map"],
  appliesTo: (asset, config) => originOf(asset, config) === "caddy",
  notApplicableReason: notEntry,
  evaluate({ "exposure.map": map }) {
    const { services = [], sources = {} } = map.value;
    if (sources.caddy !== "ok") return result("unknown", `Caddy routes are ${sources.caddy ?? "missing"}; gates can't be checked`);
    const reachable = services.filter((s) => s.exposure !== "lan");
    const unverified = reachable.filter((s) => s.gate === "unknown");
    if (unverified.length) return result("unknown", `gate not verified for: ${list(unverified.map((s) => `${s.hostname}${s.path ? ` ${s.path}` : ""} (${s.gateReason ?? "reason not recorded"})`))}`);
    const verified = reachable.filter((s) => ["authentik", "cloudflare-access", "verified-mixed"].includes(s.gate)).length;
    return result("ok", `${verified} gated route${verified === 1 ? "" : "s"} verified`);
  }
};

export const exposureExpectedPrivate = {
  id: "exposure_expected_private",
  title: "Sites meant to be private aren't reachable from the internet",
  requires: ["exposure.map"],
  appliesTo: (asset, config) => originOf(asset, config) === "caddy" && (config.exposure.expectedPrivate ?? []).length > 0,
  notApplicableReason: (asset, config) => (originOf(asset, config) === "caddy" ? "no hostnames are listed as expected private" : notEntry()),
  evaluate({ "exposure.map": map }, { config }) {
    const { services = [], sources = {} } = map.value;
    const expected = config.exposure.expectedPrivate.map((h) => h.toLowerCase());
    const of = (h) => services.filter((s) => s.hostname === h);
    const exposed = expected.filter((h) => of(h).some((s) => s.exposure === "internet"));
    if (exposed.length) return result("issue", `reachable from the internet: ${list(exposed)}`);
    const sourcesOk = sources.caddy === "ok" && sources.cloudflare === "ok";
    const unsure = expected.filter((h) => of(h).some((s) => s.exposure === "unknown") || (!sourcesOk && of(h).every((s) => s.exposure !== "internet")));
    if (unsure.length) return result("unknown", `can't establish whether these are private: ${list(unsure)}`);
    return result("ok", `${expected.length} expected-private hostname${expected.length === 1 ? "" : "s"} not reachable from the internet`);
  }
};
