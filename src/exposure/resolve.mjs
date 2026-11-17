// Joins the three views of "how can the internet reach this?" — router
// forwards (declared), Cloudflare tunnel rules and Caddy routes — into one
// list of public services and a verdict per machine. Pure: same inputs, same
// answer. Anything it can't establish stays "unknown"; nothing becomes "lan"
// unless every way in has been ruled out.
import { resolveCaddyRoutes, evalRestriction, hostMatch } from "./caddy-routes.mjs";
import { accessProtection } from "../collectors/cloudflare.mjs";
import { listenerMatch } from "./listeners.mjs";
import { PUBLIC_VISITOR, inRanges, isPrivateRange, parseRange, parseV4 } from "./ip.mjs";

// The address Caddy's client_ip matcher sees, following Caddy's own rules.
export function clientIpFor(path, clientIp, config) {
  const peer = path === "forward" ? PUBLIC_VISITOR : config.connectorAddress;
  const trusted = clientIp?.trustedProxies;
  if (!trusted) return peer; // 1. no trusted proxies: the peer's own address
  if (trusted.source !== "static" || !Array.isArray(trusted.ranges)) return "unknown";
  const v4 = trusted.ranges.filter((r) => !String(r).includes(":")); // IPv6 ranges can't contain an IPv4 peer
  if (v4.some((r) => parseRange(r) == null || !isPrivateRange(r))) return "unknown"; // can't evaluate, or public space is trusted
  if (path === "forward" || !inRanges(peer, v4)) return peer; // 1. peer not trusted
  const allow = (config.trustedClientIpHeaders ?? []).map((h) => h.toLowerCase());
  const headers = clientIp.headers;
  const proxySet = Array.isArray(headers) && headers.length === 1 && allow.includes(String(headers[0]).toLowerCase());
  return proxySet || clientIp.strict === true ? PUBLIC_VISITOR : "unknown"; // 2. reliable, else 3.
}

const DEFAULT_PORTS = { "http:": 80, "https:": 443, "ssh:": 22, "rdp:": 3389, "smb:": 445 };
function parseService(service, connectorAddress) {
  const text = String(service ?? "");
  if (/^http_status:\d+$/u.test(text) || text === "hello_world") return { kind: "none" };
  let url;
  try { url = new URL(text); } catch { return { kind: "unknown" }; }
  const port = url.port ? Number(url.port) : DEFAULT_PORTS[url.protocol];
  if (!url.hostname || !port) return { kind: "unknown" };
  const host = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ? connectorAddress : url.hostname;
  return { kind: "url", host, port };
}
function parseDial(dial) {
  const m = /^(?:[a-z]+:\/\/)?([^/:]+):(\d+)$/iu.exec(String(dial ?? ""));
  return m ? { host: m[1], port: Number(m[2]) } : null;
}
const listenPorts = (listen) => (listen ?? []).map((l) => Number(String(l).split(":").pop())).filter(Number.isInteger);
const accessPath = (pattern) => (pattern == null ? null : String(pattern).replace(/\*+$/u, "") || null);
const hostsMeet = (a, b) => a == null || b === "*" || hostMatch(a, b) || hostMatch(b, a);
const VERIFIED = new Set(["authentik", "cloudflare-access"]);

function effectiveGate(paths, fallback) {
  const live = paths.filter((p) => p.reachable !== false);
  if (!live.length) return { gate: fallback.gate, gateReason: fallback.gateReason ?? "no public path reaches this route" };
  const open = live.find((p) => p.gate === "none");
  if (open) return { gate: "none", gateReason: `no login gate on the ${open.entry} path` };
  const unsure = live.find((p) => p.gate === "unknown");
  if (unsure) return { gate: "unknown", gateReason: `${unsure.gateReason ?? "gate not verified"} (${unsure.entry} path)` };
  const kinds = [...new Set(live.map((p) => p.gate))];
  return { gate: kinds.length === 1 ? kinds[0] : "verified-mixed", gateReason: null };
}

export function resolveExposure({ caddy, cloudflare, router, assets = [], listeners = () => undefined, config }) {
  const sources = { caddy: caddy?.status ?? "missing", cloudflare: cloudflare?.status ?? "missing", router: "declared" };
  const caddyOk = sources.caddy === "ok";
  const cfOk = sources.cloudflare === "ok";
  const caddyAddr = config?.caddy?.address ?? null;
  const caddyKey = config?.caddy?.assetKey ?? null;
  const cfg = { connectorAddress: config?.cloudflare?.connectorAddress ?? null, trustedClientIpHeaders: config?.caddy?.trustedClientIpHeaders ?? [] };
  const forwards = Array.isArray(router?.portForwards) ? router.portForwards : null;
  const dmzHost = typeof router?.dmz === "string" ? router.dmz : null;
  const problems = [];
  const problem = (kind, p) => problems.push({ kind, hostname: null, upstream: null, assetKey: null, ...p });
  if (!caddyOk) problem("source_unreadable", { reason: `Caddy routes are ${sources.caddy}; exposure through Caddy is unknown` });
  if (!cfOk) problem("source_unreadable", { reason: `Cloudflare tunnel and Access settings are ${sources.cloudflare}; exposure through the tunnel is unknown` });

  const byIp = new Map();
  for (const a of assets) for (const ip of a.ips ?? []) byIp.set(ip, [...(byIp.get(ip) ?? []), a.assetKey]);
  const apps = cfOk ? cloudflare.apps : undefined;
  const rules = cfOk ? (cloudflare.tunnels ?? []).flatMap((t) => t.ingress ?? []).map((r) => ({ ...r, target: parseService(r.service, cfg.connectorAddress) })) : [];
  const toCaddy = rules.filter((r) => r.target.kind === "url" && r.target.host === caddyAddr);
  const accessGate = (hostname, path) => {
    const p = hostname == null ? "unknown" : accessProtection(hostname, path, apps);
    return p === "protected" ? "cloudflare-access" : p === "unknown" ? "unknown" : "none";
  };

  // 1. Services that answer through Caddy.
  const drafts = [];
  const entries = caddyOk ? resolveCaddyRoutes(caddy.shape) : { entries: [], problems: [] };
  for (const text of entries.problems) problem("unsupported_condition", { reason: text });
  for (const e of entries.entries) {
    const ports = listenPorts(e.listen);
    const paths = [];
    if (forwards === null) paths.push({ entry: "forward", reachable: "unknown", gate: e.gate, gateReason: "router port forwards aren't declared" });
    else if (forwards.some((f) => f.protocol === "tcp" && f.lanIp === caddyAddr && ports.includes(f.lanPort)) || (dmzHost && dmzHost === caddyAddr)) {
      paths.push({ entry: "forward", reachable: evalRestriction(e.restriction, { remoteIp: PUBLIC_VISITOR, clientIp: clientIpFor("forward", e.clientIp, cfg) }), gate: e.gate, gateReason: e.gateReason });
    }
    const viaTunnel = [];
    if (!cfOk) paths.push({ entry: "tunnel-via-caddy", reachable: "unknown", gate: e.gate === "authentik" ? "authentik" : "unknown", gateReason: "Cloudflare settings not readable" });
    else for (const r of toCaddy) {
      if (!ports.includes(r.target.port) || !hostsMeet(r.hostHeader ?? r.hostname, e.hostname)) continue;
      const access = accessGate(r.hostname, accessPath(e.path));
      const gate = access === "cloudflare-access" ? access : e.gate === "authentik" ? "authentik" : access === "unknown" || e.gate === "unknown" ? "unknown" : "none";
      const reachable = evalRestriction(e.restriction, { remoteIp: cfg.connectorAddress, clientIp: clientIpFor("tunnel-via-caddy", e.clientIp, cfg) });
      viaTunnel.push(r);
      paths.push({ entry: "tunnel-via-caddy", reachable, gate, gateReason: gate === "unknown" ? (e.gate === "unknown" ? e.gateReason : "Cloudflare Access policy can't be verified") : null });
    }
    drafts.push({ entry: e, hostname: e.hostname, path: e.path, paths, tunnelRules: viaTunnel, upstream: e.answer.kind === "proxy" ? e.answer.upstream : null });
  }
  for (const r of toCaddy) {
    const ports = new Set(entries.entries.flatMap((e) => listenPorts(e.listen)));
    if (caddyOk && !ports.has(r.target.port)) problem("unsupported_condition", { hostname: r.hostname, reason: `a tunnel rule points at Caddy port ${r.target.port}, which isn't in the route shape` });
  }

  // 2. Services a tunnel reaches directly, bypassing Caddy.
  for (const r of rules) {
    if (r.target.kind === "none" || toCaddy.includes(r)) continue;
    const hostname = r.hostname ?? "*";
    if (r.target.kind === "unknown") {
      problem("upstream_unresolvable", { hostname, upstream: r.service, reason: "tunnel service isn't a recognised address" });
      drafts.push({ entry: null, hostname, path: r.path ?? null, paths: [{ entry: "tunnel-direct", reachable: true, gate: accessGate(r.hostname, r.path ?? null), gateReason: null }], tunnelRules: [r], upstream: null, unresolved: r.service });
      continue;
    }
    const upstream = `${r.target.host}:${r.target.port}`;
    const gate = accessGate(r.hostname, r.path ?? null);
    const path = { entry: "tunnel-direct", reachable: true, gate, gateReason: gate === "unknown" ? "Cloudflare Access policy can't be verified" : null };
    const same = drafts.filter((d) => d.entry && d.hostname === hostname && d.upstream === upstream);
    if (same.length) for (const d of same) { d.paths.push(path); d.tunnelRules.push(r); }
    else drafts.push({ entry: null, hostname, path: r.path ?? null, paths: [path], tunnelRules: [r], upstream });
  }

  // 3. Finish each service: exposure, effective gate, machine, listener.
  const gateMachines = new Map(); // assetKey -> strongest exposure of a service it gates
  const rank = { lan: 0, unknown: 1, internet: 2 };
  const stronger = (a, b) => (a == null || rank[b] > rank[a] ? b : a);
  const services = drafts.map((d) => {
    const e = d.entry;
    const reach = d.paths.map((p) => p.reachable);
    const exposure = reach.includes(true) ? "internet" : reach.includes("unknown") || e?.conditions === "unknown" ? "unknown" : "lan";
    const { gate, gateReason } = effectiveGate(d.paths, { gate: e?.gate ?? "none", gateReason: e?.gateReason });

    let assetKey = null, listening = null, process = null, container = null;
    const base = { hostname: d.hostname, upstream: d.upstream ?? d.unresolved ?? null };
    if (e && e.answer.kind === "static") assetKey = caddyKey;
    else if (e && e.answer.kind === "unknown") problem("unsupported_condition", { ...base, reason: e.answer.reason });
    else if (d.upstream) {
      const dial = parseDial(d.upstream);
      const ip = dial && ["localhost", "127.0.0.1"].includes(dial.host) && e ? caddyAddr : dial?.host;
      if (!dial || parseV4(ip) == null) problem("upstream_unresolvable", { ...base, reason: "upstream is a name, not an address; the engine doesn't resolve names" });
      else {
        const owners = byIp.get(ip) ?? [];
        if (owners.length === 0) problem("upstream_not_in_inventory", { ...base, reason: `no known machine has the address ${ip}` });
        else if (owners.length > 1) problem("upstream_unresolvable", { ...base, reason: `${ip} belongs to ${owners.length} machines in the inventory` });
        else {
          assetKey = owners[0];
          ({ listening, process, container } = listenerMatch({ ip, port: dial.port, protocol: "tcp" }, listeners(assetKey)));
          if (listening === false) problem("dangling_route", { ...base, assetKey, reason: `nothing is listening on ${d.upstream}` });
        }
      }
    }
    if (e?.conditions === "unknown") problem("unsupported_condition", { ...base, assetKey, reason: e.conditionReason });
    if (e?.gate === "unknown") problem("unverified_gate", { ...base, assetKey, reason: e.gateReason });
    else if (gate === "unknown" && exposure !== "lan") problem("unverified_gate", { ...base, assetKey, reason: gateReason });
    const forward = d.paths.find((p) => p.entry === "forward");
    const tunnelled = d.paths.some((p) => p.entry === "tunnel-via-caddy" && p.reachable === true);
    if (e && e.restriction.op !== "true" && tunnelled && forward?.reachable !== true) {
      problem("restriction_bypassed_by_tunnel", { ...base, assetKey, reason: "the route's address restriction doesn't stop requests arriving through the Cloudflare tunnel" });
    }
    if (e?.gateUpstream && exposure !== "lan") {
      const dial = parseDial(e.gateUpstream);
      const owners = dial ? byIp.get(dial.host) ?? [] : [];
      if (owners.length === 1) gateMachines.set(owners[0], stronger(gateMachines.get(owners[0]), exposure));
    }

    const names = cfOk ? cloudflare.names ?? [] : null;
    const via = d.paths.filter((p) => p.reachable === true).map((p) => p.entry);
    const reason = exposure === "internet" ? `reachable from the internet through: ${[...new Set(via)].join(", ").replaceAll("tunnel-via-caddy", "Cloudflare tunnel → Caddy").replaceAll("tunnel-direct", "Cloudflare tunnel").replaceAll("forward", "router forward → Caddy")}`
      : exposure === "lan" ? (d.paths.length ? "every public path is blocked by the route's address restriction" : "no router forward or tunnel rule reaches this route")
        : "can't be established: " + ([...new Set(d.paths.filter((p) => p.reachable === "unknown").map((p) => p.gateReason && p.entry === "forward" && forwards === null ? p.gateReason : `${p.entry} path undetermined`)), ...(e?.conditions === "unknown" ? [e.conditionReason] : [])].join("; ") || "undetermined");
    return {
      hostname: d.hostname, path: d.path, paths: d.paths, gate, gateReason, upstream: d.upstream, assetKey, container, process, listening, exposure,
      publicDns: names == null || d.hostname === "*" ? null : names.some((n) => hostMatch(n, d.hostname)),
      jwtRequired: d.tunnelRules.length ? d.tunnelRules.every((r) => r.jwtRequired === true) : null,
      reason
    };
  });

  // 4. Machines.
  const undeclared = [];
  if (!caddyOk) undeclared.push(`Caddy routes ${sources.caddy}`);
  if (!cfOk) undeclared.push(`Cloudflare settings ${sources.cloudflare}`);
  if (forwards === null) undeclared.push("port forwards not declared");
  if (router?.upnp !== false) undeclared.push(router?.upnp === true ? "UPnP is on" : "UPnP not declared");
  if (router?.dmz !== false && !dmzHost) undeclared.push(router?.dmz === true ? "a DMZ host is set" : "DMZ not declared");
  if (router?.ipv6Inbound !== false) undeclared.push(router?.ipv6Inbound === true ? "inbound IPv6 is allowed" : "inbound IPv6 not declared");
  const baseline = undeclared.length ? { exposure: "unknown", reason: `can't rule out other ways in: ${undeclared.join(", ")}` } : { exposure: "lan", reason: "no public route, forward or tunnel reaches this machine" };

  const machines = new Map();
  for (const a of assets) {
    const ips = a.ips ?? [];
    const mine = services.map((s, i) => ({ s, i })).filter(({ s }) => s.assetKey === a.assetKey);
    const directForwards = (forwards ?? []).filter((f) => ips.includes(f.lanIp) && f.lanIp !== caddyAddr).map((f) => ({ wanPort: f.wanPort, lanPort: f.lanPort, protocol: f.protocol }));
    const isDmz = dmzHost != null && ips.includes(dmzHost) && dmzHost !== caddyAddr;
    let exposure = baseline.exposure, reason = baseline.reason, role = null;
    const raise = (to, why) => { if (rank[to] > rank[exposure]) { exposure = to; reason = why; } };
    for (const { s } of mine) if (s.exposure !== "lan") raise(s.exposure, s.exposure === "internet" ? `serves ${s.hostname}, which is reachable from the internet` : `serves ${s.hostname}, whose exposure can't be established`);
    if (mine.some(({ s }) => s.exposure !== "lan")) role = "app";
    if (directForwards.length || isDmz) {
      role = "direct";
      raise("internet", isDmz ? "the router's DMZ points at this machine" : `the router forwards port ${directForwards.map((f) => f.wanPort).join(", ")} straight to this machine`);
    }
    if (gateMachines.has(a.assetKey)) { role = "gate"; raise(gateMachines.get(a.assetKey), "runs the login gate in front of public services"); }
    if (a.assetKey === caddyKey) {
      role = "entry";
      const fed = (forwards ?? []).some((f) => f.lanIp === caddyAddr) || dmzHost === caddyAddr || toCaddy.length > 0;
      if (fed) raise("internet", "public traffic enters the lab through this machine");
    }
    machines.set(a.assetKey, { exposure, role, services: mine.map(({ i }) => i), directForwards, reason });
  }
  return { services, machines, problems, sources };
}
