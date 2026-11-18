// Joins the three views of "how can the internet reach this?" — router
// forwards (declared), Cloudflare tunnel rules and Caddy routes — into one
// list of public services and a verdict per machine. Pure: same inputs, same
// answer. Anything it can't establish stays "unknown"; nothing becomes "lan"
// unless every way in has been ruled out.
import { resolveCaddyRoutes, evalRestriction, hostMatch } from "./caddy-routes.mjs";
import { accessProtection } from "../collectors/cloudflare.mjs";
import { listenerMatch } from "./listeners.mjs";
import { PUBLIC_VISITOR, inRanges, isPrivateRange, isValidRange, parseV4 } from "./ip.mjs";

// The address Caddy's client_ip matcher sees, following Caddy's own rules.
export function clientIpFor(path, clientIp, config) {
  const peer = path === "forward" ? PUBLIC_VISITOR : config.connectorAddress;
  const trusted = clientIp?.trustedProxies;
  if (!trusted) return peer; // 1. no trusted proxies: the peer's own address
  if (trusted.source !== "static" || !Array.isArray(trusted.ranges)) return "unknown";
  const ranges = trusted.ranges;
  if (ranges.some((r) => !isValidRange(r) || !isPrivateRange(r))) return "unknown"; // can't evaluate, or public space is trusted
  if (path === "forward" || !inRanges(peer, ranges)) return peer; // 1. peer not trusted
  const allow = (config.trustedClientIpHeaders ?? []).map((h) => h.toLowerCase());
  const headers = Array.isArray(clientIp.headers) ? clientIp.headers.map((h) => String(h).toLowerCase()) : [];
  const proxySet = headers.length === 1 && allow.includes(headers[0]);
  // Strict mode picks the right-most untrusted X-Forwarded-For address; with
  // any other header a visitor can set the value themselves.
  const strict = clientIp.strict === true && (headers.length === 0 || (headers.length === 1 && headers[0] === "x-forwarded-for"));
  return proxySet || strict ? PUBLIC_VISITOR : "unknown"; // 2. reliable, else 3.
}

const DEFAULT_PORTS = { "http:": 80, "https:": 443, "ssh:": 22, "rdp:": 3389, "smb:": 445 };
function parseService(service, connectorAddress) {
  const text = String(service ?? "");
  if (/^http_status:\d+$/u.test(text) || text === "hello_world") return { kind: "none" };
  let url;
  try { url = new URL(text); } catch { return { kind: "unknown" }; }
  const port = url.port ? Number(url.port) : DEFAULT_PORTS[url.protocol];
  if (!url.hostname || !port) return { kind: "unknown" };
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  return { kind: "url", host: loopback ? connectorAddress : url.hostname, port, loopback };
}
const LOOPBACK_NAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
function parseDial(dial) {
  const m = /^(?:[a-z]+:\/\/)?([^/:]+):(\d+)$/iu.exec(String(dial ?? ""));
  return m ? { host: m[1], port: Number(m[2]) } : null;
}
// Does a Caddy server listen on this TCP/UDP port? true | false | "unknown".
function listensOn(listen, port) {
  if (!Array.isArray(listen) || listen.length === 0) return "unknown";
  let unsure = false;
  for (const raw of listen) {
    const text = String(raw).replace(/^(?:tcp|udp)[46]?\//u, "");
    if (/^unix/u.test(text)) continue; // a socket file isn't reachable from the network
    const spec = text.slice(text.lastIndexOf(":") + 1);
    const range = /^(\d+)(?:-(\d+))?$/u.exec(spec);
    if (!range) { unsure = true; continue; }
    const lo = Number(range[1]), hi = Number(range[2] ?? range[1]);
    if (port >= lo && port <= hi) return true;
  }
  return unsure ? "unknown" : false;
}
// The Access path to judge for a Caddy path pattern: its literal prefix, or
// the whole host when the pattern can't be read as one.
const accessPath = (pattern) => {
  if (pattern == null) return null;
  const text = String(pattern);
  if (text.includes(" & ") || /\*./u.test(text)) return null;
  return text.replace(/\*+$/u, "") || null;
};
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

export function resolveExposure({ caddy, cloudflare, router, assets = [], listeners = () => undefined, inventory = "ok", config }) {
  const sources = { caddy: caddy?.status ?? "missing", cloudflare: cloudflare?.status ?? "missing", router: "declared", inventory };
  const caddyOk = sources.caddy === "ok";
  const cfOk = sources.cloudflare === "ok";
  const caddyAddr = config?.caddy?.address ?? null;
  const caddyKey = config?.caddy?.assetKey ?? null;
  const cfg = { connectorAddress: config?.cloudflare?.connectorAddress ?? null, trustedClientIpHeaders: config?.caddy?.trustedClientIpHeaders ?? [] };
  const forwards = Array.isArray(router?.portForwards) ? router.portForwards : null;
  const dmzHost = typeof router?.dmz === "string" ? router.dmz : null;
  const problems = [];
  const problem = (kind, p, origin = "caddy") => problems.push({ kind, origin, hostname: null, upstream: null, assetKey: null, ...p });
  if (!caddyOk) problem("source_unreadable", { reason: `Caddy routes are ${sources.caddy}; exposure through Caddy is unknown` });
  if (!cfOk) problem("source_unreadable", { reason: `Cloudflare tunnel and Access settings are ${sources.cloudflare}; exposure through the tunnel is unknown` }, "cloudflare");

  const byIp = new Map();
  for (const a of assets) for (const ip of a.ips ?? []) byIp.set(ip, [...(byIp.get(ip) ?? []), a.assetKey]);
  const apps = cfOk ? cloudflare.apps : undefined;
  // The machine running a tunnel's cloudflared: its own address if configured, else the default.
  const connectorFor = (tunnelId) => config?.cloudflare?.connectors?.[tunnelId] ?? cfg.connectorAddress;
  const rules = cfOk ? (cloudflare.tunnels ?? []).flatMap((t) => (t.ingress ?? []).map((r) => ({ ...r, connector: connectorFor(t.id) })))
    .map((r) => ({ ...r, target: parseService(r.service, r.connector) })) : [];
  const toCaddy = rules.filter((r) => r.target.kind === "url" && r.target.host === caddyAddr);
  // A rule whose target is a name (or unreadable) might be Caddy too.
  const maybeCaddy = rules.filter((r) => r.target.kind === "unknown" || (r.target.kind === "url" && parseV4(r.target.host) == null));
  const accessGate = (hostname, path) => {
    const p = hostname == null ? "unknown" : accessProtection(hostname, path, apps);
    return p === "protected" ? "cloudflare-access" : p === "unknown" ? "unknown" : "none";
  };

  // 1. Services that answer through Caddy.
  const drafts = [];
  const entries = caddyOk ? resolveCaddyRoutes(caddy.shape) : { entries: [], problems: [] };
  for (const text of entries.problems) problem("unsupported_condition", { reason: text });
  for (const e of entries.entries) {
    const paths = [];
    const forwardReach = () => evalRestriction(e.restriction, { remoteIp: PUBLIC_VISITOR, clientIp: clientIpFor("forward", e.clientIp, cfg) });
    const forwarded = (forwards ?? []).filter((f) => f.lanIp === caddyAddr).map((f) => listensOn(e.listen, f.lanPort));
    if (forwards === null) paths.push({ entry: "forward", reachable: "unknown", gate: e.gate, gateReason: "router port forwards aren't declared" });
    else if (forwarded.includes(true) || (dmzHost && dmzHost === caddyAddr && listensOn(e.listen, 443) !== false)) paths.push({ entry: "forward", reachable: forwardReach(), gate: e.gate, gateReason: e.gateReason });
    else if (forwarded.includes("unknown")) {
      const r = forwardReach();
      paths.push({ entry: "forward", reachable: r === false ? false : "unknown", gate: e.gate, gateReason: e.gateReason ?? "the server's listen address can't be read" });
    }
    const viaTunnel = [];
    if (!cfOk) paths.push({ entry: "tunnel-via-caddy", reachable: "unknown", gate: e.gate === "authentik" ? "authentik" : "unknown", gateReason: "Cloudflare settings not readable" });
    else for (const r of [...toCaddy, ...maybeCaddy]) {
      if (!hostsMeet(r.hostHeader ?? r.hostname, e.hostname)) continue;
      const maybe = maybeCaddy.includes(r);
      const listening = maybe ? "unknown" : listensOn(e.listen, r.target.port);
      if (listening === false) continue;
      // Access is judged on the name the visitor used: the entry's own when concrete.
      const name = e.hostname !== "*" && !e.hostname.includes("*") ? e.hostname : r.hostname;
      const access = accessGate(name, accessPath(e.path));
      const gate = access === "cloudflare-access" ? access : e.gate === "authentik" ? "authentik" : access === "unknown" || e.gate === "unknown" ? "unknown" : "none";
      const evaluated = evalRestriction(e.restriction, { remoteIp: r.connector, clientIp: clientIpFor("tunnel-via-caddy", e.clientIp, { ...cfg, connectorAddress: r.connector }) });
      const reachable = listening === true ? evaluated : evaluated === false ? false : "unknown";
      viaTunnel.push(r);
      const why = maybe ? `tunnel rule to ${r.service} may lead into Caddy` : e.gate === "unknown" ? e.gateReason : "Cloudflare Access policy can't be verified";
      paths.push({ entry: "tunnel-via-caddy", reachable, gate, gateReason: gate === "unknown" ? why : null });
    }
    drafts.push({ entry: e, hostname: e.hostname, path: e.path, paths, tunnelRules: viaTunnel, upstream: e.answer.kind === "proxy" ? e.answer.upstream : null });
  }
  for (const r of toCaddy) {
    if (caddyOk && !entries.entries.some((e) => listensOn(e.listen, r.target.port) !== false)) problem("unsupported_condition", { hostname: r.hostname, reason: `a tunnel rule points at Caddy port ${r.target.port}, which isn't in the route shape` }, "cloudflare");
  }

  // 2. Services a tunnel reaches directly, bypassing Caddy.
  for (const r of rules) {
    if (r.target.kind === "none" || toCaddy.includes(r)) continue;
    const hostname = r.hostname ?? "*";
    if (r.target.kind === "unknown") {
      problem("upstream_unresolvable", { hostname, upstream: r.service, reason: "tunnel service isn't a recognised address" }, "cloudflare");
      drafts.push({ entry: null, hostname, path: r.path ?? null, paths: [{ entry: "tunnel-direct", reachable: true, gate: accessGate(r.hostname, null), gateReason: null }], tunnelRules: [r], upstream: null, unresolved: r.service });
      continue;
    }
    const upstream = r.target.loopback ? `127.0.0.1:${r.target.port}` : `${r.target.host}:${r.target.port}`;
    // Ingress paths are regular expressions: judge Access on the whole host.
    const gate = accessGate(r.hostname, null);
    const path = { entry: "tunnel-direct", reachable: true, gate, gateReason: gate === "unknown" ? "Cloudflare Access policy can't be verified" : null };
    const same = drafts.filter((d) => d.entry && d.hostname === hostname && d.upstream === upstream);
    if (same.length) for (const d of same) { d.paths.push(path); d.tunnelRules.push(r); }
    else drafts.push({ entry: null, hostname, path: r.path ?? null, paths: [path], tunnelRules: [r], upstream, loopbackOwner: r.connector });
  }

  // 3. Finish each service: exposure, effective gate, machine, listener.
  const gateMachines = new Map(); // assetKey -> strongest exposure of a service it gates
  const rank = { lan: 0, unknown: 1, internet: 2 };
  const stronger = (a, b) => (a == null || rank[b] > rank[a] ? b : a);
  const services = drafts.map((d) => {
    const e = d.entry;
    const origin = e ? "caddy" : "cloudflare";
    const problem = (kind, p, from = origin) => problems.push({ kind, origin: from, hostname: null, upstream: null, assetKey: null, ...p });
    const reach = d.paths.map((p) => p.reachable);
    const exposure = reach.includes(true) ? "internet" : reach.includes("unknown") || e?.conditions === "unknown" ? "unknown" : "lan";
    const { gate, gateReason } = effectiveGate(d.paths, { gate: e?.gate ?? "none", gateReason: e?.gateReason });

    let assetKey = null, listening = null, process = null, container = null;
    const base = { hostname: d.hostname, upstream: d.upstream ?? d.unresolved ?? null };
    if (e && e.answer.kind === "static") assetKey = caddyKey;
    else if (e && e.answer.kind === "unknown") problem("unsupported_condition", { ...base, reason: e.answer.reason });
    else if (d.upstream) {
      const dial = parseDial(d.upstream);
      // A loopback upstream is the machine that dials it: Caddy, or cloudflared.
      const loopback = dial && LOOPBACK_NAMES.has(dial.host.toLowerCase());
      const ip = loopback ? (e ? caddyAddr : d.loopbackOwner) : dial?.host;
      if (!dial || parseV4(ip) == null) problem("upstream_unresolvable", { ...base, reason: "upstream is a name, not an address; the engine doesn't resolve names" });
      else {
        const owners = byIp.get(ip) ?? [];
        if (owners.length === 0) problem("upstream_not_in_inventory", { ...base, reason: `no known machine has the address ${ip}` });
        else if (owners.length > 1) problem("upstream_unresolvable", { ...base, reason: `${ip} belongs to ${owners.length} machines in the inventory` });
        else {
          assetKey = owners[0];
          ({ listening, process, container } = listenerMatch({ ip: loopback ? "127.0.0.1" : ip, port: dial.port, protocol: "tcp" }, listeners(assetKey)));
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
      problem("restriction_bypassed_by_tunnel", { ...base, assetKey, reason: "the route's address restriction doesn't stop requests arriving through the Cloudflare tunnel" }, "cloudflare");
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
  if (inventory !== "ok") undeclared.push(`the machine inventory is ${inventory}`);
  if (forwards === null) undeclared.push("port forwards not declared");
  if (router?.upnp !== false) undeclared.push(router?.upnp === true ? "UPnP is on" : "UPnP not declared");
  if (router?.dmz !== false && !dmzHost) undeclared.push(router?.dmz === true ? "a DMZ host is set" : "DMZ not declared");
  if (router?.ipv6Inbound !== false) undeclared.push(router?.ipv6Inbound === true ? "inbound IPv6 is allowed" : "inbound IPv6 not declared");
  const baseline = undeclared.length ? { exposure: "unknown", reason: `can't rule out other ways in: ${undeclared.join(", ")}` } : { exposure: "lan", reason: "no public route, forward or tunnel reaches this machine" };

  // Public ways in whose target isn't a machine the engine can name. While
  // any exist, a machine whose own address is unknown might be that target.
  const stray = [];
  for (const f of forwards ?? []) {
    if (f.lanIp === caddyAddr || byIp.has(f.lanIp)) continue;
    stray.push(`router forward to ${f.lanIp}:${f.lanPort}`);
    problem("upstream_not_in_inventory", { upstream: `${f.lanIp}:${f.lanPort}`, reason: `the router forwards port ${f.wanPort} to ${f.lanIp}, an address no known machine has` }, "router");
  }
  if (dmzHost && dmzHost !== caddyAddr && !byIp.has(dmzHost)) {
    stray.push(`router DMZ to ${dmzHost}`);
    problem("upstream_not_in_inventory", { upstream: dmzHost, reason: `the router's DMZ points at ${dmzHost}, an address no known machine has` }, "router");
  }
  for (const [i, s] of services.entries()) {
    if (s.exposure === "lan" || s.assetKey != null) continue;
    const e = drafts[i].entry;
    stray.push(`${s.hostname} -> ${s.upstream ?? drafts[i].unresolved ?? (e?.answer.kind === "unknown" ? e.answer.reason : "unknown target")}`);
  }

  const machines = new Map();
  for (const a of assets) {
    const ips = a.ips ?? [];
    const mine = services.map((s, i) => ({ s, i })).filter(({ s }) => s.assetKey === a.assetKey);
    const directForwards = (forwards ?? []).filter((f) => ips.includes(f.lanIp) && f.lanIp !== caddyAddr).map((f) => ({ wanPort: f.wanPort, lanPort: f.lanPort, protocol: f.protocol }));
    const isDmz = dmzHost != null && ips.includes(dmzHost) && dmzHost !== caddyAddr;
    let exposure = baseline.exposure, reason = baseline.reason, role = null;
    const raise = (to, why) => { if (rank[to] > rank[exposure]) { exposure = to; reason = why; } };
    // A public way in whose target can't be named could be any machine.
    if (stray.length) raise("unknown", `${stray.length === 1 ? "a public route" : `${stray.length} public routes`} can't be traced to a machine (${stray[0]}), so this machine can't be ruled out`);
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
