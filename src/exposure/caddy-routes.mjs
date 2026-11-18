// Works out, from the Caddy route shape, what answers a request for each
// hostname and path, whether a verified login gate runs first, and which
// source-address conditions apply. It follows Caddy's own rules: matcher sets
// are ORed, matchers in a set are ANDed, routes run in order, `terminal` stops
// the list, and routes sharing a group are mutually exclusive.
import { inRanges, isPrivateRange, isValidRange, PUBLIC_VISITOR } from "./ip.mjs";

const T = { op: "true" };
const F = { op: "false" };
const isT = (e) => e.op === "true";
const isF = (e) => e.op === "false";

function not(e) {
  if (isT(e)) return F;
  if (isF(e)) return T;
  if (e.op === "unknown") return e;
  return { op: "not", arg: e };
}
function and(list) {
  const args = [];
  for (const e of list) {
    if (isF(e)) return F;
    if (isT(e)) continue;
    if (e.op === "and") args.push(...e.args); else args.push(e);
  }
  return args.length === 0 ? T : args.length === 1 ? args[0] : { op: "and", args };
}
function or(list) {
  const args = [];
  for (const e of list) {
    if (isT(e)) return T;
    if (isF(e)) continue;
    if (e.op === "or") args.push(...e.args); else args.push(e);
  }
  return args.length === 0 ? F : args.length === 1 ? args[0] : { op: "or", args };
}
function findUnknown(e) {
  if (e.op === "unknown") return e;
  for (const child of e.args ?? (e.arg ? [e.arg] : [])) { const u = findUnknown(child); if (u) return u; }
  return null;
}

// Three-valued (Kleene) evaluation of a source-address condition.
export function evalRestriction(expr, { remoteIp, clientIp }) {
  const ranged = (ip, ranges) => {
    if (ip === "unknown" || ip == null || !Array.isArray(ranges)) return "unknown";
    const valid = ranges.every(isValidRange);
    // Some public visitor matches unless every range is private address space.
    if (ip === PUBLIC_VISITOR) return valid && ranges.every(isPrivateRange) ? false : "unknown";
    if (inRanges(ip, ranges)) return true;
    return valid ? false : "unknown";
  };
  switch (expr?.op) {
    case "true": return true;
    case "false": return false;
    case "remote_ip": return ranged(remoteIp, expr.ranges);
    case "client_ip": return ranged(clientIp, expr.ranges);
    case "not": { const v = evalRestriction(expr.arg, { remoteIp, clientIp }); return v === "unknown" ? v : !v; }
    case "and": { const vs = expr.args.map((a) => evalRestriction(a, { remoteIp, clientIp })); return vs.includes(false) ? false : vs.includes("unknown") ? "unknown" : true; }
    case "or": { const vs = expr.args.map((a) => evalRestriction(a, { remoteIp, clientIp })); return vs.includes(true) ? true : vs.includes("unknown") ? "unknown" : false; }
    default: return "unknown";
  }
}

const AUTH_PREFIX = "/outpost.goauthentik.io/auth/";
const subset = (list, allowed) => Array.isArray(list) && list.every((x) => allowed.includes(x));
const successOnly = (codes) => Array.isArray(codes) && codes.length > 0 && codes.every((c) => c === 2 || (Number.isInteger(c) && c >= 200 && c <= 299));

// A reverse_proxy with handle_response is a gate candidate. It is a verified
// Authentik gate only in the one shape where Caddy continues on a 2xx answer
// from Authentik and returns every other answer to the visitor.
export function classifyGate(handler) {
  if (handler?.handler !== "reverse_proxy" || handler.handleResponse === undefined) return null;
  const responses = handler.handleResponse;
  if (typeof handler.rewrite !== "string" || !handler.rewrite.startsWith(AUTH_PREFIX)) return "unknown";
  if (!Array.isArray(responses) || responses.length !== 1) return "unknown";
  const r = responses[0];
  const verified = successOnly(r.statusCodes) && Array.isArray(r.unsupportedMatch) && r.unsupportedMatch.length === 0 && r.setsStatus === false
    && subset(r.handlers, ["headers", "vars"]) && subset(r.innerMatchers, ["not"]);
  return verified ? "authentik" : "unknown";
}

// Handlers that neither answer nor decide who does.
const PASS_THROUGH = ["headers", "encode", "vars"];
const MAX_OUTCOMES = 64;
const MAX_STEPS = 50_000;

function globMatch(pattern, text) {
  const p = String(pattern).toLowerCase();
  const t = String(text).toLowerCase();
  if (!p.includes("*")) return p === t;
  return new RegExp(`^${p.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/gu, "\\$&")).join(".*")}$`, "u").test(t);
}
export function hostMatch(pattern, host) {
  const p = String(pattern).toLowerCase();
  if (!p.includes("*")) return p === host;
  const a = p.split("."), b = host.split(".");
  return a.length === b.length && a.every((label, i) => label === "*" || label === b[i]);
}
const sampleHost = (name) => (name === "*" ? "hs-any-host.invalid" : name.replaceAll("*", "hs-wildcard"));
const OTHER_PATH = "/\u0001hs-any-other-path";
const samplePath = (pattern) => { const s = String(pattern).replaceAll("*", "hs-sample"); return s.startsWith("/") ? s : `/${s}`; };

// The source-address condition under which one matcher set matches this request.
function setExpr(set, req) {
  const parts = [];
  if (set.host && !set.host.some((h) => hostMatch(h, req.host))) return F;
  // After a rewrite the path a later matcher sees isn't the visitor's path.
  if (set.path && req.rewritten) parts.push({ op: "unknown", reason: "a path matcher runs after a rewrite, so it can't be evaluated" });
  else if (set.path && !set.path.some((p) => globMatch(p, req.path))) return F;
  if (set.remote_ip) parts.push({ op: "remote_ip", ranges: set.remote_ip.ranges ?? [] });
  if (set.client_ip) parts.push({ op: "client_ip", ranges: set.client_ip.ranges ?? [] });
  if (set.not) parts.push(not(or(set.not.map((inner) => setExpr(inner, req)))));
  if (set.unsupported?.length) parts.push({ op: "unknown", reason: `unsupported Caddy matcher: ${set.unsupported.join(", ")}` });
  return and(parts);
}
const matchExpr = (match, req) => (!Array.isArray(match) || match.length === 0 ? T : or(match.map((set) => setExpr(set, req))));

function walk(server, req) {
  const outcomes = [];
  let overflow = false;
  let steps = 0;
  const answer = ({ rewritten: _rewritten, answered: _answered, ...st }, ans) => { if (outcomes.length >= MAX_OUTCOMES) overflow = true; else outcomes.push({ ...st, answer: ans }); };
  const tooBig = () => { if (++steps > MAX_STEPS) overflow = true; return overflow; };

  function runHandlers(handlers, j, st, next) {
    if (tooBig()) return;
    if (j >= handlers.length) return next(st);
    const h = handlers[j];
    const rest = (s) => runHandlers(handlers, j + 1, s, next);
    if (h.handler === "subroute") return runList(h.routes ?? [], 0, st, new Set(), rest);
    if (PASS_THROUGH.includes(h.handler)) return rest(st);
    if (h.handler === "rewrite") return rest({ ...st, rewritten: true });
    if (h.handler === "static_response" || h.handler === "file_server") return answer(st, { kind: "static" });
    if (h.handler === "reverse_proxy") {
      const kind = classifyGate(h);
      if (kind === "authentik") return rest({ ...st, gate: "authentik", gateReason: null, gateUpstream: h.upstreams?.[0] ?? null });
      const upstreams = (h.upstreams ?? []).filter((u) => typeof u === "string" && u);
      if (kind === "unknown") {
        // Not a gate the engine can vouch for. Its upstream may answer the
        // request itself, or its handle_response may pass it on: both.
        const next2 = st.gate === "authentik" ? st : { ...st, gate: "unknown", gateReason: "a handle_response block doesn't match the verified Authentik pattern", gateUpstream: upstreams[0] ?? null };
        if (upstreams.length) for (const upstream of upstreams) answer(next2, { kind: "proxy", upstream });
        else answer(next2, { kind: "unknown", reason: "reverse_proxy without a fixed upstream" });
        return rest({ ...next2, answered: true });
      }
      if (!upstreams.length) return answer(st, { kind: "unknown", reason: "reverse_proxy without a fixed upstream" });
      for (const upstream of upstreams) answer(st, { kind: "proxy", upstream });
      return undefined;
    }
    return answer(st, { kind: "unknown", reason: `unrecognised Caddy handler ${h.handler ?? "(none)"}` });
  }

  function runList(routes, i, st, groups, done) {
    if (tooBig()) return;
    if (i >= routes.length) return done(st);
    const r = routes[i];
    if (r.group && groups.has(r.group)) return runList(routes, i + 1, st, groups, done);
    const m = matchExpr(r.match, st.rewritten ? { ...req, rewritten: true } : req);
    const taken = and([st.cond, m]);
    if (!isF(taken)) {
      const after = r.group ? new Set([...groups, r.group]) : groups;
      runHandlers(r.handle ?? [], 0, { ...st, cond: taken }, (s) => (r.terminal ? done(s) : runList(routes, i + 1, s, after, done)));
    }
    const skipped = and([st.cond, not(m)]);
    if (!isF(skipped)) runList(routes, i + 1, { ...st, cond: skipped }, groups, done);
    return undefined;
  }

  // Falling off the end: Caddy answers an empty 200 itself. Only worth
  // reporting when an unverified gate ran and nothing else answered.
  const end = (st) => { if (st.gate === "unknown" && !st.answered) answer(st, { kind: "unknown", reason: "nothing answers after a handle_response block" }); };
  runList(server.routes ?? [], 0, { cond: T, gate: "none", gateReason: null, gateUpstream: null }, new Set(), end);
  return { outcomes, overflow };
}

function collect(routes, hosts, paths) {
  const sets = (list) => { for (const set of list ?? []) { set.host?.forEach((h) => hosts.add(String(h).toLowerCase())); set.path?.forEach((p) => paths.add(String(p))); sets(set.not); } };
  for (const r of routes ?? []) { sets(r.match); for (const h of r.handle ?? []) if (h.routes) collect(h.routes, hosts, paths); }
}

// Could some request path match both patterns? Only provably disjoint
// pairs (different literal prefixes or suffixes) are ruled out.
function disjoint(p, q) {
  const lit = (x) => x.split("*")[0].toLowerCase();
  const sfx = (x) => (x.includes("*") ? x.slice(x.lastIndexOf("*") + 1).toLowerCase() : x.toLowerCase());
  const [a, b] = [lit(p), lit(q)];
  if (a && b && !a.startsWith(b) && !b.startsWith(a)) return true;
  const [c, d] = [sfx(p), sfx(q)];
  return Boolean(c && d && !c.endsWith(d) && !d.endsWith(c));
}
// A sample path matching both patterns, or null if none was found.
function bothSample(p, q) {
  if (globMatch(q, samplePath(p))) return samplePath(p);
  if (globMatch(p, samplePath(q))) return samplePath(q);
  for (const [a, b] of [[p, q], [q, p]]) {
    const c = `${a.replace(/\*+$/u, "")}hs-x${b.replace(/^\*+/u, "")}`.replaceAll("*", "hs-sample");
    const cand = c.startsWith("/") ? c : `/${c}`;
    if (globMatch(p, cand) && globMatch(q, cand)) return cand;
  }
  return null;
}

export function resolveCaddyRoutes(shape) {
  const entries = [];
  const problems = [];
  for (const server of shape?.servers ?? []) {
    const hosts = new Set(), paths = new Set();
    collect(server.routes, hosts, paths);
    const clientIp = { trustedProxies: server.trustedProxies ?? null, strict: server.trustedProxiesStrict === true, headers: server.clientIpHeaders ?? null };
    const base = { server: server.server, listen: server.listen ?? [], clientIp };
    for (const hostname of [...hosts, "*"]) {
      const host = sampleHost(hostname);
      const toEntries = (path, sample) => {
        const { outcomes, overflow } = walk(server, { host, path: sample });
        if (overflow) {
          problems.push(`${hostname}: too many route combinations to resolve`);
          return [{ ...base, hostname, path, answer: { kind: "unknown", reason: "too many route combinations to resolve" }, gate: "unknown", gateReason: "routes too complex to resolve", gateUpstream: null, restriction: T, conditions: "none", conditionReason: null }];
        }
        return outcomes.map((o) => {
          const unknown = findUnknown(o.cond);
          return { ...base, hostname, path, answer: o.answer, gate: o.gate, gateReason: o.gateReason, gateUpstream: o.gateUpstream, restriction: o.cond, conditions: unknown ? "unknown" : "none", conditionReason: unknown?.reason ?? null };
        });
      };
      const rest = toEntries(null, OTHER_PATH);
      const signature = (list) => JSON.stringify(list.map((e) => ({ ...e, path: null })));
      const restSignature = signature(rest);
      const hostEntries = [];
      for (const pattern of paths) {
        const specific = toEntries(pattern, samplePath(pattern));
        if (signature(specific) !== restSignature) hostEntries.push(...specific);
      }
      // Paths matching two patterns at once can take a route neither pattern
      // takes alone (an ungated *.json under a gated /a/*). Pairs are checked;
      // a pair with no sample found leaves gates on this host unverified.
      const list = [...paths];
      const unresolved = [];
      for (let i = 0; i < list.length; i++) {
        for (let j = i + 1; j < list.length; j++) {
          const [p, q] = [list[i], list[j]];
          if (disjoint(p, q)) continue;
          const sample = bothSample(p, q);
          if (sample == null) { unresolved.push(`${p} and ${q}`); continue; }
          if (sample === samplePath(p) || sample === samplePath(q)) continue;
          const combo = toEntries(`${p} & ${q}`, sample);
          if (signature(combo) !== restSignature) hostEntries.push(...combo);
        }
      }
      hostEntries.push(...rest);
      if (unresolved.length) {
        const reason = `overlapping path matchers can't all be checked (${unresolved.join("; ")})`;
        for (const e of hostEntries) if (e.gate === "authentik") { e.gate = "unknown"; e.gateReason = reason; }
      }
      entries.push(...hostEntries);
    }
  }
  return { entries, problems };
}
