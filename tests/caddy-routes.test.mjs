import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { classifyGate, resolveCaddyRoutes, evalRestriction } from "../src/exposure/caddy-routes.mjs";
import { PUBLIC_VISITOR } from "../src/exposure/ip.mjs";

const live = JSON.parse(readFileSync(new URL("./fixtures/caddy-shape-live.json", import.meta.url), "utf8"));
const liveEntries = resolveCaddyRoutes(live).entries;
const pick = (entries, hostname, path = null) => entries.filter((e) => e.hostname === hostname && e.path === path);
const one = (entries, hostname, path = null) => { const l = pick(entries, hostname, path); assert.equal(l.length, 1, `${hostname} ${path}: ${JSON.stringify(l)}`); return l[0]; };

const OK_RESPONSE = { statusCodes: [2], unsupportedMatch: [], setsStatus: false, handlers: ["headers", "vars"], setsRequestHeaders: ["X-Authentik-Username"], innerMatchers: ["not"] };
const gateH = (extra = {}) => ({ handler: "reverse_proxy", upstreams: ["192.168.0.213:9000"], rewrite: "/outpost.goauthentik.io/auth/caddy", handleResponse: [OK_RESPONSE], ...extra });
const proxy = (dial) => ({ handler: "reverse_proxy", upstreams: [dial] });
const route = (match, handle, extra = {}) => ({ group: null, terminal: false, match: match.map((m) => ({ unsupported: [], ...m })), handle, ...extra });
const shape = (routes, server = {}) => ({ version: 2, generatedAt: 1, servers: [{ server: "srv0", listen: [":443"], trustedProxies: null, trustedProxiesStrict: false, clientIpHeaders: null, routes, ...server }] });
const resolve = (routes, server) => resolveCaddyRoutes(shape(routes, server)).entries;
const LAN = { ranges: ["192.168.0.0/24"] };

test("jellyprox is an ungated proxy to 192.168.0.7:8096", () => {
  const e = one(liveEntries, "jellyprox.jellofin.com");
  assert.deepEqual([e.answer, e.gate, e.restriction, e.conditions, e.listen], [{ kind: "proxy", upstream: "192.168.0.7:8096" }, "none", { op: "true" }, "none", [":443"]]);
  assert.equal(pick(liveEntries, "jellyprox.jellofin.com", "/api/*").length, 0, "paths that change nothing for a host aren't listed");
});
test("paperless: /api/* is ungated; everything else is behind a verified Authentik gate", () => {
  const api = one(liveEntries, "paperless.jellofin.com", "/api/*");
  assert.deepEqual([api.answer.upstream, api.gate], ["192.168.0.109:8000", "none"]);
  const rest = one(liveEntries, "paperless.jellofin.com");
  assert.deepEqual([rest.answer.upstream, rest.gate, rest.gateUpstream], ["192.168.0.109:8000", "authentik", "192.168.0.213:9000"]);
});
test("sure and wyl: a gate in its own earlier route gates the app route", () => {
  assert.deepEqual([one(liveEntries, "sure.jellofin.com").answer.upstream, one(liveEntries, "sure.jellofin.com").gate], ["192.168.0.107:3000", "authentik"]);
  assert.deepEqual([one(liveEntries, "wyl.jellofin.com").answer.upstream, one(liveEntries, "wyl.jellofin.com").gate], ["192.168.0.125:8840", "authentik"]);
});
test("the outpost path answers from Authentik: ungated where it sits before the gate, gated where the gate runs first", () => {
  const p = one(liveEntries, "paperless.jellofin.com", "/outpost.goauthentik.io/*");
  assert.deepEqual([p.answer.upstream, p.gate], ["192.168.0.213:9000", "none"]);
  const s = one(liveEntries, "sure.jellofin.com", "/outpost.goauthentik.io/*");
  assert.deepEqual([s.answer.upstream, s.gate], ["192.168.0.213:9000", "authentik"]);
  assert.equal(one(liveEntries, "auth.jellofin.com").gate, "none");
});
test("www.palmettotechit.com is a static response; the apex proxies to 192.168.0.213:8088", () => {
  assert.deepEqual(one(liveEntries, "www.palmettotechit.com").answer, { kind: "static" });
  assert.deepEqual(one(liveEntries, "palmettotechit.com").answer, { kind: "proxy", upstream: "192.168.0.213:8088" });
});
test("every live hostname resolves and nothing is reported as a problem", () => {
  assert.equal(new Set(liveEntries.map((e) => e.hostname)).size, 12);
  assert.deepEqual(resolveCaddyRoutes(live).problems, []);
  assert.ok(liveEntries.every((e) => e.answer.kind !== "unknown" && e.gate !== "unknown"));
});

test("a gate limited by a path matcher doesn't gate other paths", () => {
  const entries = resolve([route([{ host: ["a.example"] }], [{ handler: "subroute", routes: [route([{ path: ["/admin/*"] }], [gateH()]), route([], [proxy("10.0.0.5:80")])] }], { terminal: true })]);
  assert.equal(one(entries, "a.example", "/admin/*").gate, "authentik");
  assert.equal(one(entries, "a.example").gate, "none");
});
test("handle_response that also continues on non-2xx is gate unknown", () => {
  for (const bad of [
    { handleResponse: [OK_RESPONSE, { ...OK_RESPONSE, statusCodes: [401] }] },
    { handleResponse: [{ ...OK_RESPONSE, statusCodes: [2, 3] }] },
    { handleResponse: [{ ...OK_RESPONSE, statusCodes: null }] },
    { handleResponse: [{ ...OK_RESPONSE, unsupportedMatch: ["headers"] }] },
    { handleResponse: [{ ...OK_RESPONSE, setsStatus: true }] },
    { handleResponse: [{ ...OK_RESPONSE, innerMatchers: ["not", "path"] }] },
    { handleResponse: [] },
    { rewrite: "/somewhere/else" },
    { rewrite: undefined }
  ]) {
    assert.equal(classifyGate(gateH(bad)), "unknown", JSON.stringify(bad));
    const e = pick(resolve([route([{ host: ["a.example"] }], [gateH(bad), proxy("10.0.0.5:80")])]), "a.example").find((x) => x.answer.upstream === "10.0.0.5:80");
    assert.equal(e.gate, "unknown");
    assert.match(e.gateReason, /doesn't match the verified Authentik pattern/u);
  }
});
test("handle_response whose handlers include reverse_proxy is gate unknown", () => {
  assert.equal(classifyGate(gateH({ handleResponse: [{ ...OK_RESPONSE, handlers: ["headers", "reverse_proxy"] }] })), "unknown");
});
test("classifyGate recognises the verified pattern and ignores plain proxies", () => {
  assert.equal(classifyGate(gateH()), "authentik");
  assert.equal(classifyGate(gateH({ handleResponse: [{ ...OK_RESPONSE, statusCodes: [200, 204] }] })), "authentik");
  assert.equal(classifyGate(proxy("10.0.0.5:80")), null);
  assert.equal(classifyGate({ handler: "headers" }), null);
});
test("an earlier terminal route for the same host wins", () => {
  const entries = resolve([route([{ host: ["a.example"] }], [{ handler: "headers" }], { terminal: true }), route([{ host: ["a.example"] }], [proxy("10.0.0.5:80")])]);
  assert.equal(pick(entries, "a.example").length, 0);
  const second = resolve([route([{ host: ["a.example"] }], [proxy("10.0.0.5:80")], { terminal: true }), route([{ host: ["a.example"] }], [proxy("10.0.0.6:80")])]);
  assert.equal(one(second, "a.example").answer.upstream, "10.0.0.5:80");
});
test("routes in the same group are mutually exclusive: only the first match runs", () => {
  const entries = resolve([route([{ host: ["a.example"] }], [{ handler: "headers" }], { group: "g" }), route([{ host: ["a.example"] }], [proxy("10.0.0.6:80")], { group: "g" }), route([{ host: ["a.example"] }], [proxy("10.0.0.5:80")])]);
  assert.equal(one(entries, "a.example").answer.upstream, "10.0.0.5:80");
});
test("matcher sets are ORed and matchers within a set are ANDed", () => {
  const entries = resolve([route([{ host: ["a.example"], path: ["/x/*"] }, { host: ["b.example"] }], [proxy("10.0.0.5:80")])]);
  assert.equal(one(entries, "a.example", "/x/*").answer.upstream, "10.0.0.5:80");
  assert.equal(pick(entries, "a.example").length, 0);
  assert.equal(one(entries, "b.example").answer.upstream, "10.0.0.5:80");
});
test("overlapping path matchers resolve by declared order", () => {
  const sub = [route([{ path: ["/api/v1/*"] }], [proxy("10.0.0.1:80")]), route([{ path: ["/api/*"] }], [proxy("10.0.0.2:80")]), route([], [proxy("10.0.0.3:80")])];
  const entries = resolve([route([{ host: ["a.example"] }], [{ handler: "subroute", routes: sub }])]);
  assert.deepEqual(["/api/v1/*", "/api/*", null].map((p) => one(entries, "a.example", p).answer.upstream), ["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]);
});
test("an unsupported matcher makes the entry's conditions unknown and names the matcher", () => {
  const e = one(resolve([route([{ host: ["a.example"], unsupported: ["header"] }], [proxy("10.0.0.5:80")])]), "a.example");
  assert.deepEqual([e.conditions, e.conditionReason], ["unknown", "unsupported Caddy matcher: header"]);
  assert.equal(evalRestriction(e.restriction, { remoteIp: PUBLIC_VISITOR, clientIp: PUBLIC_VISITOR }), "unknown");
});
test("one restricted and one unrestricted matcher set give an 'or' containing true, i.e. unrestricted", () => {
  const e = one(resolve([route([{ host: ["a.example"], remote_ip: LAN }, { host: ["a.example"] }], [proxy("10.0.0.5:80")])]), "a.example");
  assert.deepEqual(e.restriction, { op: "true" });
});
test("'not remote_ip 192.168.0.0/24' is kept as not(remote_ip) and evaluates true for a public address", () => {
  const e = one(resolve([route([{ host: ["a.example"], not: [{ remote_ip: LAN, unsupported: [] }] }], [proxy("10.0.0.5:80")])]), "a.example");
  assert.deepEqual(e.restriction, { op: "not", arg: { op: "remote_ip", ranges: ["192.168.0.0/24"] } });
  assert.equal(evalRestriction(e.restriction, { remoteIp: PUBLIC_VISITOR, clientIp: PUBLIC_VISITOR }), true);
  assert.equal(evalRestriction(e.restriction, { remoteIp: "192.168.0.9", clientIp: "192.168.0.9" }), false);
});
test("a restriction on a parent route is ANDed with a child route's restriction", () => {
  const e = one(resolve([route([{ host: ["a.example"], remote_ip: LAN }], [{ handler: "subroute", routes: [route([{ client_ip: { ranges: ["192.168.0.50/32"] } }], [proxy("10.0.0.5:80")])] }])]), "a.example");
  assert.deepEqual(e.restriction, { op: "and", args: [{ op: "remote_ip", ranges: ["192.168.0.0/24"] }, { op: "client_ip", ranges: ["192.168.0.50/32"] }] });
});
test("a restricted route followed by an open one yields both, each with its own condition", () => {
  const entries = pick(resolve([route([{ host: ["a.example"], remote_ip: LAN }], [proxy("10.0.0.5:80")], { terminal: true }), route([{ host: ["a.example"] }], [proxy("10.0.0.6:80")])]), "a.example");
  assert.deepEqual(entries.map((e) => [e.answer.upstream, e.restriction]), [["10.0.0.5:80", { op: "remote_ip", ranges: ["192.168.0.0/24"] }], ["10.0.0.6:80", { op: "not", arg: { op: "remote_ip", ranges: ["192.168.0.0/24"] } }]]);
});
test("evalRestriction is three-valued: unknown client address makes client_ip unknown; and/or/not follow Kleene logic", () => {
  const T = { op: "true" }, U = { op: "unknown", reason: "x" }, F = { op: "not", arg: T };
  const src = { remoteIp: "192.168.0.108", clientIp: "unknown" };
  assert.equal(evalRestriction({ op: "client_ip", ranges: ["192.168.0.0/24"] }, src), "unknown");
  assert.equal(evalRestriction({ op: "remote_ip", ranges: ["192.168.0.0/24"] }, src), true);
  assert.equal(evalRestriction({ op: "remote_ip", ranges: ["10.0.0.0/8"] }, src), false);
  assert.equal(evalRestriction({ op: "and", args: [F, U] }, src), false);
  assert.equal(evalRestriction({ op: "and", args: [T, U] }, src), "unknown");
  assert.equal(evalRestriction({ op: "or", args: [T, U] }, src), true);
  assert.equal(evalRestriction({ op: "or", args: [F, U] }, src), "unknown");
  assert.equal(evalRestriction({ op: "not", arg: U }, src), "unknown");
  assert.equal(evalRestriction({ op: "remote_ip", ranges: ["not-a-range"] }, src), "unknown", "ranges the engine can't evaluate are unknown, not false");
  assert.equal(evalRestriction({ op: "remote_ip", ranges: ["fd00::/8"] }, src), false, "an IPv6 range never contains an IPv4 address");
  assert.equal(evalRestriction({ op: "weird" }, src), "unknown");
});
test("an unknown handler type makes the answer unknown with the reason", () => {
  const e = one(resolve([route([{ host: ["a.example"] }], [{ handler: "acme_server" }])]), "a.example");
  assert.deepEqual(e.answer, { kind: "unknown", reason: "unrecognised Caddy handler acme_server" });
});
test("a route with no host matcher is listed for any hostname", () => {
  const entries = resolve([route([{ host: ["a.example"] }], [proxy("10.0.0.5:80")], { terminal: true }), route([], [proxy("10.0.0.9:80")])]);
  assert.equal(one(entries, "*").answer.upstream, "10.0.0.9:80");
  assert.equal(one(entries, "a.example").answer.upstream, "10.0.0.5:80");
});
test("wildcard hosts, several upstreams, dynamic upstreams and the server's client-address settings are carried", () => {
  const entries = resolve([route([{ host: ["*.a.example"] }], [{ handler: "reverse_proxy", upstreams: ["10.0.0.1:80", "10.0.0.2:80"] }], { terminal: true }), route([{ host: ["d.example"] }], [{ handler: "reverse_proxy" }])],
    { trustedProxies: { source: "static", ranges: ["192.168.0.108/32"] }, trustedProxiesStrict: true, clientIpHeaders: ["Cf-Connecting-Ip"] });
  assert.deepEqual(pick(entries, "*.a.example").map((e) => e.answer.upstream), ["10.0.0.1:80", "10.0.0.2:80"]);
  assert.equal(one(entries, "d.example").answer.kind, "unknown");
  assert.deepEqual(entries[0].clientIp, { trustedProxies: { source: "static", ranges: ["192.168.0.108/32"] }, strict: true, headers: ["Cf-Connecting-Ip"] });
});
test("file_server answers from Caddy itself; a rewrite before it changes nothing about who answers", () => {
  const site = route([{ host: ["192.168.0.105"] }], [{ handler: "subroute", routes: [
    route([{ remote_ip: { ranges: ["192.168.0.116/32"] } }], [{ handler: "subroute", routes: [route([], [{ handler: "vars" }, { handler: "rewrite" }, { handler: "file_server" }])] }], { group: "g" }),
    route([], [{ handler: "static_response" }], { group: "g" })
  ] }], { terminal: true });
  const entries = pick(resolve([site], { listen: ["192.168.0.105:2020"] }), "192.168.0.105");
  assert.deepEqual(entries.map((e) => [e.answer, e.restriction.op, e.conditions]), [[{ kind: "static" }, "remote_ip", "none"], [{ kind: "static" }, "not", "none"]]);
});
test("a path matcher that runs after a rewrite can't be evaluated: its conditions are unknown", () => {
  const entries = resolve([route([{ host: ["a.example"] }], [{ handler: "rewrite" }, { handler: "subroute", routes: [route([{ path: ["/admin/*"] }], [proxy("10.0.0.5:80")]), route([], [proxy("10.0.0.6:80")])] }])]);
  const e = pick(entries, "a.example");
  assert.ok(e.length >= 2);
  assert.ok(e.every((x) => x.conditions === "unknown" && /rewrite/u.test(x.conditionReason)), JSON.stringify(e.map((x) => [x.path, x.conditions])));
  const noPath = one(resolve([route([{ host: ["a.example"] }], [{ handler: "rewrite" }, proxy("10.0.0.5:80")])]), "a.example");
  assert.equal(noPath.conditions, "none", "no path matcher after the rewrite, nothing to doubt");
});

// --- review fixes ---
const ANY = { remoteIp: PUBLIC_VISITOR, clientIp: PUBLIC_VISITOR };
test("a restriction is judged against every public address, not one sample", () => {
  const ev = (op, ranges) => evalRestriction({ op, ranges }, ANY);
  assert.equal(ev("remote_ip", ["192.168.0.0/24"]), false, "only private ranges: no public visitor matches");
  assert.equal(ev("remote_ip", ["8.8.8.0/24"]), "unknown", "an allow-list of public addresses lets some visitors in");
  assert.equal(ev("remote_ip", ["0.0.0.0/1"]), "unknown");
  assert.equal(evalRestriction({ op: "not", arg: { op: "remote_ip", ranges: ["203.0.113.0/24"] } }, ANY), "unknown", "a block-list doesn't block everyone");
  assert.equal(evalRestriction({ op: "not", arg: { op: "remote_ip", ranges: ["192.168.0.0/16"] } }, ANY), true);
});
test("Caddy's private_ranges shorthand (with IPv6 ranges) can make a route LAN-only", () => {
  const PRIV = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.1/8", "fd00::/8", "::1"];
  assert.equal(evalRestriction({ op: "remote_ip", ranges: PRIV }, ANY), false);
  assert.equal(evalRestriction({ op: "remote_ip", ranges: PRIV }, { remoteIp: "192.168.0.108", clientIp: "192.168.0.108" }), true);
  assert.equal(evalRestriction({ op: "remote_ip", ranges: ["2001:db8::/32"] }, ANY), "unknown", "public IPv6 space");
});
test("a proxy with a non-gate handle_response still answers, with its gate unknown", () => {
  const custom = { ...gateH({ rewrite: undefined, handleResponse: [{ ...OK_RESPONSE, statusCodes: [404], handlers: ["static_response"] }] }), upstreams: ["192.168.0.7:8096"] };
  const e = pick(resolve([route([{ host: ["b.example"] }], [custom])]), "b.example");
  assert.deepEqual(e.map((x) => [x.answer, x.gate]), [[{ kind: "proxy", upstream: "192.168.0.7:8096" }, "unknown"]]);
  const behindGate = pick(resolve([route([{ host: ["c.example"] }], [gateH(), custom])]), "c.example");
  assert.deepEqual(behindGate.map((x) => [x.answer.upstream, x.gate]), [["192.168.0.7:8096", "authentik"]]);
});
test("a chain that ends after an unverified gate with nothing answering is reported, not dropped", () => {
  const e = one(resolve([route([{ host: ["d.example"] }], [gateH({ rewrite: "/x" })])]), "d.example");
  assert.deepEqual([e.answer, e.gate], [{ kind: "proxy", upstream: "192.168.0.213:9000" }, "unknown"], "the would-be gate's own upstream answers");
  const bare = one(resolve([route([{ host: ["e.example"] }], [{ ...gateH({ rewrite: "/x" }), upstreams: [] }])]), "e.example");
  assert.deepEqual([bare.answer.kind, bare.gate], ["unknown", "unknown"]);
});
test("overlapping path patterns are combined: an ungated *.json under a gated /a/* is found", () => {
  const sub = [route([{ path: ["*.json"] }], [proxy("10.0.0.5:80")]), route([], [gateH(), proxy("10.0.0.5:80")])];
  const entries = resolve([route([{ host: ["a.example"], path: ["/a/*"] }], [{ handler: "subroute", routes: sub }])]);
  const all = entries.filter((e) => e.hostname === "a.example");
  const combo = all.filter((e) => /\/a\/\*/u.test(e.path ?? "") && /\*\.json/u.test(e.path ?? ""));
  assert.equal(combo.length, 1, JSON.stringify(all.map((e) => [e.path, e.gate])));
  assert.equal(combo[0].gate, "none");
});
test("a gate skipped by either of two 'not path' sets is found on the overlap", () => {
  const gateRoute = { ...route([], [gateH()]), match: [{ not: [{ path: ["/public/*"], unsupported: [] }], unsupported: [] }, { not: [{ path: ["*.css"], unsupported: [] }], unsupported: [] }] };
  const entries = resolve([route([{ host: ["a.example"] }], [{ handler: "subroute", routes: [gateRoute, route([], [proxy("10.0.0.5:80")])] }])]).filter((e) => e.hostname === "a.example");
  const overlap = entries.find((e) => /\/public\/\*/u.test(e.path ?? "") && /\*\.css/u.test(e.path ?? ""));
  assert.ok(overlap, JSON.stringify(entries.map((e) => e.path)));
  assert.equal(overlap.gate, "none");
});
test("disjoint literal paths aren't combined (paperless keeps its three entries)", () => {
  assert.deepEqual(liveEntries.filter((e) => e.hostname === "paperless.jellofin.com").map((e) => e.path), ["/outpost.goauthentik.io/*", "/api/*", null]);
});
test("a pathological number of conditional routes stops with an unknown entry instead of hanging", () => {
  const many = Array.from({ length: 40 }, (_, i) => route([{ remote_ip: { ranges: [`10.0.${i}.0/24`] } }], [{ handler: "headers" }]));
  const t0 = Date.now();
  const r = resolveCaddyRoutes(shape([route([{ host: ["a.example"] }], [{ handler: "subroute", routes: [...many, route([], [proxy("10.0.0.5:80")])] }])]));
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
  const e = one(r.entries, "a.example");
  assert.deepEqual([e.answer.kind, e.gate], ["unknown", "unknown"]);
  assert.match(r.problems[0], /too many route combinations/u);
});
