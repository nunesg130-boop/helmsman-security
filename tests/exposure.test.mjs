import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolveExposure, clientIpFor } from "../src/exposure/resolve.mjs";
import { PUBLIC_VISITOR } from "../src/exposure/ip.mjs";

const live = JSON.parse(readFileSync(new URL("./fixtures/caddy-shape-live.json", import.meta.url), "utf8"));
const CONFIG = { caddy: { assetKey: "pve:guest:105", address: "192.168.0.105", trustedClientIpHeaders: ["Cf-Connecting-Ip"] }, cloudflare: { assetKey: "pve:guest:108", connectorAddress: "192.168.0.108" } };
const ASSETS = [
  ["pve:guest:105", "caddy", "192.168.0.105"], ["pve:guest:108", "cloudflared", "192.168.0.108"], ["pve:guest:100", "Jelly-Arr", "192.168.0.7"],
  ["pve:guest:201", "docker-auth", "192.168.0.213"], ["pve:guest:109", "docker-apps", "192.168.0.109"], ["pve:guest:110", "pihole", "192.168.0.2"],
  ["pve:guest:200", "Management-VM", "192.168.0.200"], ["pve:guest:116", "helmsec", "192.168.0.116"],
  ["pve:guest:107", "sure", "192.168.0.107"], ["pve:guest:125", "wyl", "192.168.0.125"], ["pve:guest:104", "seerr", "192.168.0.104"], ["pve:guest:122", "wizarr", "192.168.0.122"]
].map(([assetKey, name, ip]) => ({ assetKey, name, ips: [ip] }));
const fwd = (wanPort, lanIp, lanPort = wanPort, protocol = "tcp") => ({ wanPort, lanIp, lanPort, protocol });
const ROUTER = { portForwards: [fwd(80, "192.168.0.105"), fwd(443, "192.168.0.105")], upnp: false, dmz: false, ipv6Inbound: false };
const cf = (extra = {}) => ({ status: "ok", tunnels: [], apps: [], names: [], ...extra });
const ingress = (hostname, service, extra = {}) => ({ hostname, path: null, service, catchAll: !hostname, hostHeader: null, jwtRequired: false, audTags: 0, ...extra });
const tunnel = (...rules) => [{ id: "t1", ingress: [...rules, ingress(null, "http_status:404")] }];
const accessApp = (hostname, decision = "allow", includesEveryone = false, path = null) => ({ id: hostname, type: "self_hosted", domains: [{ hostname, path }], policies: [{ decision, precedence: 1, includesEveryone }] });

const proxy = (dial) => ({ handler: "reverse_proxy", upstreams: [dial] });
const route = (match, handle) => ({ group: null, terminal: true, match: match.map((m) => ({ unsupported: [], ...m })), handle });
const shapeOf = (routes, server = {}) => ({ version: 2, generatedAt: 1, servers: [{ server: "srv0", listen: [":443"], trustedProxies: null, trustedProxiesStrict: false, clientIpHeaders: null, routes, ...server }] });
const GATE = { handler: "reverse_proxy", upstreams: ["192.168.0.213:9000"], rewrite: "/outpost.goauthentik.io/auth/caddy", handleResponse: [{ statusCodes: [2], unsupportedMatch: [], setsStatus: false, handlers: ["headers"], setsRequestHeaders: [], innerMatchers: [] }] };
const LAN = { ranges: ["192.168.0.0/24"] };
const one = (hostMatcher, handle = [proxy("192.168.0.7:8096")], server) => shapeOf([route([{ host: ["a.jellofin.com"], ...hostMatcher }], handle)], server);

function run({ shape = live, caddyStatus = "ok", cloudflare = cf(), router = ROUTER, listeners = () => undefined, assets = ASSETS } = {}) {
  const out = resolveExposure({ caddy: { status: caddyStatus, shape: caddyStatus === "ok" ? shape : null }, cloudflare, router, assets, listeners, config: CONFIG });
  return { ...out, svc: (hostname, path = null) => out.services.find((s) => s.hostname === hostname && s.path === path), m: (key) => out.machines.get(key), kinds: (kind) => out.problems.filter((p) => p.kind === kind) };
}

test("the live lab: Jelly-Arr is an internet-facing app, docker-auth the gate, Caddy the entry", () => {
  const r = run();
  assert.deepEqual([r.m("pve:guest:100").exposure, r.m("pve:guest:100").role], ["internet", "app"]);
  assert.deepEqual([r.m("pve:guest:201").exposure, r.m("pve:guest:201").role], ["internet", "gate"]);
  assert.deepEqual([r.m("pve:guest:105").exposure, r.m("pve:guest:105").role], ["internet", "entry"]);
  const jelly = r.svc("jellyprox.jellofin.com");
  assert.deepEqual([jelly.exposure, jelly.gate, jelly.upstream, jelly.assetKey, jelly.listening], ["internet", "none", "192.168.0.7:8096", "pve:guest:100", null]);
  assert.deepEqual(jelly.paths, [{ entry: "forward", reachable: true, gate: "none", gateReason: null }]);
  assert.deepEqual([r.svc("paperless.jellofin.com").gate, r.svc("paperless.jellofin.com", "/api/*").gate], ["authentik", "none"]);
  assert.deepEqual(r.sources, { caddy: "ok", cloudflare: "ok", router: "declared", inventory: "ok" });
});
test("a machine with no route is lan only when every router fact is declared off", () => {
  assert.deepEqual([run().m("pve:guest:110").exposure, run().m("pve:guest:110").role], ["lan", null]);
  for (const missing of ["upnp", "dmz", "ipv6Inbound"]) {
    const m = run({ router: { ...ROUTER, [missing]: undefined } }).m("pve:guest:110");
    assert.equal(m.exposure, "unknown", missing);
    assert.match(m.reason, /can't rule out other ways in/u);
  }
  assert.equal(run({ router: { ...ROUTER, upnp: true } }).m("pve:guest:110").exposure, "unknown");
  assert.equal(run({ router: { ...ROUTER, portForwards: undefined } }).m("pve:guest:110").exposure, "unknown");
});
test("a stale or missing Caddy shape makes machines unknown, never lan", () => {
  for (const status of ["stale", "missing", "failed"]) {
    const r = run({ caddyStatus: status });
    assert.equal(r.m("pve:guest:100").exposure, "unknown", status);
    assert.equal(r.m("pve:guest:110").exposure, "unknown", status);
    assert.equal(r.kinds("source_unreadable").length, 1);
    assert.equal(r.sources.caddy, status);
  }
});
test("a remote_ip-restricted route is lan with only the router forward", () => {
  const r = run({ shape: one({ remote_ip: LAN }) });
  assert.equal(r.svc("a.jellofin.com").exposure, "lan");
  assert.deepEqual(r.svc("a.jellofin.com").paths, [{ entry: "forward", reachable: false, gate: "none", gateReason: null }]);
  assert.equal(r.m("pve:guest:100").exposure, "lan");
});
test("the same route is internet once a tunnel ingress for that hostname points at Caddy", () => {
  const r = run({ shape: one({ remote_ip: LAN }), cloudflare: cf({ tunnels: tunnel(ingress("a.jellofin.com", "https://192.168.0.105:443")) }) });
  const s = r.svc("a.jellofin.com");
  assert.equal(s.exposure, "internet");
  assert.deepEqual(s.paths.map((p) => [p.entry, p.reachable]), [["forward", false], ["tunnel-via-caddy", true]]);
  assert.match(s.reason, /tunnel/u);
  assert.equal(r.kinds("restriction_bypassed_by_tunnel")[0].hostname, "a.jellofin.com");
  assert.equal(r.m("pve:guest:100").exposure, "internet");
});
const viaTunnel = (server) => run({ shape: one({ client_ip: LAN }, undefined, server), cloudflare: cf({ tunnels: tunnel(ingress("a.jellofin.com", "https://192.168.0.105:443")) }) }).svc("a.jellofin.com");
const TRUST = { source: "static", ranges: ["192.168.0.108/32"] };
test("client_ip restricted to the LAN, cloudflared not trusted: internet (Caddy sees cloudflared's private address)", () => {
  assert.equal(viaTunnel().exposure, "internet");
  assert.equal(viaTunnel({ trustedProxies: { source: "static", ranges: ["10.9.9.9/32"] } }).exposure, "internet");
});
test("client_ip restricted to the LAN, cloudflared trusted with Cf-Connecting-Ip or strict mode: lan", () => {
  assert.equal(viaTunnel({ trustedProxies: TRUST, clientIpHeaders: ["CF-Connecting-IP"] }).exposure, "lan");
  assert.equal(viaTunnel({ trustedProxies: TRUST, trustedProxiesStrict: true }).exposure, "lan");
});
test("client_ip restricted to the LAN, cloudflared trusted with default X-Forwarded-For: unknown, never lan", () => {
  assert.equal(viaTunnel({ trustedProxies: TRUST }).exposure, "unknown");
  assert.equal(viaTunnel({ trustedProxies: TRUST, clientIpHeaders: ["X-Forwarded-For"] }).exposure, "unknown");
  assert.equal(viaTunnel({ trustedProxies: TRUST, clientIpHeaders: ["Cf-Connecting-Ip", "X-Real-Ip"] }).exposure, "unknown");
});
test("client_ip with a non-static trusted_proxies source, or one that includes public space: unknown", () => {
  assert.equal(viaTunnel({ trustedProxies: { source: "cloudflare", ranges: null } }).exposure, "unknown");
  assert.equal(viaTunnel({ trustedProxies: { source: "static", ranges: ["0.0.0.0/0"] }, clientIpHeaders: ["Cf-Connecting-Ip"] }).exposure, "unknown");
  const forwardOnly = run({ shape: one({ client_ip: LAN }, undefined, { trustedProxies: { source: "static", ranges: ["0.0.0.0/0"] } }) }).svc("a.jellofin.com");
  assert.equal(forwardOnly.exposure, "unknown");
});
test("clientIpFor covers the three cases on both entry paths", () => {
  const c = { connectorAddress: "192.168.0.108", trustedClientIpHeaders: ["Cf-Connecting-Ip"] };
  const ip = (path, trustedProxies, strict = false, headers = null) => clientIpFor(path, { trustedProxies, strict, headers }, c);
  assert.equal(ip("forward", null), PUBLIC_VISITOR);
  assert.equal(ip("tunnel-via-caddy", null), "192.168.0.108");
  assert.equal(ip("tunnel-via-caddy", { source: "static", ranges: ["10.0.0.0/8"] }), "192.168.0.108");
  assert.equal(ip("forward", TRUST), PUBLIC_VISITOR);
  assert.equal(ip("tunnel-via-caddy", TRUST, false, ["Cf-Connecting-Ip"]), PUBLIC_VISITOR);
  assert.equal(ip("tunnel-via-caddy", TRUST, true), PUBLIC_VISITOR);
  assert.equal(ip("tunnel-via-caddy", TRUST), "unknown");
  assert.equal(ip("tunnel-via-caddy", { source: "static", ranges: ["192.168.0.0/16", "fd00::/8"] }, true), PUBLIC_VISITOR, "IPv6 ranges can't contain the IPv4 peer");
  assert.equal(ip("forward", { source: "static", ranges: ["0.0.0.0/0"] }), "unknown");
  assert.equal(ip("forward", { source: "static", ranges: ["not-a-range"] }), "unknown");
  assert.equal(ip("tunnel-via-caddy", { source: "dynamic" }), "unknown");
});
test("a Cloudflare-Access-protected tunnel path plus an ungated forward path: effective gate none", () => {
  const cloudflare = cf({ tunnels: tunnel(ingress("jellyprox.jellofin.com", "http://192.168.0.7:8096")), apps: [accessApp("jellyprox.jellofin.com")] });
  const s = run({ cloudflare }).svc("jellyprox.jellofin.com");
  assert.deepEqual(s.paths.map((p) => [p.entry, p.gate]), [["forward", "none"], ["tunnel-direct", "cloudflare-access"]]);
  assert.equal(s.gate, "none");
  assert.match(s.gateReason, /forward/u);
});
test("verified Authentik on the forward path plus Cloudflare Access on the tunnel path: verified-mixed", () => {
  const cloudflare = cf({ tunnels: tunnel(ingress("a.jellofin.com", "http://192.168.0.7:8096")), apps: [accessApp("a.jellofin.com")] });
  const s = run({ shape: one({}, [GATE, proxy("192.168.0.7:8096")]), cloudflare }).svc("a.jellofin.com");
  assert.equal(s.gate, "verified-mixed");
});
test("through Caddy the tunnel passes both layers: either verified gate is enough", () => {
  const rule = tunnel(ingress("a.jellofin.com", "https://192.168.0.105:443"));
  const gated = run({ shape: one({}, [GATE, proxy("192.168.0.7:8096")]), cloudflare: cf({ tunnels: rule }) }).svc("a.jellofin.com");
  assert.deepEqual(gated.paths.map((p) => p.gate), ["authentik", "authentik"]);
  assert.equal(gated.gate, "authentik");
  const access = run({ shape: one({}), cloudflare: cf({ tunnels: rule, apps: [accessApp("a.jellofin.com")] }) }).svc("a.jellofin.com");
  assert.deepEqual(access.paths.map((p) => p.gate), ["none", "cloudflare-access"]);
  assert.equal(access.gate, "none");
});
test("a restricted-or-unrestricted matcher pair is internet", () => {
  const shape = shapeOf([route([{ host: ["a.jellofin.com"], remote_ip: LAN }, { host: ["a.jellofin.com"] }], [proxy("192.168.0.7:8096")])]);
  assert.equal(run({ shape }).svc("a.jellofin.com").exposure, "internet");
});
test("with Cloudflare evidence missing, a restricted route is unknown and nothing is lan", () => {
  const r = run({ shape: one({ remote_ip: LAN }), cloudflare: { status: "missing" } });
  assert.equal(r.svc("a.jellofin.com").exposure, "unknown");
  assert.equal(r.m("pve:guest:100").exposure, "unknown");
  assert.equal(r.m("pve:guest:110").exposure, "unknown");
  assert.equal(r.kinds("source_unreadable")[0].reason.includes("Cloudflare"), true);
});
test("with Cloudflare evidence missing, an Authentik-gated route keeps its gate; an ungated one stays none", () => {
  const off = { status: "failed" };
  assert.equal(run({ cloudflare: off }).svc("paperless.jellofin.com").gate, "authentik");
  assert.equal(run({ cloudflare: off }).svc("jellyprox.jellofin.com").gate, "none");
  assert.equal(run({ cloudflare: off }).svc("jellyprox.jellofin.com").exposure, "internet");
});
test("a router forward straight to a VM makes it internet/direct", () => {
  const r = run({ router: { ...ROUTER, portForwards: [...ROUTER.portForwards, fwd(2222, "192.168.0.200", 22)] } });
  const m = r.m("pve:guest:200");
  assert.deepEqual([m.exposure, m.role, m.directForwards], ["internet", "direct", [{ wanPort: 2222, lanPort: 22, protocol: "tcp" }]]);
  assert.equal(run({ router: { ...ROUTER, dmz: "192.168.0.200" } }).m("pve:guest:200").role, "direct");
  assert.equal(run({ router: { ...ROUTER, dmz: "192.168.0.200" } }).m("pve:guest:110").exposure, "lan");
});
test("an unverified Caddy gate yields gate unknown and a problem", () => {
  const r = run({ shape: one({}, [{ ...GATE, rewrite: "/elsewhere" }, proxy("192.168.0.7:8096")]) });
  assert.equal(r.svc("a.jellofin.com").gate, "unknown");
  assert.equal(r.kinds("unverified_gate")[0].hostname, "a.jellofin.com");
});
test("an Access application with an everyone-bypass gives gate none; unreadable policies give unknown", () => {
  const rule = tunnel(ingress("ha.jellofin.com", "http://192.168.0.2:8123"));
  assert.equal(run({ cloudflare: cf({ tunnels: rule, apps: [accessApp("ha.jellofin.com", "bypass", true)] }) }).svc("ha.jellofin.com").gate, "none");
  assert.equal(run({ cloudflare: cf({ tunnels: rule, apps: [accessApp("ha.jellofin.com", "bypass", false)] }) }).svc("ha.jellofin.com").gate, "unknown");
  const direct = run({ cloudflare: cf({ tunnels: rule, apps: [accessApp("ha.jellofin.com")], names: ["ha.jellofin.com"] }) });
  assert.deepEqual([direct.svc("ha.jellofin.com").gate, direct.svc("ha.jellofin.com").publicDns, direct.svc("ha.jellofin.com").jwtRequired], ["cloudflare-access", true, false]);
  assert.deepEqual([direct.m("pve:guest:110").exposure, direct.m("pve:guest:110").role], ["internet", "app"]);
});
test("hostname upstreams are unresolvable; unknown addresses aren't in the inventory", () => {
  const named = run({ shape: one({}, [proxy("jellyfin.internal:8096")]) });
  assert.deepEqual([named.kinds("upstream_unresolvable")[0].upstream, named.svc("a.jellofin.com").assetKey], ["jellyfin.internal:8096", null]);
  const stranger = run({ shape: one({}, [proxy("192.168.0.250:80")]) });
  assert.equal(stranger.kinds("upstream_not_in_inventory")[0].upstream, "192.168.0.250:80");
  const shared = run({ shape: one({}), assets: [...ASSETS, { assetKey: "wazuh:agent:099", name: "dup", ips: ["192.168.0.7"] }] });
  assert.match(shared.kinds("upstream_unresolvable")[0].reason, /2 machines/u);
});
test("a dangling route is reported only when nothing is listening for certain", () => {
  const ev = (listening) => () => ({ ports: { rows: listening ? [{ protocol: "tcp", localIp: "0.0.0.0", localPort: 8096, process: "jellyfin" }] : [{ protocol: "tcp", localIp: "127.0.0.1", localPort: 8096, process: "jellyfin" }], fresh: true, complete: true }, containers: null, dockerHost: "no" });
  const up = run({ shape: one({}), listeners: ev(true) });
  assert.deepEqual([up.svc("a.jellofin.com").listening, up.svc("a.jellofin.com").process, up.kinds("dangling_route").length], [true, "jellyfin", 0]);
  const down = run({ shape: one({}), listeners: ev(false) });
  assert.deepEqual([down.svc("a.jellofin.com").listening, down.kinds("dangling_route")[0].assetKey], [false, "pve:guest:100"]);
  assert.equal(run({ shape: one({}) }).kinds("dangling_route").length, 0);
});
test("an unsupported matcher makes the route unknown and is reported", () => {
  const r = run({ shape: shapeOf([route([{ host: ["a.jellofin.com"], unsupported: ["header"] }], [proxy("192.168.0.7:8096")])]) });
  assert.equal(r.svc("a.jellofin.com").exposure, "unknown");
  assert.match(r.kinds("unsupported_condition")[0].reason, /header/u);
});
test("a route on a Caddy port that nothing forwards to is lan", () => {
  const shape = shapeOf([route([{ host: ["192.168.0.105"] }], [{ handler: "static_response" }])], { listen: ["192.168.0.105:2020"] });
  const s = run({ shape }).svc("192.168.0.105");
  assert.deepEqual([s.exposure, s.paths, s.assetKey], ["lan", [], "pve:guest:105"]);
});
test("undeclared port forwards leave every Caddy route unknown", () => {
  assert.equal(run({ router: { upnp: false, dmz: false, ipv6Inbound: false } }).svc("jellyprox.jellofin.com").exposure, "unknown");
});
test("a tunnel that overrides the Host header selects the Caddy route by that header", () => {
  const cloudflare = cf({ tunnels: tunnel(ingress("public.jellofin.com", "https://192.168.0.105:443", { hostHeader: "a.jellofin.com" })) });
  const s = run({ shape: one({ remote_ip: LAN }), cloudflare }).svc("a.jellofin.com");
  assert.equal(s.exposure, "internet");
});
test("a forward to an address no known machine has is reported, and machines without a known address become unknown", () => {
  const assets = [...ASSETS, { assetKey: "pve:guest:150", name: "no-agent-vm", ips: [] }];
  const r = run({ assets, shape: one({}), router: { ...ROUTER, portForwards: [...ROUTER.portForwards, fwd(3389, "192.168.0.77")] } });
  const p = r.kinds("upstream_not_in_inventory").find((x) => x.upstream === "192.168.0.77:3389");
  assert.deepEqual([p.origin, p.hostname], ["router", null]);
  assert.match(p.reason, /router forwards port 3389/u);
  assert.equal(r.m("pve:guest:150").exposure, "unknown");
  assert.match(r.m("pve:guest:150").reason, /can't be traced to a machine/u);
  assert.equal(r.m("pve:guest:110").exposure, "unknown", "the unknown target could be any machine");
  assert.equal(run({ assets, shape: one({}) }).m("pve:guest:150").exposure, "lan", "with every public route attributed, an address-less machine can't be a target");
});
test("a public route to an address outside the inventory also makes address-less machines unknown", () => {
  const assets = [...ASSETS, { assetKey: "pve:guest:150", name: "no-agent-vm", ips: [] }];
  assert.equal(run({ assets, shape: one({}, [proxy("192.168.0.250:80")]) }).m("pve:guest:150").exposure, "unknown");
  assert.equal(run({ assets, shape: one({}, [proxy("some-name.internal:80")]) }).m("pve:guest:150").exposure, "unknown");
  assert.equal(run({ assets, shape: one({}), router: { ...ROUTER, dmz: "192.168.0.77" } }).m("pve:guest:150").exposure, "unknown");
});
test("a UDP forward to Caddy's port (HTTP/3) counts as a way in", () => {
  const r = run({ shape: one({}), router: { ...ROUTER, portForwards: [fwd(443, "192.168.0.105", 443, "udp")] } });
  assert.equal(r.svc("a.jellofin.com").exposure, "internet");
});

// --- review fixes ---
test("a public route the engine can't attribute to a machine makes every other machine unknown", () => {
  for (const handle of [[{ handler: "authentication" }, proxy("192.168.0.7:8096")], [{ handler: "reverse_proxy" }], [proxy("192.168.0.250:80")], [proxy("nas.lan:80")]]) {
    const r = run({ shape: one({}, handle) });
    assert.equal(r.m("pve:guest:110").exposure, "unknown", JSON.stringify(handle));
    assert.match(r.m("pve:guest:110").reason, /can't be traced to a machine/u);
  }
});
test("a tunnel rule whose target is a name may lead into Caddy: restricted Caddy routes become unknown", () => {
  for (const service of ["https://caddy.lan:443", "https://a.jellofin.com", "ssh://bastion"]) {
    const r = run({ shape: one({ remote_ip: LAN }), cloudflare: cf({ tunnels: tunnel(ingress("a.jellofin.com", service)) }) });
    const s = r.svc("a.jellofin.com");
    assert.equal(s.exposure, "unknown", service);
    assert.ok(s.paths.some((p) => p.entry === "tunnel-via-caddy" && p.reachable === "unknown"), service);
    assert.equal(r.m("pve:guest:100").exposure, "unknown", service);
  }
});
test("strict mode is reliable only with the default X-Forwarded-For header", () => {
  const c = { connectorAddress: "192.168.0.108", trustedClientIpHeaders: ["Cf-Connecting-Ip"] };
  const ip = (headers) => clientIpFor("tunnel-via-caddy", { trustedProxies: TRUST, strict: true, headers }, c);
  assert.equal(ip(null), PUBLIC_VISITOR);
  assert.equal(ip(["X-Forwarded-For"]), PUBLIC_VISITOR);
  assert.equal(ip(["X-Real-Ip"]), "unknown");
});
test("listen addresses: port ranges are understood, unparseable ones are unknown, unix sockets aren't reachable", () => {
  const shapeOn = (listen) => one({}, undefined, { listen });
  const r = (listen, wanPort = 8005) => run({ shape: shapeOn(listen), router: { ...ROUTER, portForwards: [fwd(wanPort, "192.168.0.105", wanPort)] } }).svc("a.jellofin.com").exposure;
  assert.equal(r([":8000-8010"]), "internet");
  assert.equal(r([":8000-8004"]), "lan");
  assert.equal(r([":https"]), "unknown");
  assert.equal(r(["tcp/:8005"]), "internet");
  assert.equal(r(["unix//run/caddy.sock"]), "lan");
  assert.equal(r([]), "unknown", "a server with no listen address can't be judged");
});
test("a localhost upstream is the Caddy machine, and a loopback bind there counts as listening", () => {
  const ev = () => ({ ports: { rows: [{ protocol: "tcp", localIp: "127.0.0.1", localPort: 8080, process: "app" }], fresh: true, complete: true }, containers: null, dockerHost: "no" });
  const r = run({ shape: one({}, [proxy("localhost:8080")]), listeners: ev });
  const s = r.svc("a.jellofin.com");
  assert.deepEqual([s.assetKey, s.listening, s.process, r.kinds("dangling_route").length], ["pve:guest:105", true, "app", 0]);
});
test("Access is judged on the Caddy entry's own hostname when a wildcard tunnel rule leads to it", () => {
  const apps = [{ ...accessApp("*.jellofin.com"), type: "self_hosted" }, { ...accessApp("a.jellofin.com", "bypass", true), type: "self_hosted" }];
  const s = run({ shape: one({}), cloudflare: cf({ tunnels: tunnel(ingress("*.jellofin.com", "https://192.168.0.105:443")), apps }) }).svc("a.jellofin.com");
  assert.equal(s.paths.find((p) => p.entry === "tunnel-via-caddy").gate, "none");
});
test("an out-of-date machine inventory means nothing can be called lan", () => {
  const out = resolveExposure({ caddy: { status: "ok", shape: live }, cloudflare: cf(), router: ROUTER, assets: ASSETS, inventory: "stale", config: CONFIG });
  assert.equal(out.machines.get("pve:guest:110").exposure, "unknown");
  assert.match(out.machines.get("pve:guest:110").reason, /machine inventory is stale/u);
  assert.equal(out.sources.inventory, "stale");
});

test("each tunnel's localhost belongs to the machine that runs that tunnel's cloudflared", () => {
  const tunnels = [
    { id: "kasm", ingress: [ingress("manage.jellofin.com", "https://localhost:443"), ingress(null, "http_status:404")] },
    { id: "ha", ingress: [ingress("haos.jellofin.com", "http://localhost:8123"), ingress(null, "http_status:404")] }
  ];
  const assets = [...ASSETS, { assetKey: "pve:guest:151", name: "Kasm", ips: ["192.168.0.151"] }, { assetKey: "pve:guest:102", name: "haos", ips: ["192.168.0.197"] }];
  const config = { ...CONFIG, cloudflare: { ...CONFIG.cloudflare, connectors: { kasm: "192.168.0.151", ha: "192.168.0.197" } } };
  const out = resolveExposure({ caddy: { status: "ok", shape: live }, cloudflare: cf({ tunnels }), router: ROUTER, assets, config });
  const svc = (h) => out.services.find((s) => s.hostname === h);
  assert.equal(svc("manage.jellofin.com").assetKey, "pve:guest:151");
  assert.equal(svc("haos.jellofin.com").assetKey, "pve:guest:102");
  assert.deepEqual([out.machines.get("pve:guest:151").exposure, out.machines.get("pve:guest:102").exposure], ["internet", "internet"]);
});
test("a tunnel without its own connector address falls back to the default one", () => {
  const config = { ...CONFIG, cloudflare: { ...CONFIG.cloudflare, connectors: { other: "192.168.0.2" } } };
  const out = resolveExposure({ caddy: { status: "ok", shape: live }, cloudflare: cf({ tunnels: tunnel(ingress("x.jellofin.com", "http://localhost:80")) }), router: ROUTER, assets: ASSETS, config });
  assert.equal(out.services.find((s) => s.hostname === "x.jellofin.com").assetKey, "pve:guest:108");
});
