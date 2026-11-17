import test from "node:test";
import assert from "node:assert/strict";
import { collectCloudflare, accessProtection } from "../src/collectors/cloudflare.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";
import { cloudflareRoutes, CF_CFG } from "./fixtures/cloudflare-fixture.mjs";

async function collect(routes, token = "cf-secret-token") {
  const srv = await startFixtureServer(routes);
  try {
    const out = await collectCloudflare({ http: createHttp({ allowHosts: ["127.0.0.1"] }), cfg: CF_CFG, token, now: () => 7000, base: `${srv.url}/client/v4`, certSha256: srv.certSha256 });
    return { out, srv, get: (kind) => out.evidence.find((e) => e.kind === kind).value };
  } finally { await srv.close(); }
}
const allow = { decision: "allow", precedence: 1, include: [{ email_domain: { domain: "example.com" } }] };
const bypassAll = { decision: "bypass", precedence: 1, include: [{ everyone: {} }] };

test("tunnel ingress is normalised, with tunnel-side enforcement kept separately", async () => {
  const { get, srv } = await collect(cloudflareRoutes());
  assert.deepEqual(get("cloudflare.tunnel").tunnels[0].ingress, [
    { hostname: "ha.jellofin.com", path: null, service: "http://192.168.0.197:8123", catchAll: false, hostHeader: null, jwtRequired: true, audTags: 1 },
    { hostname: "manage.jellofin.com", path: null, service: "https://192.168.0.201:443", catchAll: false, hostHeader: null, jwtRequired: false, audTags: 0 },
    { hostname: null, path: null, service: "http_status:404", catchAll: true, hostHeader: null, jwtRequired: false, audTags: 0 }
  ]);
  assert.equal(srv.requests[0].headers.authorization, "Bearer cf-secret-token");
  assert.ok(srv.requests.every((r) => r.method === "GET"));
});

test("Access applications carry their domains, paths and policies", async () => {
  const apps = [{ id: "a1", type: "self_hosted", domain: "ha.jellofin.com", self_hosted_domains: ["ha.jellofin.com", "ha.jellofin.com/api/*"], policies: [allow, bypassAll] }];
  const { get } = await collect(cloudflareRoutes({ apps }));
  assert.deepEqual(get("cloudflare.access").apps, [{ id: "a1", type: "self_hosted", domains: [{ hostname: "ha.jellofin.com", path: null }, { hostname: "ha.jellofin.com", path: "/api/" }],
    policies: [{ decision: "allow", precedence: 1, includesEveryone: false }, { decision: "bypass", precedence: 1, includesEveryone: true }] }]);
});

test("policies are fetched separately when the application list doesn't include them", async () => {
  const { get } = await collect(cloudflareRoutes({ apps: [{ id: "a2", domain: "x.jellofin.com", policies: ["policy-uuid-only"] }], policies: { a2: [allow] } }));
  assert.deepEqual(get("cloudflare.access").apps[0].policies, [{ decision: "allow", precedence: 1, includesEveryone: false }]);
});

test("DNS names are paged and deduplicated", async () => {
  const dns = Array.from({ length: 230 }, (_, i) => ({ name: `H${i % 220}.jellofin.com`, type: "A" }));
  const { get, srv } = await collect(cloudflareRoutes({ dns }));
  assert.equal(get("cloudflare.dns").names.length, 220);
  assert.equal(srv.requests.filter((r) => r.url.includes("dns_records")).length, 3);
});

test("a short page count, success:false, a missing ingress list and auth errors fail the run", async () => {
  const short = cloudflareRoutes();
  short["/client/v4/zones/zone/dns_records"] = (req) => [200, { success: true, result: req.url.includes("page=1&") ? [{ name: "a" }] : [], result_info: { total_count: 5 } }];
  await assert.rejects(collect(short), (e) => e.code === "parse" && /1 of 5/u.test(e.message));
  const failed = cloudflareRoutes();
  failed["/client/v4/accounts/acc/access/apps"] = () => [200, { success: false, errors: [{ message: "nope" }], result: null }];
  await assert.rejects(collect(failed), (e) => e.code === "parse");
  const local = cloudflareRoutes();
  local["/client/v4/accounts/acc/cfd_tunnel/t1/configurations"] = { success: true, result: { config: null } };
  await assert.rejects(collect(local), (e) => e.code === "parse" && /ingress/u.test(e.message));
  const denied = cloudflareRoutes();
  denied["/client/v4/accounts/acc/cfd_tunnel/t1/configurations"] = () => [403, {}];
  await assert.rejects(collect(denied), (e) => e.code === "auth" && !e.message.includes("cf-secret-token"));
});

const app = (domains, policies) => ({ id: "x", domains, policies });
const P = { allow: { decision: "allow", includesEveryone: false }, bypassAll: { decision: "bypass", includesEveryone: true }, bypassSome: { decision: "bypass", includesEveryone: false }, odd: { decision: "magic", includesEveryone: false } };

test("an application that only allows or denies protects its host", () => {
  const apps = [app([{ hostname: "ha.example.com", path: null }], [P.allow])];
  assert.equal(accessProtection("ha.example.com", null, apps), "protected");
  assert.equal(accessProtection("ha.example.com", "/anything", apps), "protected");
  assert.equal(accessProtection("other.example.com", null, apps), "none");
});
test("a bypass for everyone is not protection; a partial bypass or an unrecognised decision is unknown", () => {
  assert.equal(accessProtection("h", null, [app([{ hostname: "h", path: null }], [P.allow, P.bypassAll])]), "bypassed");
  assert.equal(accessProtection("h", null, [app([{ hostname: "h", path: null }], [P.allow, P.bypassSome])]), "unknown");
  assert.equal(accessProtection("h", null, [app([{ hostname: "h", path: null }], [P.odd])]), "unknown");
  assert.equal(accessProtection("h", null, [{ id: "x", domains: [{ hostname: "h", path: null }] }]), "unknown");
  assert.equal(accessProtection("h", null, undefined), "unknown");
});
test("a more specific application overrides the broader one for its path, and weakens the host as a whole", () => {
  const apps = [app([{ hostname: "h", path: null }], [P.allow]), app([{ hostname: "h", path: "/api/" }], [P.bypassAll])];
  assert.equal(accessProtection("h", "/api/x", apps), "bypassed");
  assert.equal(accessProtection("h", "/app", apps), "protected");
  assert.equal(accessProtection("h", null, apps), "bypassed");
});
test("an application that covers only a path leaves the rest of the host unprotected", () => {
  const apps = [app([{ hostname: "h", path: "/admin/" }], [P.allow])];
  assert.equal(accessProtection("h", "/admin/x", apps), "protected");
  assert.equal(accessProtection("h", "/", apps), "none");
  assert.equal(accessProtection("h", null, apps), "none");
});
test("wildcard application domains cover subdomains only", () => {
  const apps = [app([{ hostname: "*.example.com", path: null }], [P.allow])];
  assert.equal(accessProtection("a.example.com", null, apps), "protected");
  assert.equal(accessProtection("example.com", null, apps), "none");
});
