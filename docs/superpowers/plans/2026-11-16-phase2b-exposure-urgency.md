# Phase 2B — Exposure, Urgency, Risk Acceptance, Posture Score — Implementation Plan (revision 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For every public route into the lab, the engine knows the hostname, the machine and port behind it, whether a *verified* login gate sits in front, and whether anything is actually listening; it uses that to mark vulnerability findings urgent, lets the owner accept specific risks, and publishes a posture score that separates what is confirmed from what is merely possible.

**Architecture:** Two new read-only sources (a Caddy route "shape" file produced on the Caddy LXC and served only to the engine, and the Cloudflare API with a read-only token) plus declared router settings feed a pure exposure resolver. Its output is stored as evidence and joined with 2A's findings to compute urgency, acceptance and the score as pure, versioned functions. "Unknown" is a first-class value at every layer: an unverified gate, an unsupported matcher or an uncertain attribution is carried through to the API and report and never collapses into a safer-looking default.

**Tech Stack:** Node.js 24 (ESM), `node:sqlite`, `node --test`, no npm dependencies; on the Caddy LXC: `jq` and a systemd timer.

**Spec:** `docs/superpowers/specs/2026-11-15-security-phase2-design.md`, sections 4.5–4.8 (owner decisions of 2026-11-15). Plan 2 of 3 for phase 2. Revisions 2 and 3 fold in sixteen review points from 2026-11-16 (listed under "Revision notes").

## Global Constraints

- Everything in the 2A plan's Global Constraints still applies (never guess, read-only, tenant rows, egress allowlist, secrets never stored or logged, power-loss safe).
- **Unknown never collapses.** Gate, exposure, listening and attribution each have an explicit unknown value. Unknown is treated as the *less safe* reading wherever a rule needs a decision, and is always shown as unknown.
- **LAN-only is decided per route:** a route is `lan` only if no public entry path can reach it while satisfying its restrictions (see "Entry paths"). Public DNS presence never lowers exposure or urgency.
- **A gate counts only when verified, on every public path.** Each entry path to a service has its own gate (`authentik`, `cloudflare-access`, `none`, `unknown`). A service's effective gate is the weakest across all the public paths that reach it: any path with `none` → `none`; otherwise any `unknown` → `unknown`; verified only when **every** reachable public path has a verified gate (`verified-mixed` when the paths are verified by different gates; it counts as verified). Only a verified effective gate earns the reduced "gated" urgency; `unknown` is treated as `none` for urgency and as most exposed for acceptance.
- **Restrictions keep their logic.** Source-address restrictions are carried as a boolean expression (and / or / not), never flattened, and evaluated three-valued (true / false / unknown).
- **A derived client address is trusted only with a complete trust chain** (see "Entry paths"); otherwise `client_ip` restrictions evaluate to unknown.
- Authentik itself, and Caddy as the entry point, are always service-exposed.
- **Confidence in the vulnerability and confidence in its exposure are separate fields** (`lowConfidence` from 2A; `exposureBasis` here). Uncertain exposure never suppresses a confirmed vulnerability.
- Urgent (confirmed) = service-exposed and (KEV, or severity high/critical with `fix-available-not-applied`); or gated and KEV; or host-exposed and KEV — using only `exposureBasis: "route"` attributions and verified gates. Low-confidence and accepted findings are never urgent. Missing or stale inputs make urgency `null`, never `false`.
- If any source a service's chain depends on is missing, stale or unparseable, that service's exposure is `unknown`, never `lan`.
- Router facts are declared in config and labelled "declared, not verified". Undeclared `upnp`, `dmz`, `ipv6Inbound` are unknown.
- The engine never contacts Caddy's admin API and never receives Caddy's secrets. The shape filter keeps structure and names; it never emits header values, tokens, key paths or response bodies.
- Score and urgency rules carry version numbers; the same evidence always gives the same result.

## Facts verified against the live lab (2026-11-16)

- Caddy has one server `srv0` listening `:443` (port 80 is Caddy's automatic HTTPS redirect). ER605 forwards only 80 and 443 to 192.168.0.105. UPnP off, DMZ off, LAN IPv6 not delegated.
- 14 hostnames route through Caddy; none has a `remote_ip`/`client_ip` restriction. The owner is removing three dead routes (`donetick`, `trek`, `home`). Fixture `tests/fixtures/caddy-shape-live.json` is shape **version 1** from before that cleanup; Task 2 regenerates it as version 2.
- Authentik forward auth appears as a `reverse_proxy` to `192.168.0.213:9000` with `rewrite` to `/outpost.goauthentik.io/auth/caddy` and a `handle_response` block, either inside the same route before the app's proxy (paperless, security) or as its own earlier route (sure, wyl). The contents of `handle_response` have not been seen yet (version 1 reduced it to `true`).
- `paperless.jellofin.com` has a `/api/*` route that proxies to Paperless before the gate.
- Other handlers seen: `subroute`, `static_response`, `encode`, `headers`.
- cloudflared runs at 192.168.0.108 and the tunnel is remotely managed. Whether any tunnel ingress points at Caddy is not yet known; the resolver must handle both.

## Caddy semantics the resolver must implement

**Matching.** A route's `match` is a list of matcher sets: the route matches if **any** set matches (OR); a set matches if **every** matcher in it matches (AND). An empty or absent `match` matches everything. `not` negates its nested sets. Supported matchers: `host`, `path`, `remote_ip`, `client_ip`, `not` (containing only supported matchers). Any other matcher name makes that route **conditionally reachable in an unknown way**: entries that depend on it carry `conditions: "unknown"` and the reason names the matcher.

**Ordering.** Within a route list (top level or `subroute`), routes run in order; each matching route's handlers run. `terminal: true` stops later routes in that list. Routes sharing a `group` are mutually exclusive: only the first matching route in the group runs. Path matchers may overlap; the resolver enumerates the distinct path conditions per hostname (each listed path pattern, their overlaps by declared order, and "everything else") and walks the chain for each.

**Handlers.** `reverse_proxy` without `handle_response` answers the request. `static_response` answers. `headers` and `encode` pass through. `subroute` recurses. A `reverse_proxy` with `handle_response` is a **gate candidate**, classified by `classifyGate`:
- `authentik` only if all hold: `rewrite.uri` starts with `/outpost.goauthentik.io/auth/`; exactly one `handle_response` entry matches success status codes (2xx only: `status_code` ⊆ {2, 200–299}); that entry's handlers are only `headers` (copying response headers to the request) and nothing that answers; there is no entry that lets non-2xx responses continue. With that pattern Caddy returns the auth server's non-2xx answer to the client and continues the chain only on 2xx.
- `unknown` for any other `handle_response` shape (extra entries, a non-2xx match, handlers other than `headers`, missing status match).
- Any other handler type → the entry's answer is `unknown` with reason `unrecognised Caddy handler <type>`.

## Entry paths (how public traffic can reach something)

| Entry path | Source address the target sees | Applies when |
|---|---|---|
| `forward` | The visitor's public address | A declared router forward (`wanPort` → `lanIp:lanPort`) reaches a port the target listens on. For Caddy: 443, and 80 for the redirect. For any other machine: that machine and port directly, Caddy not involved. |
| `tunnel-direct` | n/a (tunnel connects to the service itself) | A Cloudflare ingress rule's `service` points at a machine other than Caddy. |
| `tunnel-via-caddy` | cloudflared's address (192.168.0.108, private) as `remote_ip`; `client_ip` per the trust chain below | A Cloudflare ingress rule's `service` points at Caddy's address. The ingress hostname selects the Caddy route. |

**Client-address trust chain.** For a request arriving through a proxy, Caddy's `client_ip` is the visitor's real address only if all hold; otherwise it is **unknown** (it may be spoofable):
1. the immediate peer (cloudflared) is inside the server's `trusted_proxies` ranges, and those ranges are private and don't include `0.0.0.0/0` or other public space;
2. the address is taken from a header the proxy is known to set itself: either `client_ip_headers` is exactly a header from the configured allowlist `exposure.caddy.trustedClientIpHeaders` (default `["Cf-Connecting-Ip"]`), or `trusted_proxies_strict` is on (right-most untrusted address of `X-Forwarded-For`). The default non-strict `X-Forwarded-For` (left-most address, which a visitor can supply) does **not** qualify.
On the `forward` path the peer is the visitor, so `client_ip` equals `remote_ip` unless the peer's public address falls inside `trusted_proxies` (then unknown).

A Caddy route with a restriction is `lan` only if, for every entry path that can reach it, its restriction expression evaluates to **false** for that path's source address. If it evaluates to true on any path the route is `internet`; if no path is true but any is unknown, the route is `unknown`. So a `remote_ip` restriction blocks `forward` but **not** `tunnel-via-caddy`; a `client_ip` restriction blocks `tunnel-via-caddy` only with a complete trust chain. If the tunnel configuration can't be read, routes with restrictions are `unknown`, not `lan`.

## Review Focus

1. A gate in a separate route limited by a path matcher: requests outside that path must be `gate: none`, not gated.
2. A `handle_response` that doesn't match the verified Authentik pattern: `gate: unknown`, and the finding must not get gated urgency anywhere downstream (API, report, score).
3. Caddy shape present but stale, empty, or version 1: every Caddy-derived exposure is `unknown`; machines don't fall back to `lan`.
4. A route restricted with `remote_ip` to the LAN while a tunnel ingress points at Caddy for that hostname: `internet`, with the reason naming the tunnel.
5. A router forward straight to a VM (e.g. 2222 → 192.168.0.200:22): that VM is `internet` even though no Caddy or tunnel route mentions it.
6. An acceptance made while a finding was LAN-only or gated must stop applying when it becomes more exposed or its gate becomes unknown, version unchanged.
7. Something listening only on `127.0.0.1:8000` behind a route to `192.168.0.109:8000`: `listening: false` only if ports evidence is fresh and complete (and, on a Docker host, container evidence is fresh too); otherwise `null`.
8. A hostname reachable both through a Cloudflare-Access-protected tunnel and through the ungated router → Caddy path: effective gate `none`, full urgency.
9. A restriction like `not remote_ip <public range>` or two matcher sets where only one is restricted: evaluated as written, never as a flat list.
10. `client_ip` restricted to the LAN with cloudflared trusted but default (non-strict) `X-Forwarded-For`: `unknown`, not `lan`.
11. The Caddy admin API answering an error page, or jq failing mid-run: the previous shape file is left untouched and ages out to unknown.

---

### Task 1: Config for exposure sources and the declared router

**Files:** Modify `src/config.mjs`, `src/secrets.mjs`, `src/api/admin.mjs`, `src/api/admin-page.html`, `src/main.mjs` (secret list). Test: `tests/config.test.mjs`, `tests/api-admin.test.mjs`.

**Interfaces:**
- `exposure.caddy = { url, assetKey, address, maxAgeMinutes: 30, trustedClientIpHeaders: ["Cf-Connecting-Ip"] }` — `address` is Caddy's LAN IP (used to recognise forwards and tunnel ingress that point at it); the URL host joins `allowHttpHosts`.
- `exposure.cloudflare = { accountId, zoneId, tunnelIds: [string], assetKey, connectorAddress }` — `connectorAddress` is cloudflared's LAN IP; egress `api.cloudflare.com`; credential `cloudflare.apiToken`.
- `exposure.expectedPrivate: [hostname]` (hostnames the owner intends to be LAN-only).
- `network[]` entries gain `portForwards: [{ wanPort, lanIp, lanPort, protocol: "tcp"|"udp" }]`, `upnp`, `dmz`, `ipv6Inbound` (`true` / `false` / absent = unknown; `dmz` may be an IPv4 string).

- [ ] **Step 1: Write the failing tests** — valid blocks parse; URL, IPs, ports (1–65535), protocol and non-empty `tunnelIds` are validated; `egressHosts` adds the Caddy host and `api.cloudflare.com` only when configured; `cloudflare.apiToken` is a known, write-only, admin-settable credential.
- [ ] **Step 2: Run** `node --test tests/config.test.mjs tests/api-admin.test.mjs` — Expected: new tests FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Commit `feat: config for exposure sources and declared router settings`.

### Task 2: Caddy shape filter (version 2) and collector

**Files:** Create `deploy/caddy/shape.jq`, `deploy/caddy/export-shape.sh`, `deploy/caddy/hs-caddy-shape.service`, `deploy/caddy/hs-caddy-shape.timer`, `src/collectors/caddy-shape.mjs`; modify `.github/workflows/ci.yml`; replace `tests/fixtures/caddy-shape-live.json` (owner regenerates, Step 0). Test: `tests/collector-caddy.test.mjs`.

**Interfaces:**
- Shape v2 document: `{ version: 2, generatedAt, servers: [{ server, listen, trustedProxies: { source, ranges } | null, trustedProxiesStrict: boolean, clientIpHeaders: [string] | null, routes: [Route] }] }`. A `trusted_proxies` source other than `static` is kept as `{ source, ranges: null }` (its ranges can't be known from config → trust chain unknown).
- `Route = { group: string|null, terminal: boolean, match: [MatcherSet], handle: [Handler] }`.
- `MatcherSet = { host?, path?, remote_ip?: { ranges }, client_ip?: { ranges }, not?: [MatcherSet], unsupported: [matcherName] }` — every matcher key other than the five supported ones is listed **by name** in `unsupported` (values dropped). Nothing is silently removed.
- `Handler = { handler, upstreams?: [dial], rewrite?: uri, routes?: [Route], handleResponse?: [{ statusCodes: [number]|null, unsupportedMatch: [name], handlers: [handlerType], setsRequestHeaders: [headerName] }], other?: true }` — `handleResponse` keeps each entry's status-code match, the handler **types** inside it and the request-header **names** it sets; never header values. Handlers of unrecognised type keep only `handler`.
- `deploy/caddy/export-shape.sh` (run by the timer every 5 minutes), which must fail closed:
  - `set -euo pipefail`; a private temp file in the same directory, removed on exit.
  - `curl --fail --silent --show-error --max-time 10 http://localhost:2019/config/` into a temp file (a non-2xx answer or a timeout aborts; curl and jq are separate steps so neither failure is masked).
  - `jq -f shape.jq` into a second temp file; then **validate** it: `jq -e '.version == 2 and (.servers | type == "array" and length > 0) and ([.servers[].routes[]?] | length > 0) and (.generatedAt | type == "number")'`.
  - Only after validation: `chmod 0644` and `mv` over `/var/lib/hs-caddy/shape.json` (atomic). On any failure the previous file is left untouched, so it ages past `maxAgeMinutes` and exposure becomes unknown; the unit exits non-zero so `systemctl status` shows the failure.
- The systemd service runs the script as a dedicated unprivileged user with write access only to `/var/lib/hs-caddy`.
- `collectCaddyShape({ http, cfg, now }) → { evidence: [{ assetKey: cfg.assetKey, kind: "caddy.shape", value }] }`; rejects (code `parse`) on `version !== 2`, missing `servers`, no routes at all, `generatedAt` older than `maxAgeMinutes` or more than 5 minutes ahead.

- [ ] **Step 0 (owner, live):** run the v2 filter on the Caddy LXC after the dead-route cleanup and send the compact output; it becomes the fixture. Confirms what the real `handle_response` blocks contain.
- [ ] **Step 1: Write the failing tests** — a jq test over a planted-secret config. It is **mandatory in CI**: when `process.env.CI` is set and `jq` is missing the test fails; locally without jq it is skipped with a visible message. `ci.yml` gains a `jq --version` step before the tests. Planted config: (`api_token`, an `Authorization` header value, `client_certificate_key_file`, a `header` matcher with a secret value, a `static_response` body): no secret string appears; the `header` matcher shows up as `unsupported: ["header"]`; `group` and `trustedProxies` survive; `trustedProxiesStrict` and `clientIpHeaders` survive; `handleResponse` carries status codes, handler types and header names. Exporter tests (run `export-shape.sh` against a local stand-in for the admin API, with the paths overridable by environment variables): a good config replaces the file; an HTTP 500, a non-JSON body, a config with no routes, and a failing jq filter each leave the previous file byte-for-byte unchanged and exit non-zero. Collector: live fixture accepted; stale, future-dated, version 1, empty and malformed rejected.
- [ ] **Step 2: Run** `node --test tests/collector-caddy.test.mjs` — Expected: FAIL.
- [ ] **Step 3: Implement** the filter, units and collector.
- [ ] **Step 4: Run** — Expected: PASS. Commit `feat: Caddy route shape v2 and collector`.

### Task 3: Cloudflare collector (tunnel ingress, Access applications and policies, DNS)

**Files:** Create `src/collectors/cloudflare.mjs`, `tests/fixtures/cloudflare-fixture.mjs`. Test: `tests/collector-cloudflare.test.mjs`.

**Interfaces:**
- `collectCloudflare({ http, cfg, token, now, base = "https://api.cloudflare.com/client/v4" }) → { evidence }` on `cfg.assetKey`:
  - `cloudflare.tunnel`: `{ tunnels: [{ id, ingress: [{ hostname|null, path|null, service, jwtRequired: boolean, audTags: number }] }] }` from `GET /accounts/{acct}/cfd_tunnel/{id}/configurations`. `jwtRequired` is the tunnel-side `originRequest.access.required` and is kept as its own evidence, separate from Access applications.
  - `cloudflare.access`: `{ apps: [{ id, domains: [{ hostname, path|null }], policies: [{ decision: "allow"|"deny"|"bypass"|"non_identity", precedence, includesEveryone: boolean }] }] }` from `GET /accounts/{acct}/access/apps` (all pages) and each app's policies (inline when present, else `GET …/apps/{id}/policies`).
  - `cloudflare.dns`: `{ names: [string] }` from `GET /zones/{zone}/dns_records` (all pages).
- Bearer auth; `success !== true`, missing `result` or a paging count mismatch → reject (`parse`); 401/403 → `auth`. Any failing call fails the run.
- `accessProtection(hostname, path, apps) → "protected"|"bypassed"|"none"|"unknown"`: picks the most specific application whose domain and path cover the request (longest path wins); `bypassed` if that app has a `bypass` policy that includes everyone or any policy shape the function doesn't recognise as restricting → `unknown`; `protected` only when every policy is `allow`/`deny` with no everyone-bypass; `none` when no app covers it.

- [ ] **Step 0 (owner, live):** with the token, confirm the tunnel configuration and Access endpoints answer `success: true`; record counts in the PR.
- [ ] **Step 1: Write the failing tests** — normalisation of each endpoint; paging; a catch-all ingress rule kept and marked; an app on `example.com` with a more specific app on `example.com/api` that bypasses → `/api/x` is `bypassed`, `/` is `protected`; an unrecognised policy decision → `unknown`; `jwtRequired` preserved independently; auth and malformed responses fail the run; the token never appears in errors.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: Cloudflare tunnel, Access policies and DNS collector`.

### Task 4: Caddy route resolver

**Files:** Create `src/exposure/caddy-routes.mjs`. Test: `tests/caddy-routes.test.mjs`.

**Interfaces:**
- `classifyGate(handler) → "authentik" | "unknown" | null` per "Caddy semantics" (null = not a gate candidate).
- `resolveCaddyRoutes(shape) → { entries: [Entry], problems: [string] }` with
  `Entry = { server, hostname, path: string|null, answer: { kind: "proxy", upstream } | { kind: "static" } | { kind: "unknown", reason }, gate: "authentik"|"none"|"unknown", gateReason: string|null, restriction: Expr, conditions: "none"|"unknown", conditionReason: string|null, listen: [string], clientIp: { trustedProxies, strict, headers } }`.
  `path: null` means every path not listed separately for that host. `conditions: "unknown"` when an unsupported matcher gates the entry.
- `Expr` is the source-address condition for reaching the entry, kept as a tree: `{ op: "true" } | { op: "remote_ip", ranges } | { op: "client_ip", ranges } | { op: "and", args: [Expr] } | { op: "or", args: [Expr] } | { op: "not", arg: Expr } | { op: "unknown", reason }`. It is built from the matcher sets on the path to the entry: matchers within a set are `and`ed, sets are `or`ed, nested routes are `and`ed with their parents, and `not` wraps its sets; `host` and `path` matchers are consumed by hostname/path enumeration and don't appear. A set with no source matcher contributes `true`. Trivial simplification only (`and` with `true`, `or` containing `true`).
- `evalRestriction(expr, { remoteIp, clientIp }) → true | false | "unknown"` — three-valued: `clientIp: "unknown"` makes a `client_ip` node unknown; `and`/`or`/`not` follow Kleene logic (false and unknown = false; true or unknown = true; not unknown = unknown).

- [ ] **Step 1: Write the failing tests** (live fixture plus small synthetic shapes):

```js
test("jellyprox is an ungated proxy to 192.168.0.7:8096", ...);
test("paperless: /api/* is ungated; everything else is behind a verified Authentik gate", ...);
test("sure and wyl: a gate in its own earlier route gates the app route", ...);
test("the outpost path on gated hosts answers from Authentik with gate none", ...);
test("www.palmettotechit.com is a static response; the apex proxies to 192.168.0.213:8088", ...);
test("a gate limited by a path matcher doesn't gate other paths", ...);                       // Review Focus 1
test("handle_response that also continues on non-2xx is gate unknown", ...);                  // Review Focus 2
test("handle_response whose handlers include reverse_proxy is gate unknown", ...);
test("an earlier terminal route for the same host wins", ...);
test("routes in the same group are mutually exclusive: only the first match runs", ...);
test("matcher sets are ORed and matchers within a set are ANDed", ...);                       // host A + path /x OR host B
test("overlapping path matchers resolve by declared order", ...);
test("an unsupported matcher makes the entry's conditions unknown and names the matcher", ...);
test("one restricted and one unrestricted matcher set give an 'or' containing true, i.e. unrestricted", ...);
test("'not remote_ip 192.168.0.0/24' is kept as not(remote_ip) and evaluates true for a public address", ...);   // Review Focus 9
test("a restriction on a parent route is ANDed with a child route's restriction", ...);
test("evalRestriction is three-valued: unknown client address makes client_ip unknown; and/or/not follow Kleene logic", ...);
test("an unknown handler type makes the answer unknown with the reason", ...);
```
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: Caddy route resolver with verified gates`.

### Task 5: Exposure resolver

**Files:** Create `src/exposure/resolve.mjs`, `src/exposure/listeners.mjs`. Test: `tests/exposure.test.mjs`, `tests/listeners.test.mjs`.

**Interfaces:**
- `listenerEvidence(asset, store, now) → { ports: { rows, fresh, complete }, containers: { rows, fresh } | null, dockerHost: "configured" | "unmonitored" | "no" }` (in `listeners.mjs`). `ports.complete` requires an active agent, fresh `wazuh.ports` evidence and a non-empty port inventory (a machine reporting zero listening ports is treated as incomplete). `dockerHost` is `configured` when the asset has a Docker gate in config, `unmonitored` when its package inventory contains a container runtime (`docker-ce`, `docker.io`, `containerd`, `podman`) but no gate is configured, else `no`.
- `isListening({ ip, port, protocol }, evidence) → true | false | null`:
  - `true` when a fresh ports row has that protocol and port bound to that IP or a wildcard (`0.0.0.0`, `::`), or fresh container evidence shows a **running** container publishing that host port on that IP or a wildcard. A bind on `127.0.0.1`/`::1`, or a container that isn't running, doesn't count.
  - `false` only when **all** hold: `ports.fresh && ports.complete`, no row qualifies, and container publication is ruled out — `dockerHost === "no"`, or `dockerHost === "configured"` with fresh container evidence showing no qualifying publication. (Docker can publish a port through NAT rules without a host socket, so the socket inventory alone never proves a Docker host isn't serving a port.)
  - Otherwise `null` (including every `dockerHost === "unmonitored"` case without a positive match).
- `resolveExposure({ caddy, cloudflare, router, assets, listeners, config }) → { services: [Service], machines: Map<assetKey, MachineExposure>, problems: [Problem], sources }` where
  - `Service = { hostname, path, paths: [{ entry: "forward"|"tunnel-direct"|"tunnel-via-caddy", reachable: true|false|"unknown", gate: "authentik"|"cloudflare-access"|"none"|"unknown", gateReason }], gate: "authentik"|"cloudflare-access"|"verified-mixed"|"none"|"unknown", gateReason, upstream, assetKey|null, container|null, process|null, listening: true|false|null, exposure: "internet"|"lan"|"unknown", publicDns: true|false|null, jwtRequired: boolean|null, reason }`.
  - `MachineExposure = { exposure: "internet"|"lan"|"unknown", role: "entry"|"gate"|"app"|"direct"|null, services: [index], directForwards: [{ wanPort, lanPort, protocol }], reason }`.
  - `Problem = { kind: "dangling_route"|"upstream_not_in_inventory"|"upstream_unresolvable"|"unverified_gate"|"unsupported_condition"|"source_unreadable"|"restriction_bypassed_by_tunnel", hostname, upstream, assetKey, reason }`.
  - `sources = { caddy, cloudflare: "ok"|"stale"|"missing"|"failed", router: "declared" }`.
- Rules:
  - Entry paths per "Entry paths" above. For each path that can address the service's hostname, `reachable = evalRestriction(entry.restriction, sourceFor(path))`, where `sourceFor` gives `remoteIp` and a `clientIp` that is the visitor's address only with a complete client-address trust chain (else `"unknown"`). Exposure: `internet` if any path is reachable `true`; `unknown` if none is true but any is `"unknown"`, a needed source isn't `ok`, or `conditions` is unknown; `lan` only if every path is `false` and both sources are `ok`.
  - **Gate per path, then combined.** Each path gets its own gate: `forward` → the Caddy gate; `tunnel-direct` → `cloudflare-access` only when `accessProtection` is `protected` (`bypassed` → `none`; `unknown` → `unknown`); `tunnel-via-caddy` passes two layers in series, so it is verified if either Cloudflare Access or the Caddy gate is verified, `unknown` if neither is verified but one is unknown, else `none`. The service's effective `gate` considers only paths with `reachable` true or unknown: any `none` → `none`; else any `unknown` → `unknown`; else the single verified kind, or `verified-mixed` when paths are verified by different gates. `gateReason` names the path that decided it.
  - A declared forward to a machine other than Caddy makes that machine `internet` with role `direct`, whatever else is known about it.
  - `dangling_route` only when `listening === false`; `listening === null` is reported in the service, not as a problem.
  - Machines with no internet service or forward: `lan` only when `router.upnp === false && router.dmz === false && router.ipv6Inbound === false` and both sources are `ok`; otherwise `unknown` ("can't rule out other ways in").

- [ ] **Step 1: Write the failing tests** — from the live fixture plus an inventory mirroring the lab: Jelly-Arr `internet`/`app`; docker-auth `gate`; Caddy `entry`; pihole `lan` with all router facts false and `unknown` when `upnp` is undeclared; stale shape → Jelly-Arr `unknown` (Review Focus 3); a `remote_ip`-restricted route is `lan` with only the router forward, and `internet` with `restriction_bypassed_by_tunnel` once a tunnel ingress for that hostname points at Caddy (Review Focus 4); the same route restricted by `client_ip` is `lan` only with a complete trust chain (cloudflared trusted **and** `Cf-Connecting-Ip` or strict mode), `unknown` with cloudflared trusted but default non-strict `X-Forwarded-For` (Review Focus 10), and `internet` when cloudflared isn't trusted at all; a hostname with a Cloudflare-Access-protected tunnel path **and** an ungated forward path has effective gate `none` (Review Focus 8); the same hostname with a verified Authentik gate on the forward path is `verified-mixed`; a restricted-or-unrestricted matcher pair is `internet` (Review Focus 9); with Cloudflare evidence missing, a restricted route is `unknown`; a forward `2222 → 192.168.0.200:22` makes Management-VM `internet`/`direct` (Review Focus 5); an unverified Caddy gate yields `gate: "unknown"` plus an `unverified_gate` problem; an Access app with an everyone-bypass gives `gate: "none"`; hostname upstreams give `upstream_unresolvable`; an upstream IP with no asset gives `upstream_not_in_inventory`. `listeners.test.mjs`: wildcard and exact binds count; loopback doesn't; stopped container doesn't; stale ports → `null`; an empty port inventory → `null`; fresh complete ports with no match on a non-Docker machine → `false`; the same on a configured Docker host needs fresh container evidence, else `null`; on a machine with Docker installed but no gate → `null` (Review Focus 7).
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: exposure resolver with per-route entry paths`.

### Task 6: Exposure cycle, storage and route checks

**Files:** Modify `src/cycle.mjs`, `src/main.mjs`, `src/checks/index.mjs`; create `src/checks/exposure.mjs`; append migration v3 in `src/db.mjs`. Test: `tests/exposure-cycle.test.mjs`, `tests/checks-exposure.test.mjs`.

**Interfaces:**
- Collectors `caddy` and `cloudflare` join the normal collection. After it, `resolveExposure` runs in its own `runCollector` run (`exposure`) and stores `{ assetKey: "_global", kind: "exposure.map", source: "exposure" }`. Its stale limit equals the collection's; a failed or missing map makes all exposure `unknown` downstream.
- Migration v3: `ALTER TABLE holds ADD COLUMN context_json TEXT`.
- Checks:
  - `exposure_routes` (Caddy and Cloudflare assets): `issue` listing `dangling_route`, `upstream_not_in_inventory`, `upstream_unresolvable`, `restriction_bypassed_by_tunnel`; `unknown` when the source is stale or failed, or when only `unsupported_condition` problems prevent a verdict; `ok` with the count of public hostnames.
  - `exposure_gates` (Caddy asset): `unknown` listing hostnames whose gate is `unknown`; `ok` otherwise ("N gated routes verified").
  - `exposure_expected_private` (Caddy asset): `issue` naming each `exposure.expectedPrivate` hostname that is `internet`; `unknown` naming those that are `unknown`.
  - `collector_coverage` on network assets: reason states which router facts are declared and which are unknown.

- [ ] **Step 1: Write the failing tests** — the cycle stores `exposure.map`; the three checks produce the states above from fixtures; a failed `exposure` run makes them `unknown`; v2→v3 migration keeps holds.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: exposure cycle and route checks`.

### Task 7: Finding exposure and urgency

**Files:** Create `src/vuln/urgency.mjs`. Test: `tests/urgency.test.mjs`.

**Interfaces:**
- `findingExposure(finding, machine, services, listeners) → { exposure: "service"|"gated"|"host"|"none"|"unknown", basis: "route"|"heuristic"|"unknown", possible: "service"|"gated"|null, gate, via: hostname|null }`. Order of evaluation (gate first, attribution second):
  1. Machine `unknown` → `{ exposure: "unknown", basis: "unknown" }`. Machine `lan` → `none` / `route`.
  2. Machine role `entry` or `gate` → `service` / `route` (the whole machine is the public face).
  3. Machine role `direct` → `host` / `route`, `possible: "service"`.
  4. Machine role `app`: confirmed exposure is `host` / `route`. Then a **heuristic** upgrade is computed but not applied: if the finding's package name matches the process listening on a service's upstream port (equal, or `<process>-server`, or the process name is a prefix), `possible` is `"gated"` only when that service's **effective** gate (weakest across every reachable public path, from Task 5) is verified, and `"service"` when it is `none` or `unknown`; `basis` stays `route` for the confirmed part and the heuristic is exposed as `possible`. Kernel packages (`linux-image-*`) never get a heuristic upgrade.
- `urgency({ exposure, possible, kev, severity, fixState, lowConfidence, accepted }) → { urgent: true|false|null, possiblyUrgent: boolean, why: string }`:
  - Confirmed rule per Global Constraints on `exposure`. `urgent: null` when `kev === null` and exposure isn't `none`, or when `exposure === "unknown"`.
  - `possiblyUrgent` is true when `urgent !== true` and the rule would give `true` with `exposure` replaced by `possible`, or with `exposure: "unknown"` read as `service`, or with `kev: null` read as `true`.
  - Low-confidence or accepted → `{ urgent: false, possiblyUrgent: false }`.
- `URGENCY_RULES = 1`.

- [ ] **Step 1: Write the failing tests** — a truth table over exposure × KEV (true/false/null) × severity × fixState; Jelly-Arr kernel KEV (`host`) → urgent; Jelly-Arr high openssl with fix, no KEV → not urgent, not possibly urgent; a `jellyfin` package on Jelly-Arr with a high fixable flaw → `urgent: false`, `possiblyUrgent: true`, `possible: "service"`; the same package behind a verified gate → `possible: "gated"`, not possibly urgent unless KEV; behind an **unknown** gate → `possible: "service"` (Review Focus 2); behind a Cloudflare-protected tunnel path plus an ungated forward path → `possible: "service"`, never gated (Review Focus 8); docker-auth (role `gate`) high fixable → urgent; a low-confidence finding is never urgent, while a confirmed finding with heuristic exposure is never suppressed; KEV stale → `urgent: null`.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: finding exposure and urgency rules`.

### Task 8: Risk acceptance

**Files:** Modify `src/holds.mjs`, `src/api/admin.mjs`, `src/api/admin-page.html`. Test: `tests/holds.test.mjs`, `tests/api-admin.test.mjs`.

**Interfaces:**
- `HoldStore.add({ kind: "acceptance", assetKey, checkId: <CVE>, product: <package>, version, reason, expiresAt, context: { kev, exposure, gate } })` stores `context_json`. `gate` is the service's **effective** gate at acceptance time.
- `HoldStore.activeAcceptance(assetKey, cve, pkg, version, { kev, exposure, gate }, now) → { id, reason } | null` — null when the version differs; the finding is KEV now and wasn't then; its exposure rank rose (`none` < `gated` < `host` < `service` < `unknown`); or its effective gate went from verified to `none`/`unknown` (for example, a new ungated entry path appeared).
- Admin page: Kind `acceptance` shows Asset, CVE, Package, Version, Reason, Expires. Exposure, gate and KEV are captured server-side from current data at creation; creating one for a finding that doesn't exist is 400.

- [ ] **Step 1: Write the failing tests** — exact match on (asset, CVE, package, version); version change, new KEV, higher exposure, gate becoming unknown, and a new ungated entry path each end it (Review Focus 6); expiry ends it; it stays listed; 400 for an unknown finding.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: risk acceptance`.

### Task 9: Posture score

**Files:** Create `src/vuln/score.mjs`, `docs/scoring.md`. Test: `tests/score.test.mjs`.

**Interfaces:**
- `postureScore({ findings, coverage, freshness }) → { version: 1, state: "scored"|"incomplete", confirmed: number|null, pessimistic: number|null, incompleteReasons: [string], deductions: [{ assetKey, scenario: "confirmed"|"pessimistic", reason, points, cves }], unknowns: { urgencyUnknown, exposureUnknown, gateUnknown, heuristic }, coverage: { inScope, withoutFreshCoverage } }`.
- **Weights** (per finding, not low-confidence, not accepted): urgent 10; other high/critical with `fix-available-not-applied` 3; medium with fix 0.5; everything else 0.
- **Confirmed score:** 100 minus the sum of weights using `urgent === true` only, capped at 25 per asset, floor 0.
- **Pessimistic score:** each finding is counted **once**. Its pessimistic weight is 10 if `urgent === true`, `urgent === null` or `possiblyUrgent`; otherwise its confirmed weight. The pessimistic deduction for a finding is therefore its confirmed weight plus only the difference (a finding already costing 3 adds 7). The same 25-point per-asset cap and floor apply. `pessimistic ≤ confirmed` always.
- **Incomplete (no numbers):** `state: "incomplete"`, both scores `null`, when any holds: vulnerability findings are stale or were never read; the KEV list is missing or older than 7 days; more than **20 %** of in-scope assets lack fresh `vuln_coverage_host`; the exposure map is missing or failed. `incompleteReasons` names each.
- Deductions are grouped by asset, scenario and reason, sorted by points descending then asset key, each listing its CVEs.
- `docs/scoring.md`: the formula, both scenarios with a worked example, the cap, the incomplete thresholds, the wording `"<confirmed> based on confirmed findings; <pessimistic> in the pessimistic case"`, and that any change bumps the version.

- [ ] **Step 1: Write the failing tests** — determinism regardless of input order; per-asset cap applied to both scenarios; a finding with confirmed weight 3 that is possibly urgent lowers the pessimistic score by exactly 7 more, never 13; `pessimistic ≤ confirmed`; accepted and low-confidence findings count in neither; heuristic-only exposure affects only the pessimistic score; each incomplete condition alone yields `state: "incomplete"` with its reason and null scores; 1 uncovered asset of 22 (4.5 %) is scored, 5 of 22 (22.7 %) is incomplete; `unknowns` counts are reported.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: posture score v1 with confirmed and pessimistic scenarios`.

### Task 10: API and report

**Files:** Modify `src/api/public.mjs`, `scripts/hs-report.mjs`, `scripts/smoke.mjs`. Test: `tests/api-public.test.mjs`.

**Interfaces:**
- Finding items gain `exposure`, `exposureBasis`, `possibleExposure`, `gate`, `via`, `urgent` (true/false/null), `possiblyUrgent`, `urgencyWhy`, `accepted` (`{ id, reason }` | null). New filters `urgent=true|unknown` and `possiblyUrgent=true`. With the exposure map missing, `urgent=true` answers 409 like the KEV filter does.
- `GET /api/v1/exposure` → `{ services, problems, sources, machines: [{ assetKey, assetName, exposure, role, directForwards, reason }] }`; every service carries `gate` and `gateReason`.
- `GET /api/v1/posture` → the score object plus `rules: { urgency: 1, score: 1 }`.
- `hs-report` sections: `=== PUBLIC ROUTES ===` (hostname | path | entry paths | effective gate (`UNVERIFIED` when unknown; per-path gates shown when they differ) | upstream → machine | listening yes/no/unknown); `=== ROUTE PROBLEMS ===`; `=== URGENT ===` (machine | CVE | package | why); `=== POSSIBLY URGENT ===` (same, with what is uncertain); and either `POSTURE 72 based on confirmed findings; 41 in the pessimistic case (rules v1)` or `POSTURE incomplete: <reasons>`.

- [ ] **Step 1: Write the failing tests** — endpoints, filters, 409 without an exposure map, auth, an unknown gate shown as unknown in both endpoints, and no Cloudflare token in any response.
- [ ] **Step 2–4:** run (FAIL), implement (smoke gains Caddy and Cloudflare stand-ins), run `node --test 'tests/**/*.test.mjs' && node scripts/lint.mjs && node scripts/smoke.mjs` (PASS). Commit `feat: exposure and posture API and report`.

### Task 11: Rollout guide, review and PR

**Files:** Create `docs/rollout-phase2b.md`.

Owner steps:
1. Caddy LXC: install `deploy/caddy/` (filter, service, timer), enable the timer, confirm `/var/lib/hs-caddy/shape.json` refreshes.
2. Caddyfile: add a site serving only that file to the engine, then `caddy validate` and reload:
   ```
   http://192.168.0.105:2020 {
       bind 192.168.0.105
       @engine remote_ip 192.168.0.116
       handle @engine {
           root * /var/lib/hs-caddy
           rewrite * /shape.json
           file_server
       }
       respond 403
   }
   ```
   Port 2020 isn't forwarded by the router and no tunnel points at it; the engine will itself report this route as `lan`.
3. Cloudflare → API Tokens → custom token: Account › Cloudflare Tunnel › Read; Account › Access: Apps and Policies › Read; Zone › DNS › Read (`jellofin.com`). Nothing else. Note the account, zone and tunnel ids.
4. Config: `exposure.caddy` (with `address: "192.168.0.105"`), `exposure.cloudflare` (with `connectorAddress: "192.168.0.108"`), `exposure.expectedPrivate`, and on the `er605` entry `portForwards` (80 and 443 → 192.168.0.105), `upnp: false`, `dmz: false`, `ipv6Inbound: false`.
5. Admin page: set `cloudflare.apiToken`; pull, restart, `hs-report`.

- [ ] **Step 1:** write the guide.
- [ ] **Step 2:** independent whole-branch review; fix Critical and Important findings test-first in one pass.
- [ ] **Step 3:** push and open the PR, listing rulings and deferred minors.

## Revision notes (2026-11-16)

1. Gate verification keeps `handle_response` detail; unrecognised patterns are `gate: unknown` (Tasks 2, 4).
2. Unsupported matchers are named, not dropped; route groups, overlapping paths and OR/AND matcher logic are modelled (Tasks 2, 4).
3. Cloudflare Access protection is judged from policies and path-specific applications; tunnel-side JWT enforcement is separate evidence (Task 3).
4. LAN-only is evaluated across the complete entry path; direct router forwards expose their target (Task 5).
5. The gate is determined before a finding is attributed; package/process matching is labelled a heuristic (Task 7).
6. Listener matching requires address, protocol, running container and fresh evidence (Task 5).
7. The score separates confirmed from uncertain and can be "incomplete" (Task 9).
8. LAN-only is decided per route, per entry path, including `client_ip` and `trusted_proxies` (Tasks 2, 5).
9. `gate: unknown` is carried through resolver, API, report, urgency and acceptance (Tasks 4–10).
10. Vulnerability confidence (`lowConfidence`) and exposure confidence (`exposureBasis`, `possible`) are separate (Task 7).
11. The score range counts each finding once, applies the per-asset cap to both scenarios, and is suppressed above a 20 % coverage gap or with stale inputs (Task 9).
12. Gate status is evaluated per entry path; a service is gated only when every reachable public path has a verified gate; acceptance stores the effective gate (Tasks 5, 7, 8).
13. Restrictions stay a boolean expression through the resolver and are evaluated three-valued (Tasks 4, 5).
14. A derived client address needs a complete trust chain: trusted peer plus a proxy-set header or strict mode; otherwise unknown (Tasks 1, 2, 5).
15. `listening: false` requires complete port evidence and, where Docker can publish the port, fresh container evidence (Task 5).
16. The shape exporter fails closed (HTTP failure, pipeline failure, validation before replacement), and the jq filter test is mandatory in CI (Task 2).
