# Phase 2B — Exposure, Urgency, Risk Acceptance, Posture Score — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For every public route into the lab, the engine knows the hostname, the machine and port behind it, whether a login gate sits in front, and whether anything is actually listening; it uses that to mark vulnerability findings urgent, lets the owner accept specific risks, and publishes a deterministic posture score.

**Architecture:** Two new read-only sources (a Caddy route "shape" file served by Caddy itself to the engine only, and the Cloudflare API with a read-only token) plus the declared router settings feed a pure exposure resolver. Its output is stored as evidence and joined with 2A's findings to compute urgency, acceptance and the score, all as pure functions with versioned rules.

**Tech Stack:** Node.js 24 (ESM), `node:sqlite`, `node --test`, no npm dependencies; on the Caddy LXC: `jq` and a systemd timer.

**Spec:** `docs/superpowers/specs/2026-11-15-security-phase2-design.md`, sections 4.5, 4.6, 4.7, 4.8 (owner decisions of 2026-11-15 recorded there). Plan 2 of 3 for phase 2.

## Global Constraints

- Everything in the 2A plan's Global Constraints still applies (never guess, read-only, tenant rows, egress allowlist, secrets never stored or logged, power-loss safe).
- A Caddy route counts as `lan` **only** if Caddy restricts it to private source addresses (`remote_ip` / `client_ip` limited to RFC 1918). Public DNS presence never lowers exposure or urgency.
- Authentik itself, and Caddy as the entry point, are always service-exposed.
- Urgent = service-exposed and (KEV, or severity high/critical with `fix-available-not-applied`); or gated and KEV; or host-exposed and KEV. Low-confidence and accepted findings are never urgent. KEV stale → urgency for internet-reachable findings is `null` (unknown), never `false`.
- If any source a service's chain depends on is missing, stale or unparseable, that service's exposure is `unknown`, never `lan`.
- Router facts are declared in config and always labelled "declared, not verified". Undeclared `upnp`, `dmz`, `ipv6Inbound` default to unknown.
- The engine never contacts Caddy's admin API and never receives Caddy's secrets: the shape is produced on the Caddy LXC by a tested jq filter.
- Score rules carry a version number; the same evidence always gives the same score.

## Facts verified against the live lab (2026-11-16)

- Caddy has one server `srv0` listening `:443` (port 80 is Caddy's automatic HTTPS redirect, not in the config). ER605 forwards only 80 and 443 to 192.168.0.105. UPnP off, DMZ off, LAN IPv6 not delegated.
- 14 hostnames route through Caddy; none has a `remote_ip`/`client_ip` restriction. Fixture: `tests/fixtures/caddy-shape-live.json` (shape only; no secrets).
- Authentik forward auth appears as a `reverse_proxy` to `192.168.0.213:9000` with `rewrite: "/outpost.goauthentik.io/auth/caddy"` and `handle_response: true`, either inside the same route before the app's proxy (paperless, security, home) or as its own non-terminal route before the app's route (sure, wyl).
- `paperless.jellofin.com` has a `/api/*` route that proxies to Paperless **before** the gate, so `/api/*` is ungated.
- `donetick.jellofin.com` → `192.168.0.109:2021`, whose container was removed on 2026-11-15 (dangling).
- `trek.jellofin.com` → `192.168.0.232:3000` and `home.jellofin.com` → `192.168.0.180:3000`: neither address belongs to a known machine.
- Other handlers seen: `subroute`, `static_response`, `encode`, `headers`.
- The Cloudflare Tunnel is remotely managed (configured in the Cloudflare dashboard).

## Caddy route semantics the resolver must implement

Within a route list (top level or `subroute`), every route whose matchers all match runs, in order; a route with `terminal: true` stops later routes in that list. Within a route, handlers run in order. A `reverse_proxy` without `handle_response` answers the request (later handlers and routes don't run). A `reverse_proxy` **with** `rewrite` to an Authentik outpost auth path and `handle_response` is a gate: on success the chain continues. `static_response` answers. `headers` and `encode` pass through. Any other handler type makes the affected hostname's exposure path `unknown` with reason `unrecognised Caddy handler <type>`.

Resolution enumerates, per hostname, the distinct path conditions that lead to a different answer (the paths named in matchers, plus "everything else") and walks the chain for each, tracking whether a gate has run. Output per hostname and path condition: the answering upstream (or static response), and the gate (`authentik` / `none`).

## Review Focus

1. A gate in a separate non-terminal route that only matches some paths (e.g. `path` matcher on the gate route): requests outside that path must be `gate: none`.
2. A host matched in more than one top-level route (first terminal one wins): the resolver must honour order and `terminal`, not merge.
3. Caddy shape file present but older than its limit, or listing zero routes: every Caddy-derived exposure becomes `unknown`, and machines that only Caddy made `internet` don't silently fall back to `lan`.
4. Upstream given as a hostname (`jellyfin:8096`) or a Unix socket: asset unknown, reason recorded, not silently dropped.
5. An acceptance created while the finding was LAN-only must stop applying when the finding becomes internet-exposed, even if the version is unchanged.

---

### Task 1: Config for exposure sources and the declared router

**Files:** Modify `src/config.mjs`, `src/secrets.mjs`, `src/api/admin.mjs`, `src/api/admin-page.html`, `src/main.mjs` (secret list). Test: `tests/config.test.mjs`, `tests/api-admin.test.mjs`.

**Interfaces:**
- Produces config:
  - `exposure.caddy = { url: "http://192.168.0.105:2020/shape.json", assetKey: "pve:guest:105", maxAgeMinutes: 30 }` (http allowed; the host joins `allowHttpHosts`).
  - `exposure.cloudflare = { accountId, zoneId, tunnelIds: [string], assetKey }` (egress `api.cloudflare.com`; credential `cloudflare.apiToken`).
  - `network[]` entries gain optional `portForwards: [{ wanPort, lanIp, lanPort, protocol: "tcp"|"udp" }]`, `upnp`, `dmz`, `ipv6Inbound` (each `true` / `false` / absent = unknown; `dmz` may be an IP string).
- Produces credential name `cloudflare.apiToken`, settable on the admin page.

- [ ] **Step 1: Write the failing tests** — valid blocks parse; `exposure.caddy.url` must be http(s) with a host; `tunnelIds` must be a non-empty string list; port forward fields validated (ports 1–65535, IPv4 `lanIp`); `egressHosts` adds the Caddy host to `allowHttpHosts` and `api.cloudflare.com` to `allowHosts` only when configured; `cloudflare.apiToken` is a known, write-only credential.
- [ ] **Step 2: Run** `node --test tests/config.test.mjs tests/api-admin.test.mjs` — Expected: new tests FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Commit `feat: config for exposure sources and declared router settings`.

### Task 2: Caddy shape collector

**Files:** Create `src/collectors/caddy-shape.mjs`, `deploy/caddy/shape.jq`, `deploy/caddy/hs-caddy-shape.service`, `deploy/caddy/hs-caddy-shape.timer`. Test: `tests/collector-caddy.test.mjs`.

**Interfaces:**
- `deploy/caddy/shape.jq`: the filter tested on 2026-11-16, wrapped as `{version: 1, generatedAt: (now | floor), servers: [...]}`. Never emits handler fields other than `handler`, `upstreams[].dial`, `rewrite.uri`, nested `routes`, `handle_response` (as `true`), nor matcher keys other than `host`, `remote_ip`, `client_ip`, `path`, `not`.
- Timer: every 5 minutes, `curl -s localhost:2019/config/ | jq -f /usr/local/share/hs-caddy/shape.jq > tmp && mv tmp /var/lib/hs-caddy/shape.json` (atomic replace; mode 0644).
- `collectCaddyShape({ http, cfg, now }) → { evidence: [{ assetKey: cfg.assetKey, kind: "caddy.shape", value }] }`; rejects (code `parse`) on wrong `version`, missing `servers`, or `generatedAt` older than `maxAgeMinutes` or more than 5 minutes in the future; rejects when no server has any route.

- [ ] **Step 1: Write the failing tests** — a jq test (skipped when `jq` isn't installed) runs `shape.jq` over a planted-secret config (`api_token`, `Authorization` header, `client_certificate_key_file`) and asserts none of the secret strings appear and every allowed field does; collector tests: live fixture accepted; stale, future, wrong version, empty and malformed files rejected.
- [ ] **Step 2: Run** `node --test tests/collector-caddy.test.mjs` — Expected: FAIL.
- [ ] **Step 3: Implement** collector and deploy files.
- [ ] **Step 4: Run** — Expected: PASS. Commit `feat: Caddy route shape collector`.

### Task 3: Cloudflare collector (tunnel ingress, Access apps, DNS)

**Files:** Create `src/collectors/cloudflare.mjs`, `tests/fixtures/cloudflare-fixture.mjs`. Test: `tests/collector-cloudflare.test.mjs`.

**Interfaces:**
- `collectCloudflare({ http, cfg, token, now, base = "https://api.cloudflare.com/client/v4" }) → { evidence }` with three kinds on `cfg.assetKey`:
  - `cloudflare.tunnel`: `{ tunnels: [{ id, ingress: [{ hostname, path, service, access: boolean }] }] }` from `GET /accounts/{accountId}/cfd_tunnel/{id}/configurations` (`result.config.ingress[]`; `originRequest.access.required` → `access`).
  - `cloudflare.access`: `{ domains: [string] }` from `GET /accounts/{accountId}/access/apps` (all pages; `domain` and `self_hosted_domains`).
  - `cloudflare.dns`: `{ names: [string] }` from `GET /zones/{zoneId}/dns_records` (all pages, `per_page=100`).
- Bearer auth; `success !== true`, missing `result`, or a page count mismatch → reject (code `parse`); 401/403 → `auth`. A failing call fails the whole run (all-or-nothing).

- [ ] **Step 0 (live check, owner):** with the token from the rollout doc, `curl -s -H "Authorization: Bearer $T" https://api.cloudflare.com/client/v4/accounts/<acct>/cfd_tunnel/<id>/configurations | jq '.success, (.result.config.ingress | length)'` prints `true` and a count. Record the result in the PR.
- [ ] **Step 1: Write the failing tests** — normalisation of each endpoint; paging for Access and DNS; catch-all ingress rule (`service: http_status:404`, no hostname) kept but marked; auth and malformed responses fail the run; the token never appears in errors.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: Cloudflare tunnel, Access and DNS collector`.

### Task 4: Caddy route resolver

**Files:** Create `src/exposure/caddy-routes.mjs`. Test: `tests/caddy-routes.test.mjs`.

**Interfaces:**
- `resolveCaddyRoutes(shape) → { entries: [{ hostname, path: string|null, answer: { kind: "proxy", upstream: "ip:port" } | { kind: "static" } | { kind: "unknown", reason }, gate: "authentik"|"none", lanOnly: boolean, listen: [string] }], problems: [string] }` implementing "Caddy route semantics" above. `path: null` means "every path not listed separately for this host". `lanOnly` is true only when every matcher set leading to the entry restricts `remote_ip`/`client_ip` to RFC 1918 ranges.
- `isGate(handler) → boolean`: `reverse_proxy` with `handle_response` and `rewrite` starting `/outpost.goauthentik.io/auth/`.

- [ ] **Step 1: Write the failing tests** against `tests/fixtures/caddy-shape-live.json`:

```js
test("jellyprox is an ungated proxy to 192.168.0.7:8096", ...);
test("paperless: /api/* is ungated, everything else is behind Authentik", () => {
  const e = byHost("paperless.jellofin.com");
  assert.deepEqual(e.find((x) => x.path === "/api/*").gate, "none");
  assert.deepEqual(pick(e.find((x) => x.path === null)), { gate: "authentik", upstream: "192.168.0.109:8000" });
});
test("sure and wyl: a gate in its own earlier route still gates the app", ...);
test("the outpost path on gated hosts answers from Authentik", ...);
test("www.palmettotechit.com is a static response; the apex proxies to 192.168.0.213:8088", ...);
test("no route in the live config is lanOnly", ...);
test("a terminal earlier route for the same host wins", ...);              // Review Focus 2
test("a gate limited by a path matcher doesn't gate other paths", ...);     // Review Focus 1
test("an unknown handler type makes the entry unknown with the reason", ...);
test("a remote_ip 192.168.0.0/24 matcher marks the entry lanOnly; 0.0.0.0/0 does not", ...);
```
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: Caddy route resolver`.

### Task 5: Exposure resolver

**Files:** Create `src/exposure/resolve.mjs`. Test: `tests/exposure.test.mjs`.

**Interfaces:**
- Consumes: Task 4 entries; Task 3 evidence; config `network[]`; assets (with `sources.pve`, IPs from Proxmox inventory, `sources.wazuh.id`); per-asset `wazuh.ports` and `docker.containers` evidence.
- Produces `resolveExposure({ caddy, cloudflare, router, assets, listeners }) → { services: [Service], machines: Map<assetKey, MachineExposure>, problems: [Problem], sources: { caddy: "ok"|"stale"|"missing", cloudflare: …, router: "declared" } }` where
  - `Service = { hostname, path, entry: "caddy"|"tunnel", gate: "authentik"|"cloudflare-access"|"none", upstream, assetKey: string|null, container: string|null, process: string|null, listening: true|false|null, exposure: "internet"|"lan"|"unknown", publicDns: true|false|null, reason }`.
  - `MachineExposure = { exposure: "internet"|"lan"|"unknown", role: "entry"|"gate"|"app"|null, gatedOnly: boolean, services: [index] }` — the Caddy machine is `entry`; the machine serving `auth.jellofin.com` (or any gate upstream) is `gate`.
  - `Problem = { kind: "dangling_route"|"upstream_not_in_inventory"|"upstream_unresolvable"|"source_unreadable", hostname, upstream, assetKey, reason }`.
- Rules: Caddy entries are `internet` when a declared forward reaches the Caddy machine on a port Caddy listens on (443, or 80 for the redirect) and the entry isn't `lanOnly`; tunnel ingress is `internet`; anything depending on a source that isn't `ok` is `unknown`. `listening` comes from `wazuh.ports` (TCP listen on that port, any address) or a container publishing it; no ports evidence for that machine → `null` (never "dangling"). An upstream IP with no asset → `upstream_not_in_inventory`. Machines without any internet service: `lan` only when `router.upnp === false && router.dmz === false && router.ipv6Inbound === false` and all sources are `ok`; otherwise `unknown` with reason "can't rule out other ways in".

- [ ] **Step 1: Write the failing tests** built from the live fixture plus a small inventory mirroring the lab: donetick is a `dangling_route`; trek and home are `upstream_not_in_inventory`; Jelly-Arr (192.168.0.7) is `internet` / `app`; docker-auth (192.168.0.213) is `gate`; Caddy (pve:guest:105) is `entry`; pihole is `lan` with all router facts declared false and `unknown` when `upnp` is undeclared; stale Caddy shape makes Jelly-Arr `unknown` (Review Focus 3); hostname upstreams give `upstream_unresolvable` (Review Focus 4); a tunnel hostname behind Cloudflare Access gets `gate: "cloudflare-access"`; `publicDns` true/false/null from DNS evidence.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: exposure resolver`.

### Task 6: Exposure cycle, checks and storage

**Files:** Modify `src/cycle.mjs`, `src/main.mjs`, `src/checks/index.mjs`; create `src/checks/exposure.mjs`; append migration v3 in `src/db.mjs`. Test: `tests/exposure-cycle.test.mjs`, `tests/checks-exposure.test.mjs`.

**Interfaces:**
- Collectors `caddy` and `cloudflare` join the normal collection (every `collectMinutes`). After collection, `resolveExposure` runs and its result is stored as evidence `{ assetKey: "_global", kind: "exposure.map", source: "exposure" }` in its own `runCollector` run (so a failed resolution is visible and makes exposure unknown).
- Migration v3: `ALTER TABLE holds ADD COLUMN context_json TEXT` (acceptance snapshot; Task 8).
- Checks:
  - `exposure_routes` on the Caddy asset and the Cloudflare asset: `issue` listing dangling and not-in-inventory upstreams; `ok` with a count of public hostnames otherwise; `unknown` when the source is stale or failed.
  - `exposure_lan_only_unrestricted` (Caddy asset): `issue` when a hostname listed in config `exposure.expectedPrivate` (e.g. `["paperless.jellofin.com","sure.jellofin.com","security.jellofin.com","home.jellofin.com","wyl.jellofin.com"]`) is internet-reachable.
  - `collector_coverage` on network assets: reason becomes `router not readable; exposure uses declared settings (UPnP off, DMZ off, IPv6 off)` or names the undeclared ones.

- [ ] **Step 1: Write the failing tests** — the cycle stores `exposure.map`; with the live fixture the Caddy asset gets `exposure_routes: issue` naming donetick, trek and home; `exposure_lan_only_unrestricted` names the five expected-private hosts; stale shape → both `unknown`; v2→v3 migration keeps holds.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: exposure cycle and route checks`.

### Task 7: Urgency classification

**Files:** Create `src/vuln/urgency.mjs`. Test: `tests/urgency.test.mjs`.

**Interfaces:**
- `findingExposure(finding, machineExposure, services) → "service"|"gated"|"host"|"none"|"unknown"`:
  - Machine role `entry` or `gate` → `service` for every finding on it.
  - Machine `internet` with role `app`: `service` when the package is the serving process's (package name equals a listening process name from `wazuh.ports`, or `<process>-server`), else `gated` if every internet service on the machine has a gate, else `host`. `linux-image-*` and `linux-*` kernel packages → `host`.
  - Machine `lan` → `none`; `unknown` → `unknown`.
- `isUrgent({ exposure, kev, severity, fixState, lowConfidence, accepted }) → true|false|null` implementing the Global Constraints rule; `null` when `kev === null` and exposure is `service`/`gated`/`host`/`unknown`, or when exposure is `unknown` and the finding is KEV.
- Rules version constant `URGENCY_RULES = 1`.

- [ ] **Step 1: Write the failing tests** — a truth table covering every exposure × KEV(true/false/null) × severity × fixState combination the rule distinguishes; Jelly-Arr kernel KEV (host, kev) → urgent; Jelly-Arr high openssl with fix, no KEV (host) → not urgent; docker-auth (gate) high with fix → urgent; low-confidence and accepted → never urgent; KEV stale → `null`.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: urgency rules`.

### Task 8: Risk acceptance

**Files:** Modify `src/holds.mjs`, `src/api/admin.mjs`, `src/api/admin-page.html`. Test: `tests/holds.test.mjs`, `tests/api-admin.test.mjs`.

**Interfaces:**
- `HoldStore.add({ kind: "acceptance", assetKey, checkId: <CVE>, product: <package>, version, reason, expiresAt, context: { kev, exposure } })` stores `context_json`.
- `HoldStore.activeAcceptance(assetKey, cve, pkg, version, { kev, exposure }, now) → { id, reason } | null` — null when the version differs, the finding is now KEV but wasn't at acceptance, or its exposure is now more exposed than at acceptance (order: none < gated < host < service; `unknown` counts as most exposed).
- Admin page: Kind `acceptance` shows Asset, CVE, Package, Version, Reason, Expires. The current exposure and KEV are captured server-side from the latest findings at creation time (the form doesn't send them).

- [ ] **Step 1: Write the failing tests** — acceptance matches exact (asset, CVE, package, version); version change, new KEV, and more exposure each end it (Review Focus 5); expiry ends it; it stays listed; admin POST for an acceptance on a finding that doesn't exist is 400.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: risk acceptance`.

### Task 9: Posture score

**Files:** Create `src/vuln/score.mjs`, `docs/scoring.md`. Test: `tests/score.test.mjs`.

**Interfaces:**
- `postureScore({ findings, coverage }) → { version: 1, score: 0..100, deductions: [{ assetKey, reason, points, cves: [string] }], lowCoverage: boolean, coverage: { inScope, unknown } }`. Starts at 100; per finding that is not low-confidence and not accepted: urgent 10, other high/critical with `fix-available-not-applied` 3, medium with fix 0.5; per-asset cap 25; floor 0; deductions grouped by asset and reason, sorted by points desc then asset key; `urgent: null` counts as urgent for the deduction **and** sets `lowCoverage`. `lowCoverage` when more than 10 % of in-scope assets have `vuln_coverage_host` not `ok`.
- `docs/scoring.md` states the formula, the version, and that changing any weight bumps the version.

- [ ] **Step 1: Write the failing tests** — determinism (same input twice, same output; input order doesn't matter); cap per asset; floor; accepted and low-confidence ignored; low coverage at 3 of 22; every deduction lists its CVEs.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Commit `feat: posture score v1`.

### Task 10: API, report and rollout

**Files:** Modify `src/api/public.mjs`, `src/vuln/findings.mjs` (annotate list items), `scripts/hs-report.mjs`, `scripts/smoke.mjs`; create `docs/rollout-phase2b.md`. Test: `tests/api-public.test.mjs`.

**Interfaces:**
- Finding items gain `exposure`, `urgent` (true/false/null), `accepted` (`{ id, reason }` or null), `exposureReason`. New filter `urgent=true`.
- `GET /api/v1/exposure` → `{ services, problems, sources, machines: [{ assetKey, assetName, exposure, role, gatedOnly }] }`.
- `GET /api/v1/posture` → score object plus `rulesVersion: { urgency, score }`.
- `hs-report`: `=== PUBLIC ROUTES ===` (hostname | path | gate | upstream → machine | listening), `=== ROUTE PROBLEMS ===`, `=== URGENT ===` (machine | CVE | package | why urgent), and `POSTURE <score>/100 (rules v1)` with the low-coverage flag.
- `docs/rollout-phase2b.md`, owner steps:
  1. Caddy LXC: install `deploy/caddy/` files (jq filter, service, timer), enable the timer, check `/var/lib/hs-caddy/shape.json` updates.
  2. Caddyfile: add a site that serves only that file to the engine, then `caddy reload`:
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
     Port 2020 is not forwarded by the router, so this site is LAN-only; the engine itself will show it as such.
  3. Cloudflare dashboard → My Profile → API Tokens → Create custom token: Account › Cloudflare Tunnel › Read; Account › Access: Apps and Policies › Read; Zone › DNS › Read (zone `jellofin.com`); no other permissions. Note the account id, zone id and tunnel id.
  4. Config: `exposure.caddy`, `exposure.cloudflare`, `exposure.expectedPrivate`, and on `network[er605]`: `portForwards` (80 and 443 → 192.168.0.105), `upnp: false`, `dmz: false`, `ipv6Inbound: false`.
  5. Admin page: set `cloudflare.apiToken`; pull, restart, run `hs-report`.

- [ ] **Step 1: Write the failing tests** for the endpoints, the urgent filter, auth, and that no Cloudflare token appears in any response.
- [ ] **Step 2–4:** run (FAIL), implement (extend smoke with Caddy and Cloudflare stand-ins), run `node --test 'tests/**/*.test.mjs' && node scripts/lint.mjs && node scripts/smoke.mjs` (PASS).
- [ ] **Step 5: Commit** `feat: exposure and posture API, report and rollout guide`, push, open the PR.
