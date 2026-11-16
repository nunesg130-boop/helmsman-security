# Helmsman Security — Phase 2 (Know what's vulnerable) — Design

Date: 2026-11-15
Status: Written after brainstorming; reviewed by a builder check; awaiting owner approval
Scope: Phase 2 of 5. Builds on the running phase 1 engine (`2026-11-12-security-phase1-design.md`). Phase 3 (detection), 4 (compliance) and 5 (safe remediation) get their own specs.
Background: project brief `homelab-security-ops-platform.md`, build prompt `homelab-security-ops-platform-build-prompt.md`, research report `homelab-security-platform-foundations-research.md`, rollout notes `helmsman-security-rollout-notes.md` (all in the owner's "Infrastructure Projects" project) and the Jellofin Infrastructure Manual v2.6.

## 1. Intent

The owner wants to **protect their homelab**. Phase 1 answers "what is running and is it healthy". Phase 2 answers **"what is vulnerable, how much does it matter, and what should I fix first"**: every known flaw (CVE) on every machine and container, judged by whether attackers actively use it, whether a fix exists, and whether the affected service can be reached from the internet.

The never-guess rule carries over unchanged: a machine whose vulnerability data is missing or old is **unknown**, never "no vulnerabilities". Silence from a scanner is a finding, not a pass.

The owner has no coding experience. Claude builds and maintains everything.

### Success criteria
- Every vulnerability on every machine with an agent, and in every running container image, is listed with: CVE, affected package and version, severity, whether CISA lists it as actively exploited (KEV), EPSS probability, fix state, exposure, and when it was last confirmed.
- **Urgent** findings are a short list the owner can act on tonight. The exact rule is in 4.6: roughly, the vulnerable thing is what the internet talks to and it is either actively exploited (CISA KEV) or high/critical with a fix available; elsewhere on an exposed machine, only actively exploited flaws are urgent.
- Every machine and container shows its **vulnerability coverage**: scanned recently (ok) or not (unknown, with the reason). A machine is never shown as clean because nothing was reported.
- Routes meant to be private but not actually restricted in Caddy are reported, so the owner can close them (a one-line source restriction per Caddy site, done by the owner; the engine never changes Caddy).
- A **posture score** that only drops for things the owner can act on, where every lost point links to its findings, and which carries a "low coverage" flag when too much is unknown.
- Exposure is read from **live configuration** (Caddy, Cloudflare Tunnel) plus a declared router list, never from documentation. Differences between what's live and what's declared are reported.
- Still read-only end to end.

### Goals
1. Vulnerability findings for host packages (from Wazuh) and container images (from Grype).
2. Threat context from CISA KEV and EPSS, downloaded and cached locally.
3. Fix state per finding: `fix-available-not-applied` / `no-fix-exists` / `unknown`.
4. Exposure per service and per machine: `internet` / `tailnet` / `lan` / `unknown`, with the path that makes it so ("vault.jellofin.com → Caddy → 192.168.0.109:80 → container aliasvault").
5. Risk acceptance: the owner can accept a specific finding with a reason; it stays quiet until something about it changes.
6. A deterministic, versioned posture score.
7. New read-only API endpoints for all of the above.

### Non-goals (phase 2)
- Active scanning (nmap, ZAP baseline). It touches live services, so it needs rules of engagement; deferred to a later step ("2b") once read-only findings have run for a while.
- The Helmsman Security tab (display side). It stays on the to-do list and will consume these endpoints.
- Detection of attacks, alerts and push notifications (phase 3). Compliance (phase 4). Any fix or write (phase 5).
- Router and switch configuration collectors beyond the declared port-forward list (the ER605 has no usable API).
- Language-level dependency scanning of source repositories.

### Anti-goals (a failure even if it "works")
- A machine or image looking clean because its scan didn't run, failed, or returned nothing.
- Exposure computed from a document or memory instead of live configuration, or an unreadable source treated as "LAN only".
- Urgency inflated by low-confidence package matches.
- Any credential the engine holds being able to change anything (Wazuh, Cloudflare, Caddy, Docker).
- A noisy list: hundreds of "urgent" items nobody can act on.

## 2. Constraints
- Everything from phase 1 still applies: Node.js 24, no npm dependencies where avoidable, `node:sqlite`, LAN-only engine LXC (`helmsec`, 192.168.0.116) on norco, egress allowlist, power-loss safety, multi-tenant rows, nothing lab-specific hardcoded.
- Wazuh 4.14.10 all-in-one on VM 116 (192.168.0.115). Its API allows ~300 requests/min shared with the dashboard; the engine already paces itself to 120/min (PR #6).
- The engine LXC was sized for phase 1 (≈1 vCPU, 1 GB RAM, 8 GB disk). Grype's database and image pulls need more disk (see 4.3); resizing the LXC is an owner step.
- Home power is unstable with no UPS; every new job must survive being killed halfway.
- Security tools are themselves targets (Trivy compromise, March 2026). Every third-party binary is pinned to an exact version and checksum-verified, and runs with no access to the engine's stored credentials.

### The lab's public surface (owner-confirmed 2026-11-15, matches manual v2.6 appendix B)
| Path in | Services |
|---|---|
| Internet → ER605 (ports 80/443 forwarded) → Caddy 192.168.0.105 | Jellyfin `jellyprox`, Seerr `seerprox`, AliasVault `vault`, Authentik `auth`, Kasm `manage`, Paperless, Navidrome, the owner's business site (VM 201), Helmsman (planned) |
| Internet → Cloudflare Tunnel (remotely managed in the Cloudflare dashboard) → cloudflared LXC 192.168.0.108 | Home Assistant, management paths |
| Tailscale | Home Assistant and selected systems (tailnet only, not internet, unless Funnel is enabled) |

Phase 2 must **verify** this from live sources, not encode it. The table is the expected answer the engine's output gets compared against. A known leftover to verify: the Donetick "Caddy route" to 192.168.0.109:2021, whose container was removed on 2026-11-15.

## 3. Approaches considered

| Approach | Trade-off | Outcome |
|---|---|---|
| **A. Wazuh matches host CVEs; the engine adds judgment; Grype covers container images** | Reuses the agents and Wazuh's vulnerability module (NVD, OSV, CISA, vendor feeds), so no CVE database to run for hosts. Depends on Wazuh's matching quality; the engine treats stale Wazuh data as unknown. Grype fills the gap Wazuh can't see (inside images). | **Chosen** (owner handed the "how" to Claude). |
| B. Engine mirrors NVD/OSV itself and matches package lists | Independent of Wazuh, but gigabytes of data to mirror and keep fresh, several times the work, and duplicates something already running. | Rejected; revisit only if Wazuh's matching proves unreliable. |
| C. Vuls (agentless) for hosts | Good fix-state model, but needs SSH into every host — the credential blast radius phase 1 deliberately avoided. | Rejected. |

## 4. Design

```
 Wazuh indexer (wazuh-states-vulnerabilities-*) ──┐
 Grype (pinned) ← registry images by digest ──────┤
 CISA KEV + EPSS feeds (daily) ───────────────────┤
 OSV API (fix versions, when Wazuh lacks them) ───┤──▶ engine: findings → fix state → exposure → urgency → score
 Caddy config (read-only gate) ───────────────────┤
 Cloudflare Tunnel config (read-only API token) ──┤
 Declared ER605 port forwards (config) ───────────┤
 Phase 1 evidence: Wazuh ports, Docker containers ┘
```

### 4.1 Host vulnerabilities from Wazuh
- Source: the Wazuh **indexer** (OpenSearch, 192.168.0.115:9200), index pattern `wazuh-states-vulnerabilities-*`. This is the documented way to read vulnerability state in 4.14; the server API has no vulnerability endpoint.
- Credential: a new indexer user (e.g. `helmsec-vuln-ro`) with a role granting only `read` / `search` on `wazuh-states-vulnerabilities-*` (and nothing else). TLS pinned to the indexer certificate, like the other sources. Stored encrypted as credential `wazuh.indexerPassword`.
- Requests are paged (search-after or scroll), bounded, and paced; one query per agent or one paged query overall is the builder's call.
- Each document becomes a finding: agent id → asset (via phase 1 linking), CVE id, package name/version/architecture, severity, CVSS base score, detection time, Wazuh reference.
- **Freshness**: a host's Wazuh vulnerability data is fresh only if (a) the agent is active, (b) its package inventory evidence is fresh, and (c) Wazuh's vulnerability content is current. How to read (c) from 4.14 (manager CTI/content status) must be verified against the live server during planning; if it can't be read, (c) is treated as satisfied only while the Wazuh collector is ok, and the spec's verification step records that limitation.
- A host with an agent but **no** documents is not "clean": it is ok only if the agent's inventory is fresh and the vulnerability module has evaluated that agent (verify how to tell during planning); otherwise unknown ("Wazuh hasn't evaluated this machine").
- Version adapter: this goes into the Wazuh adapter interface (`vulnerabilities()`), so Wazuh 5.x stays a second adapter.

### 4.2 Fix state
- `fix-available-not-applied`: a fixed version exists for this OS release and the installed version is lower.
- `no-fix-exists`: the distribution/vendor says no fix yet (e.g. Debian "unfixed", OSV with no fixed range).
- `unknown`: anything else, including no data.
- Source order (builder verifies against a real Wazuh document first): Wazuh's own fields if 4.14 includes a fixed version; otherwise OSV (`api.osv.dev` batch query by ecosystem + package + version, e.g. `Debian:13`, `Ubuntu:24.04`). For container findings, Grype's fix state (`fixed` with version / `not-fixed` / `wont-fix` / `unknown`) maps directly; `wont-fix` maps to `no-fix-exists`.

### 4.3 Container images with Grype
- Image list comes from the phase 1 Docker collector (`/images/json` via the read-only gates), deduplicated by **digest**. Only images used by running containers are scanned.
- Grype runs **on the engine LXC**, scanning `registry:<repo>@<digest>` directly from the registry. It never talks to the Docker hosts and needs no Docker socket.
- Pinned Grype version, binary checksum verified at install. Runs as a child process with a minimal environment (no engine credentials, no engine database access), JSON output, hard timeout, size cap on output.
- Grype vulnerability database: updated at most daily from Anchore; its build date is evidence. Older than 5 days → every image result becomes unknown ("Grype database out of date").
- Results are cached by digest; an unchanged digest is rescanned only when the database updates.
- An image that can't be pulled (private registry, deleted tag, rate limit) is unknown with that reason, never clean.
- *(Builder's call)* Locally built images (no registry digest) can't be scanned this way. They stay **unknown** ("built locally, no registry digest") and count toward coverage, so the owner sees them. The owner can exclude a specific image with a reason through the existing exclusion mechanism, which removes it from the coverage flag but keeps it listed as excluded. Registry credentials and image export through the Docker gates are out of scope.
- Disk: the LXC needs roughly +10 GB (database plus temporary layers; exact figure measured in the first run). Owner resizes the LXC before deploy.
- Egress allowlist grows to the registries actually in use (taken from the image list: e.g. `ghcr.io`, Docker Hub hosts, `lscr.io`) plus Grype's database host. The allowlist is generated from configuration and the current image list, and shown on the admin page.

### 4.4 Threat context
- **CISA KEV** JSON feed and **EPSS** daily scores, downloaded once a day over TLS, stored with their fetch time. Older than 7 days → KEV/EPSS-dependent fields are unknown (and urgency falls back to "unknown", not "not urgent").
- Low-confidence matches: a finding whose package match the source marks as fuzzy/CPE-only is flagged `lowConfidence` and never counts as urgent or in the score; it is still listed.

### 4.5 Exposure
For each listening service, decide: `internet`, `tailnet`, `lan`, or `unknown`, with the path.

Sources:
1. **Caddy routes**, read from Caddy's admin API (`GET /config/`) through a read-only gate on the Caddy LXC: the same nginx pattern as the Docker gates — only `GET /config/` (and sub-paths), only from 192.168.0.116, port of the builder's choice, Host header rewritten to what Caddy's admin API accepts (it rejects unexpected Host/Origin values). Caddy's admin API can change configuration, so the gate is the only path to it; the engine strips secrets (TLS keys, DNS-provider tokens, forward-auth secrets) from the config before storing it, using the existing redaction rules plus a Caddy-specific list.
2. **Cloudflare Tunnel** ingress rules from the Cloudflare API (tunnel configuration endpoint) with one dedicated, read-only API token: **Cloudflare Tunnel: Read** and **Access: Apps and Policies Read** on the one account (to see which tunnel hostnames sit behind Cloudflare Access), plus **Zone DNS: Read** on the `jellofin.com` zone (to record which hostnames are in public DNS). Stored encrypted as credential `cloudflare.apiToken`. Config: account id, zone, tunnel id(s).
3. **ER605 port forwards**: declared in config (`network[].portForwards: [{ wanPort, lanIp, lanPort, protocol }]`) because the router has no API. Every result derived from it is labelled "declared, not verified".
4. **Listening sockets** from phase 1 evidence (Wazuh `ports`) and Docker published ports.
5. *(Builder's call)* **Other ways in** that phase 2 can't read: IPv6 reaching LAN hosts directly, UPnP on the ER605, a DMZ host. Config has `network[].ipv6Inbound`, `upnp`, `dmz` declarations, each defaulting to **unknown**. While any is unknown, the router asset shows it as a coverage gap ("can't confirm nothing else reaches the LAN from the internet"), and no machine's exposure is downgraded to `lan` on the strength of the forward list alone — such machines read `lan (unverified)`, which never counts as safe in the score's coverage flag.
6. Tailscale: phase 2 treats tailnet reachability as `tailnet` only where declared in config; reading the Tailscale API (to detect Funnel) is a later addition. Until then, Funnel status is unknown and listed as a coverage gap.

Resolution (owner-decided 2026-11-15):
- **Caddy chooses a site by the requested hostname, not by the visitor's address.** Any Caddy route is therefore reachable from the internet once 80/443 are forwarded to Caddy, whether or not its hostname is in public DNS. A Caddy route counts as `lan` **only** if Caddy itself restricts it to private source addresses (a `remote_ip` / `client_ip` matcher, or equivalent, limited to RFC 1918 ranges). Anything else reachable through the forward is `internet`.
- Whether a hostname is in public DNS (from Cloudflare DNS) is recorded as an attribute (`publicDns: yes/no/unknown`) and shown, but it **never lowers exposure or urgency**: an unlisted name is hidden, not locked (and names with publicly issued certificates are discoverable in Certificate Transparency logs anyway).
- Each route records its **login gate**: `authentik` (Caddy `forward_auth` to Authentik), `cloudflare-access`, or `none`. A gate lowers urgency (4.6) but never changes the exposure class.
- A route is **internet** if its entry point is reachable from the internet (Caddy with a declared 443/80 forward to it, or the Cloudflare Tunnel) and its upstream resolves to `ip:port`.
- The upstream `ip:port` is mapped to an asset (by IP, using phase 1 linking) and to a container (published port) or host process (Wazuh ports) where possible.
- If any source needed for a service's chain can't be read or is stale, that service's exposure is **unknown**, never `lan`.
- Upstreams that point at nothing listening (e.g. the old Donetick route) are reported as **dangling routes**, an issue in their own right.
- Live vs declared/expected differences are reported (a public hostname that isn't in the expected table, or the reverse).

Applying exposure to findings:
- **Service-exposed**: the vulnerable component *is* what serves an exposed route with no login gate in front (the container image behind it, or the host package owning the listening process when Wazuh reports the process). The login gate itself (Authentik, and Caddy as the entry point) is always service-exposed.
- **Gated**: the vulnerable component serves an exposed route that sits behind a login gate.
- **Host-exposed**: the vulnerable package is on a machine that serves an exposed route, but isn't tied to that service.
- Otherwise the machine's best exposure (`tailnet` / `lan` / `unknown`).

### 4.6 Urgency and posture score
- **Urgent** (owner-decided 2026-11-15) = service-exposed and (KEV, or severity high/critical with `fix-available-not-applied`); or gated and KEV; or host-exposed and KEV. Low-confidence and accepted findings are never urgent. If KEV data is stale, urgency for internet-exposed findings is `unknown` rather than "not urgent".
- **Posture score v1** (versioned, deterministic, documented in `docs/scoring.md`): starts at 100; deducts for actionable, unaccepted, non-low-confidence findings — urgent 10 each, other high/critical with a fix 3 each, medium with a fix 0.5 each — capped per asset so one machine can't take the whole score; floor 0. Every deduction links to its findings. "Low coverage" flag when more than 10 % of in-scope assets/images have unknown vulnerability coverage. Exact weights are the builder's call within this shape, recorded with the score version so old scores stay reproducible.

### 4.7 Risk acceptance
- New kind `acceptance` alongside holds and exclusions (same table and admin page): asset, CVE, package, installed version, reason, optional expiry.
- Fingerprint = (asset, CVE, package, version). If the version changes, or the finding newly becomes KEV or internet-exposed, the acceptance stops applying and the finding returns.
- Accepted findings stay listed and counted as "accepted", never as fixed.

### 4.8 Ledger and API
- New table for findings (tenant, asset, source, CVE, package, version, severity, CVSS, KEV, EPSS, fix state, fixed version, exposure + path, urgent, low confidence, first seen, last confirmed, accepted).
- New per-asset checks in the existing ledger: `vuln_coverage_host`, `vuln_coverage_images` (ok / unknown / not_applicable), `urgent_vulnerabilities` (issue when any urgent finding is open), `dangling_routes` on the Caddy/tunnel assets.
- The `er605` coverage unknown stays (no collector), but its declared forwards are shown with "declared, not verified".
- New GET endpoints (same token, paging, size caps): `/api/v1/vulnerabilities` (filters: urgent, asset, exposure, KEV, fix state), `/api/v1/exposure` (services and paths), `/api/v1/posture` (score, version, deductions, coverage flag).
- `hs-report` gains an urgent-findings section and the score.

## 5. Quality bar
- Tests first for: fix-state mapping, exposure resolution (including unreadable sources → unknown, dangling routes), urgency rules, acceptance fingerprints, score determinism (same evidence → same score), redaction of Caddy config.
- Fixtures recorded from the live lab (sanitised): one real `wazuh-states-vulnerabilities` page, one Caddy `/config/` (secrets replaced), one Cloudflare tunnel configuration, one Grype JSON. Malformed, empty, auth-failure, timeout and stale cases all yield unknown.
- Power-loss test for a run interrupted mid-Grype-scan.
- Soak test against a copy of the live database before deploy (first use of this gate).
- Pinned, checksum-verified Grype; pinned nginx for the Caddy gate.

## 6. Rollout (owner steps are copy-paste, guided)
1. Resize the engine LXC disk (+10 GB).
2. Create the Wazuh indexer read-only user and role (guided, in the Wazuh dashboard).
3. Create the Cloudflare API token (Tunnel: Read only) and note the account and tunnel ids.
4. Deploy the read-only gate on the Caddy LXC; test from helmsec (allowed) and elsewhere (refused).
5. Add the declared ER605 port forwards to config (owner reads them from the router UI).
6. Deploy the new engine version, enter the two new credentials on the admin page.
7. Review the first results with Claude: urgent list, dangling routes, live-vs-expected exposure differences, coverage unknowns.

## 7. Left to the builder
Module layout, SQLite schema details, paging and caps, the exact Grype version (latest stable at build time, pinned), how KEV/EPSS are stored, exact score weights within 4.6, Caddy-gate port and Host-header value, and how the registry allowlist is presented.

## 8. Open questions (to verify during planning, against the live lab)
- Does a 4.14 `wazuh-states-vulnerabilities` document carry a fixed version / fix status? (Decides whether OSV is needed.)
- How to tell, from 4.14, that the vulnerability module has evaluated a given agent and that its content is current.
- Which ports the ER605 actually forwards (owner reads from the router UI).
