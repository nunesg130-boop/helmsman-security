# Phase 2C — Container Image Vulnerabilities — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every image used by a running container on a monitored Docker host has its known vulnerabilities listed (CVE, package, severity, fix state, KEV/EPSS, exposure, urgency), with per-host image coverage. An image that wasn't scanned, couldn't be pulled, was built locally or was scanned against an out-of-date database is **unknown**, never clean.

**Architecture:** A separate scanner worker (`hs-grype`) runs under its own system user and talks to the engine only through a spool directory. The engine writes a scan request per image digest. The worker pulls the image once with Syft into an SBOM (software bill of materials) and runs Grype on the stored SBOM. It re-runs Grype on that SBOM whenever the vulnerability database changes, without pulling again. It writes results atomically. The engine reads results in its own collector run, files findings under the Docker host with the container name, and joins them with 2B's exposure map. A route that lands on a container publishing that port gives its image **confirmed** service exposure, not the process-name heuristic.

**Tech Stack:** Node.js 24 (ESM), `node:sqlite`, `node --test`, no npm dependencies. On helmsec: Grype v0.122.0 and Syft v1.57.2 (pinned), systemd.

**Spec:** `docs/superpowers/specs/2026-11-15-security-phase2-design.md` section 4.3 (and 4.5–4.8 for exposure, urgency, score). Plan 3 of 3 for phase 2.

## Global Constraints

- Everything in the 2A and 2B plans' Global Constraints still applies: never guess, read-only, tenant rows, egress allowlist, secrets never stored or logged, power-loss safe, unknown never collapses.
- **The scanner never touches the engine's secrets.** Grype and Syft run as user `hs-grype`, which has no read access to `/var/lib/helmsman-security` or `/etc/helmsman-security`. The engine and the worker share only `/var/lib/hs-grype/spool` (requests: engine writes, worker reads) and `/var/lib/hs-grype/out` (results: worker writes, engine reads).
- **Third-party binaries are pinned and checksum-verified** before install (`deploy/grype/versions.json`). The worker refuses to start if the installed binaries' SHA-256 doesn't match.
- **The scanner's network access is allowlisted.** The worker runs a local CONNECT proxy, and Grype and Syft are started with `HTTPS_PROXY` pointing at it. It allows only the registries of queued images (and their blob hosts) plus the Grype database host. Every other connection is refused and logged.
- **Pull each image as rarely as possible.** One Syft pull per digest. Rescans run against the stored SBOM. Docker Hub pulls are capped at `images.dockerHubPullsPerHour` (default 8). A rate-limited pull is unknown ("rate-limited, retrying"), never clean.
- **Database freshness:** Grype's database build date is evidence. Older than `images.dbMaxAgeDays` (default 5): every image result is unknown ("Grype database out of date").
- Only images used by **running** containers are scanned. A container's image is identified by **registry digest**. An image with no registry digest is `local`, which is unknown unless the owner excludes it with a reason.
- The engine's own collector run stays short: it never waits on a scan. Scans run in the worker at its own pace, and each result lands in its own file (power-loss safe).

## Facts verified against the live lab (2026-11-17)

- helmsec (CT 117): 1 vCPU, 1 GB RAM, 7.8 GB disk with 6.2 GB free. The engine runs as `helmsec:helmsec`. **Rollout raises it to 2 GB RAM and +15 GB disk.**
- 3 monitored Docker hosts run 28 containers using 22 distinct images. Largest: autocaliweb 2.7 GB, byparr 2.5 GB, paperless-ngx 2.5 GB, authentik 1.2 GB, grafana 1.2 GB.
- Registries: Docker Hub (nginx, grafana, loki, portainer, postgres, valkey, gelbphoenix, qmcgaw, deluan), `ghcr.io` (authentik, aliasvault, paperless, helmsman, cleanuparr, byparr), `lscr.io` (linuxserver; it serves through ghcr.io).
- Locally built (no registry digest): `palmetto-tech-site-palmetto-tech-site`, `palmetto-tech-site-form-handler` on docker-auth.
- authentik-server and authentik-worker share one image; findings are filed per container.
- Kasm (VM 151) runs Docker (bridge addresses 172.17–19.x) but has no read-only gate, so its images can't be listed. That surfaces as unknown coverage, never as "no containers".
- Grype latest release v0.122.0 (2026-11-16). GitHub's asset digest for `grype_0.122.0_linux_amd64.tar.gz` is `sha256:e697e6f7224637df87e267e4318cc027feae99a8e1b80280241d32b9ee5d4920`.
- Syft latest release v1.57.2 (read by the owner on helmsec 2026-11-17). GitHub's asset digest for `syft_1.57.2_linux_amd64.tar.gz` is `sha256:ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b`.

## Spool protocol (engine ⇄ worker)

All files are JSON and written atomically (temp file in the same directory, `fsync`, rename). Digests are written `sha256-<hex>` in file names.

- `spool/req-<digest>.json` (engine writes): `{ v: 1, digest, ref: "<registry>/<repo>@sha256:<hex>", registry, platform: "linux/amd64", requestedAt }`. Writing it again for the same digest is a no-op.
- `out/sbom-<digest>.json` (worker): Syft JSON output, kept until the digest hasn't been requested for 14 days.
- `out/scan-<digest>.json` (worker): `{ v: 1, digest, ref, status: "scanned"|"failed", reason, dbBuilt, grypeVersion, syftVersion, scannedAt, matches: [Match] }`. `Match = { id, relatedCves: [string], severity, cvss, fixState: "fixed"|"not-fixed"|"wont-fix"|"unknown", fixVersions: [string], pkg: { name, version, type, purl }, matchType }`. Fields are copied from Grype's JSON (`matches[].vulnerability`, `.relatedVulnerabilities`, `.artifact`, `.matchDetails[0].type`).
- `out/db.json` (worker): `{ v: 1, built, schemaVersion, grypeVersion, checkedAt, status: "ok"|"failed", reason }`.
- Failure reasons are fixed strings: `pull-denied`, `not-found`, `rate-limited`, `timeout`, `too-large`, `blocked-host <host>`, `syft-error`, `grype-error`, `db-unavailable`.

## Review Focus

1. **A result scanned against an older database than the current one** (the DB updated after the scan) must not count as current coverage. The image reads "rescan pending" until rescanned, and is unknown if that takes longer than `dbMaxAgeDays` past the scan.
2. **A container whose image digest changed** (a `:latest` image updated in place) must not keep the old digest's findings as current. Results are matched by digest, never by tag.
3. **A partially written or corrupt result file** (power cut mid-write, truncated JSON) is a failed read, so that image is unknown. It never means zero vulnerabilities.
4. **Grype JSON listing a GHSA id with a related CVE** must join KEV and EPSS on the CVE. A finding with no CVE keeps its GHSA id and has `kev: null`, never `false`.
5. **Two containers from the same image on one host** (authentik server and worker) must give two sets of findings, each with its own exposure, not collide on the primary key.

---

### Task 1: Config, versions manifest, migration v4

**Files:** Modify `src/config.mjs`, `src/db.mjs`, `config.example.json`. Create `deploy/grype/versions.json`. Test: `tests/config.test.mjs`, `tests/db.test.mjs`.

**Interfaces:**
- `config.images = { enabled: boolean, spoolDir: "/var/lib/hs-grype/spool", outDir: "/var/lib/hs-grype/out", platform: "linux/amd64", dbMaxAgeDays: 5, resultMaxAgeDays: 7, dockerHubPullsPerHour: 8 } | null`. Defaults apply when `images: { enabled: true }`. Paths must be absolute.
- `deploy/grype/versions.json = { grype: { version: "0.122.0", url, sha256 }, syft: { version, url, sha256 } }`. Both entries are known: Grype 0.122.0 and Syft 1.57.2 with the digests above.
- Migration v4: rebuild `findings` with two new columns, `container TEXT NOT NULL DEFAULT ''` and `image TEXT`, and `container` added to the primary key, keeping every row (as v3 did for `holds`). New table `image_scans (tenant_id, digest, status, reason, db_built, scanned_at, read_at, PRIMARY KEY (tenant_id, digest))`.

- [ ] **Step 1:** Write the failing tests: defaults are applied; relative paths and a non-positive `dbMaxAgeDays` are rejected; a v3 database migrates to v4 keeping its findings with `container = ''`; two rows that differ only by container can coexist.
- [ ] **Step 2–4:** Run them (FAIL), implement, run them (PASS). Commit `feat: images config and findings schema v4`.

### Task 2: Running images by registry digest

**Files:** Modify `src/collectors/docker.mjs`. Create `src/images/identity.mjs`. Test: `tests/images-identity.test.mjs`, `tests/collector-docker.test.mjs`.

**Interfaces:**
- The Docker collector also reads `GET /images/json` and emits `docker.images = [{ id, repoTags, repoDigests }]`. The completeness meta from 2B covers both lists. A non-array response fails the host.
- `runningImages(containers, images) → [{ container, imageRef, status: "registry", registry, repo, digest } | { container, imageRef, status: "local", reason: "built locally, no registry digest" } | { container, imageRef, status: "unknown", reason }]`. Only `state === "running"` containers count. The container's `imageId` is matched to `images[].id`. The repo digest chosen is the one whose repo matches the container's image name (Docker Hub short names are normalised: `nginx` → `docker.io/library/nginx`). If several digests exist and none matches, the result is `unknown`.
- `registryHosts(registry) → [string]`: the hosts a pull may contact. `docker.io` → `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`. `ghcr.io` → `ghcr.io`, `pkg-containers.githubusercontent.com`. `lscr.io` → `lscr.io`, `ghcr.io`, `pkg-containers.githubusercontent.com`. Any other registry → that host only (anything else it needs shows up as a `blocked-host` failure).

- [ ] **Step 1:** Write failing tests built from the live listing:
  - `ghcr.io/goauthentik/server:2026.5.6` running twice yields two entries with one digest.
  - `nginx:1.30.6-alpine` normalises to `docker.io/library/nginx`.
  - The two palmetto images are `local`.
  - Stopped containers are skipped.
  - An image id missing from `/images/json` is `unknown`.
  - Mismatched repo digests are `unknown`.
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS). Commit `feat: running container images by registry digest`.

### Task 3: The scanner worker

**Files:** Create `deploy/grype/hs-grype-worker.mjs`, `deploy/grype/hs-grype.service`, `deploy/grype/install.sh`. Test: `tests/grype-worker.test.mjs` (fake `grype` and `syft` scripts in `tests/fixtures/grype/`).

**Interfaces:**
- `install.sh`:
  - Downloads the two pinned tarballs from `versions.json` into a temp dir.
  - Verifies SHA-256 and stops on mismatch.
  - Installs both binaries to `/usr/local/lib/hs-grype/bin/` (root-owned, 0755).
  - Creates user `hs-grype` and the directory layout:
    - `/var/lib/hs-grype` 0750 `hs-grype:hs-grype`
    - `spool` 2770 `hs-grype:helmsec`
    - `out` 2750 `hs-grype:helmsec`
    - `db` and `tmp` 0700 `hs-grype`
  - Adds `helmsec` to no new groups beyond `hs-grype`'s spool group.
  - Prints a check that `hs-grype` can't read `/var/lib/helmsman-security`.
- The worker is a long-running Node process under systemd as `hs-grype`. Its loop:
  1. Daily, and at start: run `grype db update` then `grype db status -o json`, and write `out/db.json`.
  2. For each `spool/req-*.json`:
     - If no SBOM exists, run `syft <ref> -o syft-json --platform <platform>` into `out/sbom-<digest>.json`. Respect the Docker Hub hourly cap; when over it, leave the request queued.
     - Then run `grype sbom:<file> -o json` and write `out/scan-<digest>.json`.
  3. Rescan every SBOM whose last scan's `dbBuilt` is older than the current database.
- Child processes:
  - Environment is only `PATH`, `HOME=/var/lib/hs-grype`, `TMPDIR=/var/lib/hs-grype/tmp`, `GRYPE_DB_CACHE_DIR=/var/lib/hs-grype/db`, `GRYPE_CHECK_FOR_APP_UPDATE=false`, `SYFT_CHECK_FOR_APP_UPDATE=false`, `HTTPS_PROXY`/`HTTP_PROXY=http://127.0.0.1:<proxyPort>`.
  - Timeout 20 minutes each, stdout capped at 256 MB, stderr kept to its last 4 KB for the failure reason.
- The CONNECT proxy listens on 127.0.0.1 only. It allows a host only if it's in `registryHosts()` of a currently queued request, or is the Grype database host (`grype.anchore.io` and the host its `latest.json` points to, read at update time). It refuses anything else with 403 and records `blocked-host <host>` on the scan that asked.
- systemd unit: `User=hs-grype`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/hs-grype`, `InaccessiblePaths=/var/lib/helmsman-security /etc/helmsman-security`, `MemoryMax=1536M`, `Nice=10`, `Restart=on-failure`. There's a fallback note for LXCs without namespacing, as in 2B.

- [x] **Step 1:** Syft version read by the owner: v1.57.2 (digest in Facts).
- [ ] **Step 2:** Write failing tests with the fake binaries:
  - A request produces an SBOM and then a scan result, both written atomically (no partial file is ever visible under the final name).
  - A second request for the same digest doesn't run Syft again.
  - A newer DB build triggers a Grype-only rescan.
  - Syft exiting with "unauthorized" yields `failed`/`pull-denied`.
  - A timeout yields `timeout`.
  - Output over the cap yields `too-large`.
  - The fake binary trying a non-allowlisted host through the proxy yields `blocked-host`.
  - The Docker Hub cap holds the 9th pull in an hour.
  - The worker refuses to start on a checksum mismatch.
  - The child environment contains nothing but the listed variables.
- [ ] **Step 3–4:** Run (FAIL), implement, run (PASS). Commit `feat: sandboxed Grype/Syft scanner worker`.

### Task 4: Image collector in the engine

**Files:** Create `src/images/cycle.mjs`, `src/images/classify.mjs`. Modify `src/main.mjs`, `src/vuln/findings.mjs`. Test: `tests/images-cycle.test.mjs`, `tests/images-classify.test.mjs`. Fixture: `tests/fixtures/grype/scan-authentik.json` (recorded from a real Grype v0.122.0 run in Task 3's rollout dry run; until then, a hand-made file in Grype's documented shape).

**Interfaces:**
- `classifyMatch(match) → { cve, aliases, severity, cvss, fixState, fixedVersion, lowConfidence }`:
  - `cve` is the first `CVE-` id among `id` and `relatedCves`. If there is none, `id` itself (e.g. a GHSA id).
  - `fixState`: `fixed` → `fix-available-not-applied` (with the first fix version); `not-fixed` or `wont-fix` → `no-fix-exists`; anything else → `unknown`.
  - `lowConfidence` when `matchType` is `cpe-match`.
  - Severity is normalised as in 2A.
- `imagesCycle({ db, tenantId, store, findings, config, fs, now })`: one collector run named `grype-images`, as a pure read-and-file step:
  1. From fresh `docker.containers` and `docker.images` evidence per host, compute `runningImages`.
  2. Write a request for every `registry` image (idempotent).
  3. Read `out/db.json` and `out/scan-<digest>.json`. A file that won't parse counts as a failed read.
  4. Classify each image as `scanned` (current), `pending` (no result yet, or rescan pending), `failed` (with reason), `stale-db`, or `local`.
  5. Replace the findings for source `grype`. Only current results contribute; each finding is filed under the host's asset key with its `container` and `image`.
  6. Write evidence per host, `grype.images = [{ container, imageRef, digest, status, reason, scannedAt, dbBuilt }]`, plus global `grype.db`.
- `FindingStore.list` returns `container` and `image`.

- [ ] **Step 1:** Write failing tests:
  - A current scan gives findings with container, image and CVE (GHSA → related CVE).
  - Two containers sharing a digest give two finding sets.
  - A changed digest drops the old findings and reads `pending`.
  - A result whose `dbBuilt` is older than `db.json`'s reads `pending`, and `stale-db` once the database itself is older than 5 days.
  - A truncated result file reads `failed`/`unreadable result`.
  - A missing `db.json` makes every image unknown.
  - Host-package findings (source `wazuh`) are untouched by `replaceSource("grype")`.
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS). Commit `feat: container image findings from the scanner`.

### Task 5: Image coverage check

**Files:** Modify `src/checks/vuln.mjs`, `src/checks/index.mjs`. Test: `tests/checks-vuln.test.mjs`.

**Interfaces:**
- `vuln_coverage_images` (the spec's name).
  - **Applies to:**
    - machines with a configured Docker gate;
    - machines whose package inventory contains a container runtime (as 2B's `dockerHost: "unmonitored"`), which read unknown with "Docker is installed but has no read-only gate; its images can't be listed".
  - **States:**
    - `ok`: every running image is `scanned` and current. Reason: "N images scanned, M findings".
    - `unknown`: names each image that is `pending`, `failed`, `stale-db` or `local`, with its reason.
  - **Exclusions:** a per-image exclusion uses the existing exclusion mechanism with `checkId: "image:<repo>"`. It removes that image from the unknown list and names it as excluded in the reason. A `*` exclusion excludes the whole machine, as today.
- The posture score's coverage counts `vuln_coverage_images` rows alongside `vuln_coverage_host` (in scope = applicable and not excluded).

- [ ] **Step 1:** Write failing tests:
  - All scanned → ok.
  - One pending, one local, one failed → unknown, naming all three with reasons.
  - Excluding the local image leaves the other two and names the exclusion.
  - Kasm-like machine (`docker-ce` package, no gate) → unknown.
  - No container runtime and no gate → not_applicable.
  - Score coverage counts image rows.
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS). Commit `feat: image vulnerability coverage`.

### Task 6: Confirmed service exposure for container findings

**Files:** Modify `src/vuln/urgency.mjs`, `src/vuln/annotate.mjs`. Test: `tests/urgency.test.mjs`, `tests/annotate.test.mjs`.

**Interfaces:**
- `findingExposure(finding, machine, services)`, for a finding with a `container`, on a machine with role `app`:
  - If any non-lan service on that machine has `service.container === finding.container`, the result is **confirmed**: `exposure` = `"gated"` when that service's effective gate is verified, else `"service"`; `basis: "route"`; `via` = that hostname.
  - With several such services, the weakest gate wins (as in 2B).
  - Otherwise `host` / `route`, with no heuristic upgrade for container findings: the container is known, so guessing by process name adds nothing.
- Host-package findings keep 2B's behaviour.
- `URGENCY_RULES` becomes **2**. The rule itself is unchanged; only its inputs gain confirmed container exposure. Recorded in `docs/scoring.md`.

- [ ] **Step 1:** Write failing tests:
  - An aliasvault image finding (route `vault` → container `aliasvault`, gate none, high and fixable) is **urgent** with exposure `service`.
  - The same finding behind a verified Authentik gate is `gated` (urgent only if KEV).
  - A finding in `paperless-db-1` on the same host (no route to it) is `host`.
  - An unknown gate on the route gives `service`.
  - Container findings never get `possible` set.
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS). Commit `feat: confirmed container exposure`.

### Task 7: API, report and 2B leftovers

**Files:** Modify `src/api/public.mjs`, `scripts/hs-report.mjs`, `scripts/smoke.mjs`, `src/exposure/caddy-routes.mjs`. Test: `tests/api-exposure.test.mjs`, `tests/api-public.test.mjs`, `tests/caddy-routes.test.mjs`.

**Interfaces:**
- `/api/v1/vulnerabilities` items gain `container` and `image`, plus a filter `source=wazuh|grype`. The summary per machine gains `images: { scanned, pending, failed, local, excluded }`, and its totals split host and image counts.
- `GET /api/v1/images`: per host, every running image with status, reason, digest, scannedAt, dbBuilt and finding counts, plus `db: { built, stale, status }`.
- `hs-report` gains `=== CONTAINER IMAGES ===`: `host | container | image | status | findings (critical/high) | KEV`, with the database line on top. URGENT lines name the container when there is one.
- 2B leftover: entries that differ only by restriction collapse to one display row per (hostname, path, answer) in the report. The API keeps all entries.
- Smoke test: a fake worker output directory with one scanned image, one local image and a `db.json`.

- [ ] **Step 1:** Write failing tests:
  - Endpoint shape and filters.
  - A stale database gives `db.stale: true` and every image unknown.
  - Auth and GET-only.
  - The duplicate 2020 site renders once.
- [ ] **Step 2–4:** Run (FAIL), implement, run the full suite, lint and smoke (PASS). Commit `feat: container images in API and report`.

### Task 8: Rollout guide, review, PR

**Files:** Create `docs/rollout-phase2c.md`.

Owner steps:
1. On norco: `pct set 117 --memory 2048` and `pct resize 117 rootfs +15G`, then `pct reboot 117`.
2. On helmsec: `git pull`, then `sh deploy/grype/install.sh`. It verifies checksums, creates the user and directories, and installs the unit. Then `systemctl enable --now hs-grype`.
3. Check: `sudo -u hs-grype ls /var/lib/helmsman-security` must fail. `/var/lib/hs-grype/out/db.json` must show a current build.
4. Config: `images: { enabled: true }`. Restart the engine.
5. The first full scan takes a few hours because of the Docker Hub cap. `hs-report` shows images moving from `pending` to `scanned`.
6. Decide on the two local palmetto images: exclude them with a reason ("built locally from my own source"), or leave them unknown.
7. Kasm shows "Docker installed but no gate". Adding the same nginx gate as on the other hosts is optional and can come later.

- [ ] **Step 1:** Write the guide.
- [ ] **Step 2:** Independent whole-branch review; fix Critical and Important findings test-first in one pass.
- [ ] **Step 3:** Push, open the PR listing rulings and deferred minors.

## Decisions taken here (the builder's calls, per spec section 7)

1. **Syft plus Grype instead of Grype alone.** The image is pulled once per digest into an SBOM, and each database update rescans the SBOM offline. With 22 images, several from Docker Hub's rate-limited anonymous pulls, rescanning by pulling again every day would hit the limit and move gigabytes. Cost: a second pinned binary from the same publisher.
2. **A separate worker over a spool directory**, not a child process of the engine. The engine runs as an unprivileged user and can't hand Grype a different identity. A separate systemd service under its own user is the simplest way to keep the scanner away from the engine's database and master key. It also means a long scan never holds up the engine's 15-minute cycle.
3. **Findings are filed under the Docker host with the container name**, not under a per-image asset. Exposure, acceptance and the score are per machine, and two containers from one image can be exposed differently.
4. **Results count only when scanned against the current database.** Anything else is pending or unknown.
