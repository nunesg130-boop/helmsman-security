# Helmsman Security Engine — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the LAN-only `helmsman-security` engine. It collects inventory and health evidence from Proxmox, Wazuh 4.14, Docker and endoflife.date, judges every (asset, check) pair as ok / issue / unknown / not_applicable / excluded, and serves the results on a read-only API.

**Architecture:** Collectors write evidence into SQLite inside one transaction per run. Pure check functions read evidence through one central runner. The runner turns missing, stale, future-dated or failed-collector evidence into `unknown` before any check logic runs. A coverage ledger stores the results. Two HTTP listeners serve them: a token-protected GET-only API for Helmsman, and an admin listener that only accepts the Caddy host plus the Authentik owner header.

**Tech Stack:** Node.js 24 (ESM), built-in `node:sqlite`, `node:test`, `node:https`, `node:crypto`. No npm dependencies.

**Spec:** `docs/superpowers/specs/2026-11-12-security-phase1-design.md` (a copy of the Helmsman repo spec, kept in sync).

**Out of this plan:** Helmsman's Security connector and workspace (a separate plan, written once this API exists), and the owner's infrastructure runbook (Wazuh VM, agents, credentials, LXC). Neither is code in this repo.

## Global Constraints

- Node `>=24.19.0 <25`, `"type": "module"`, zero npm dependencies (`package.json` has no `dependencies`/`devDependencies`).
- Every table has `tenant_id TEXT NOT NULL`. Every query filters by it. The default tenant id is `"default"`.
- Result states are exactly `ok`, `issue`, `unknown`, `not_applicable`, `excluded`. A check can never return `ok` without fresh evidence.
- No LLM is involved anywhere.
- The engine makes no write calls to any upstream. Upstream HTTP methods are `GET` only, except `POST /security/user/authenticate` (Wazuh login).
- Egress allowlist: configured Proxmox, Wazuh and Docker-proxy hosts, plus `endoflife.date`. Every other host is refused before connecting.
- Default thresholds (config keys, all overridable): `collectMinutes: 15`, `staleFactor: 3` (evidence stale after 45 min), `eolRefreshHours: 24`, `eolMaxAgeDays: 7`, `backupMaxAgeDays: 2`, `clockDriftSeconds: 5`, `storageFillPct: 85`, `ssdLifeRemainingPct: 10`.
- Secrets never appear in logs, errors, API responses or evidence. Error strings pass through `redact()` (Task 10).
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_014qq3h471xA47WJUgpbcwCv
  ```

## Review Focus

1. **Engine clock behind or ahead after a power loss.** If `collectedAt > now`, the evidence is "from the future" and must read `unknown` ("clock moved backwards"), never fresh. The test lives in Task 4.
2. **A successful but empty answer.** Wazuh returns zero packages for a newly enrolled agent whose first syscollector scan hasn't finished. This must produce `unknown` ("no inventory yet"), not `ok`. The tests live in Task 12 (the adapter marks it) and Task 6 (the EOL check honours it).
3. **Disks that don't report SMART health or wear.** USB drives, some HDDs and RAID passthrough disks report `health: "UNKNOWN"` or `wearout: "N/A"`. Those disks must be `unknown`, and the check must not pass on the other disks. The test lives in Task 7.
4. **A re-enrolled Wazuh agent.** The old, disconnected agent and the new agent share a MAC address. The guest must be ambiguous (with a reason telling the owner to remove the old agent in Wazuh), never auto-linked. The test lives in Task 9.
5. **Credentials leaking through error text.** A Proxmox `401` body, or a URL containing `PVEAPIToken=…`, must not reach `lastError` in the API. The test lives in Task 10.

---

## File structure

```
package.json                     scripts: test, smoke, lint
.github/workflows/ci.yml         Node 24: lint + test + smoke
Dockerfile, .dockerignore
config.example.json
src/
  states.mjs                     STATES, result()
  version.mjs                    compareVersions()
  db.mjs                         openDb(), schema migrations
  evidence.mjs                   EvidenceStore (runs + evidence)
  collect.mjs                    runCollector()
  checks/runner.mjs              runCheck(): central unknown rule
  checks/agent.mjs               agent_connected, agent_present
  checks/eol.mjs                 os_eol, software_eol, eolCycle()
  checks/disk.mjs                disk_health
  checks/backup.mjs              backup_jobs, backup_storage
  checks/clock.mjs               clock_drift
  checks/reboot.mjs              pending_reboot, newestKernel()
  checks/windows.mjs             windows_failed_updates
  checks/index.mjs               CHECKS (ordered registry)
  identity.mjs                   linkAssets()
  holds.mjs                      HoldStore
  ledger.mjs                     evaluateAll(), LedgerStore
  http.mjs                       fetchJson(), CollectorError, redact()
  collectors/proxmox.mjs         collectProxmox()
  collectors/wazuh414.mjs        createWazuh414(): the version adapter
  collectors/wazuh.mjs           collectWazuh(): uses an adapter
  collectors/docker.mjs          collectDocker()
  collectors/eol-dataset.mjs     collectEolDataset()
  secrets.mjs                    createSecretBox(), CredentialStore
  config.mjs                     loadConfig()
  scheduler.mjs                  startScheduler()
  api/public.mjs                 createPublicServer()
  api/admin.mjs                  createAdminServer()
  main.mjs                       wiring + startup recovery
scripts/smoke.mjs                end-to-end run against fixture servers
tests/…                          one test file per src module
tests/fixtures/{proxmox,wazuh414,docker,eol}/*.json
tests/helpers/fixture-server.mjs local HTTPS server serving fixtures
```

---

### Task 1: Repo scaffold, states and version comparison

**Files:**
- Create: `package.json`, `.gitignore`, `.github/workflows/ci.yml`, `README.md`, `src/states.mjs`, `src/version.mjs`
- Test: `tests/states.test.mjs`, `tests/version.test.mjs`

**Interfaces:**
- Produces: `STATES` (frozen array of the five states); `result(state: string, reason: string, evidence?: EvidenceRef[]) -> {state, reason, evidence}`, which throws `TypeError` for an unknown state or an empty reason; `compareVersions(a: string, b: string) -> -1|0|1`.

- [ ] **Step 1: Write the failing tests**

```js
test("result rejects states outside STATES", () => assert.throws(() => result("green", "x"), TypeError));
test("result requires a reason", () => assert.throws(() => result("ok", ""), TypeError));
test("compareVersions orders numeric segments", () => {
  assert.equal(compareVersions("6.8.12-4-pve", "6.8.12-10-pve"), -1);
  assert.equal(compareVersions("6.11.4-301.fc41", "6.11.4-301.fc41"), 0);
  assert.equal(compareVersions("1:2.3", "2.4"), 1); // a Debian epoch wins
});
```

- [ ] **Step 2: Run `node --test tests/` and verify that both files fail**
- [ ] **Step 3: Implement**

`package.json` scripts: `"test": "node --test tests/"`, `"lint": "node scripts/lint.mjs"` (runs `node --check` on every `.mjs` under `src/`, `scripts/`, `tests/`), `"smoke": "node scripts/smoke.mjs"`. `compareVersions` splits on the epoch `:`, then compares runs of digits numerically and non-digit runs lexically. CI runs `npm run lint && npm test && npm run smoke` on Node 24.

- [ ] **Step 4: Run `npm test` and confirm PASS**
- [ ] **Step 5: Commit "Scaffold engine repo with states and version compare"**

### Task 2: Database and tenant isolation

**Files:**
- Create: `src/db.mjs`
- Test: `tests/db.test.mjs`

**Interfaces:**
- Produces: `openDb(file: string) -> DatabaseSync` (WAL mode, `foreign_keys=ON`, migrations applied, `PRAGMA user_version` = schema version).

Tables (all have `tenant_id`):
- `runs(id INTEGER PK, tenant_id, collector, started_at, finished_at, status CHECK IN ('running','ok','failed'), error, warnings_json)`
- `evidence(tenant_id, asset_key, kind, source, run_id, collected_at, stale_after_ms, payload_hash, value_json, PK(tenant_id, asset_key, kind, source))`
- `assets(tenant_id, asset_key, class CHECK IN ('host','guest','roaming','appliance','container','network'), name, sources_json, last_seen_at, PK(tenant_id, asset_key))`
- `holds(id INTEGER PK, tenant_id, kind CHECK IN ('hold','exclusion'), asset_key, check_id, product, version, reason NOT NULL, expires_at, created_at)`
- `manual_links(tenant_id, asset_key, source, source_id, PK(tenant_id, source, source_id))`
- `ledger(tenant_id, asset_key, check_id, state, reason, evidence_json, evaluated_at, last_ok_at, state_since, PK(tenant_id, asset_key, check_id))`
- `credentials(tenant_id, name, sealed, updated_at, PK(tenant_id, name))`

- [ ] **Step 1: Write the failing tests:** `openDb sets WAL`, which asserts `journal_mode` is `"wal"`; `migrations are idempotent`, which opens the same file twice and checks `user_version` is unchanged; and `every table has tenant_id`, which loops over `sqlite_master` and runs `pragma table_info` on each table.
- [ ] **Step 2: Run, and expect FAIL**
- [ ] **Step 3: Implement `openDb`** with ordered migration functions keyed by version.
- [ ] **Step 4: Run, and expect PASS**
- [ ] **Step 5: Commit "Add SQLite schema with tenant column on every table"**

### Task 3: Evidence store, collector runs and crash recovery

**Files:**
- Create: `src/evidence.mjs`, `src/collect.mjs`, `tests/helpers/slow-run.mjs`
- Test: `tests/evidence.test.mjs`, `tests/power-loss.test.mjs`

**Interfaces:**
- Produces:
  - `new EvidenceStore(db, tenantId)` with:
    - `beginRun(collector: string, now: number) -> number`
    - `finishRun(runId, status: 'ok'|'failed', {error?: string, warnings?: string[]}, now)`
    - `failOpenRuns(now) -> number`, which sets every `running` row to `failed` with the error `"interrupted (engine stopped mid-run)"`
    - `put(runId, {assetKey, kind, source, value, collectedAt, staleAfterMs})`, where `payload_hash` is the sha256 of canonical JSON (sorted keys)
    - `get(assetKey, kind) -> Evidence|null`, where `Evidence = {assetKey, kind, source, value, collectedAt, staleAfterMs, runId}`
    - `lastRun(collector) -> {status, startedAt, finishedAt, error, lastSuccessAt}|null`
  - `runCollector(store, name: string, fn: () => Promise<{evidence: EvidenceInput[], warnings?: string[]}>, {now: () => number, staleAfterMs: number}) -> Promise<{status, runId}>`. It calls `beginRun` first, outside any transaction. On success, every `put` and `finishRun('ok')` happen in **one** `BEGIN IMMEDIATE…COMMIT`. On a throw it calls `finishRun('failed', {error: redact(err.message)})` and writes no evidence.

- [ ] **Step 1: Write the failing tests**
  - `tenant B cannot read tenant A evidence`: `put` as `"a"`, then `get` as `"b"` returns `null`.
  - `failed run writes no evidence`: `fn` throws, and `get` returns the previous value unchanged.
  - `successful run replaces evidence atomically`.
  - `power loss mid-run`: spawn `node tests/helpers/slow-run.mjs <dbfile>`, which begins a run, opens the transaction, puts one row and then waits forever. The parent waits for its `"ready"` stdout line, sends `SIGKILL`, reopens the db and asserts that `failOpenRuns()` returns `1` and `get()` returns `null`.
- [ ] **Step 2: Run, and expect FAIL**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run, and expect PASS**
- [ ] **Step 5: Commit "Add evidence store with atomic runs and interrupted-run recovery"**

### Task 4: Central check runner (the "never guess" rule)

**Files:**
- Create: `src/checks/runner.mjs`
- Test: `tests/runner.test.mjs`

**Interfaces:**
- Consumes: `EvidenceStore.get`, `EvidenceStore.lastRun`, `result()`.
- Produces:
  - `CheckDef = {id: string, title: string, requires: string[] /* evidence kinds */, appliesTo(asset) -> boolean, evaluate(inputs: Record<kind, Evidence>, ctx) -> Result}`
  - `runCheck(check, asset, ctx: {store, holds: HoldStore, config, now: number}) -> Result`
  - `Asset = {assetKey, class, name, sources, ambiguous?}`
  - `evidenceKey(asset, kind) -> string|null`: kinds starting `wazuh.` resolve to `wazuh:agent:<asset.sources.wazuh.id>` (null when the asset has no agent, which reads as missing evidence). Every other kind resolves to `asset.assetKey`. This is how agent evidence attaches to linked Proxmox assets without copying rows.

The runner applies these rules in order, and the first match wins:
1. `!appliesTo(asset)` gives `not_applicable` ("does not apply to <class>").
2. An active exclusion for (asset, check) gives `excluded`, with the exclusion's reason.
3. For each required kind, the evidence is unusable when:
   - it is missing: "no <kind> evidence";
   - `collectedAt > now + 60000`: "evidence dated in the future (clock moved?)";
   - `now - collectedAt > staleAfterMs`: "<kind> last confirmed <age> ago";
   - the last run of its `source` collector is `failed`: "<source> collection failing: <error>".

   Unusable evidence gives `unknown`. If several kinds are unusable, the reasons are joined with "; ".
4. Otherwise it calls `evaluate`. If that throws, the result is `unknown` "check error: <message>". If the check returns `ok`, the runner attaches evidence refs `{assetKey, kind, source, collectedAt}` for each input.

- [ ] **Step 1: Write the failing tests:** one per rule above, plus `evaluate cannot return ok when a required kind is missing even if evaluate would` (a stub evaluate always returns `ok`) and `future-dated evidence is unknown` (Review Focus 1).
- [ ] **Step 2: Run, and expect FAIL**
- [ ] **Step 3: Implement `runCheck`**
- [ ] **Step 4: Run, and expect PASS**
- [ ] **Step 5: Commit "Add check runner that turns missing or stale evidence into unknown"**

### Task 5: Agent checks

**Files:**
- Create: `src/checks/agent.mjs`
- Test: `tests/checks-agent.test.mjs`

**Interfaces:**
- Consumes: the `wazuh.agent` evidence value `{id, name, status: 'active'|'disconnected'|'never_connected'|'pending', lastKeepAlive: number|null}`.
- Produces: the `agentConnected` and `agentPresent` CheckDefs.

| Check | Rule |
|---|---|
| `agent_connected` | Applies to `host`, `guest` and `roaming` assets that have `sources.wazuh`. `active` gives ok. Other statuses give issue "agent <status>, last seen <age> ago". **Roaming:** for any status other than `active`, the result is `unknown` "away since <lastKeepAlive>", with a `roaming: true` flag. |
| `agent_present` | Applies to `host` and `guest`. If `sources.wazuh` is present, ok. Otherwise issue "no Wazuh agent installed". `appliance` assets are `not_applicable` ("no agent possible"). This check requires no evidence kinds: its input is the asset itself. Ambiguous linking is handled in Task 9, which produces `unknown` assets before checks run. |

- [ ] **Steps 1–5:** TDD as above. Tests: `active is ok`, `disconnected host is issue`, `roaming away is unknown and flagged`, `appliance is not_applicable`, `guest without agent is issue`. Commit "Add agent checks".

### Task 6: EOL dataset collector and EOL checks

**Files:**
- Create: `src/collectors/eol-dataset.mjs`, `src/checks/eol.mjs`, `tests/fixtures/eol/{debian,ubuntu,proxmox-ve,macos,fedora,docker-engine}.json`
- Test: `tests/eol.test.mjs`

**Interfaces:**
- Consumes: `fetchJson` (Task 10, injected, so tests pass a stub), the `wazuh.os` value `{platform, name, version, major, minor, kernelRelease}`, and the `wazuh.packages` value `{items: [{name, version}], scanned: boolean}`.
- Produces:
  - `collectEolDataset({fetchJson, products: string[], now}) -> {evidence:[{assetKey:'_global', kind:'eol.dataset', source:'eol', value:{fetchedAt, products: Record<slug, Release[]>}}]}`. It fetches `https://endoflife.date/api/v1/products/<slug>` and reads `body.result.releases`, keeping `{name, isEol, eolFrom}`. If any product fails, the whole run fails, because a partial dataset would make some checks falsely ok.
  - `eolCycle(releases: Release[], version: string) -> Release|null`. It tries a `name` equal to `major.minor`, then `major`, and returns `null` otherwise. It never picks the "closest" release.
  - `OS_PRODUCT = {debian:'debian', ubuntu:'ubuntu', fedora:'fedora', darwin:'macos', macos:'macos'}`, with the platform taken from `wazuh.os.platform`. Proxmox hosts are detected by the package `pve-manager`, which gives product `proxmox-ve` at the package's version.
  - The CheckDefs `osEol` and `softwareEol`. `software_eol` uses `config.eol.software: [{product, packages: string[]}]`, which defaults to `[{product:'docker-engine', packages:['docker-ce']}, {product:'proxmox-ve', packages:['pve-manager']}]`.

The `eol.dataset` evidence uses `staleAfterMs = eolMaxAgeDays × 86400000`, so a dataset older than 7 days makes every EOL check unknown through the runner's rule.

Rules:
- `os_eol`: platform not mapped gives unknown "OS <name> not tracked by endoflife.date". No cycle match gives unknown "no EOL entry for <product> <version>". `isEol` true gives issue "<product> <cycle> reached end of life on <eolFrom>", unless an active hold matches. Otherwise ok.
- `software_eol`: `packages.scanned === false` gives unknown "no inventory yet" (Review Focus 2). Any tracked package that is EOL and not held gives issue (listing all of them). Tracked packages with no cycle match are listed in the reason, and the result is unknown only if *every* tracked package present is unmatched. If no tracked packages are installed, the result is ok "no tracked products installed".

- [ ] **Step 1: Write the failing tests:** `collector reads result.releases`; `one failed product fails the run`; `eolCycle prefers major.minor then major and never guesses`; `debian 11 is issue with date in reason`; `held product is not an issue`; `unscanned packages are unknown`; and `dataset older than eolMaxAgeDays is unknown`, which goes through `runCheck`.
- [ ] **Step 2: Run, and expect FAIL**
- [ ] **Step 3: Implement.** Fixtures copy the `{result:{releases:[{name,isEol,eolFrom}]}}` shape. During rollout they are replaced by real recordings.
- [ ] **Step 4: Run, and expect PASS**
- [ ] **Step 5: Commit "Add endoflife.date collector and OS/software EOL checks"**

### Task 7: Disk, backup, storage and clock checks

**Files:**
- Create: `src/checks/disk.mjs`, `src/checks/backup.mjs`, `src/checks/clock.mjs`
- Test: `tests/checks-proxmox.test.mjs`

**Interfaces:**
- Consumes these evidence values, produced in Task 11:
  - `pve.disks` (node asset): `[{devpath, model, health, wearout, type}]`
  - `pve.storage` (node asset): `[{storage, active, enabled, used, total, shared}]`
  - `pve.backups` (guest asset): `{coveredByJob: boolean, jobIds: string[], newestBackupAt: number|null, lastTask: {status, endtime}|null}`
  - `pve.time` (node asset): `{offsetSeconds: number}`
- Produces the CheckDefs `diskHealth`, `backupJobs`, `backupStorage` and `clockDrift`.

Rules:
- `disk_health` (node): every disk is classified as follows.
  - `health` in `PASSED|OK` is good. `UNKNOWN`, empty or missing is unknown. Anything else is bad.
  - `wearout` is a number giving % **life remaining**, and is bad when it is at or below `ssdLifeRemainingPct`. `N/A` is ignored when `health` is good.
  - The node result is issue if any disk is bad (every bad disk is listed), otherwise unknown if any disk is unknown (Review Focus 3), otherwise ok.
  - **Before implementing, confirm the `wearout` semantics** by reading `sub get_disks` in Proxmox's `PVE/Diskmanage.pm` (git.proxmox.com, `pve-storage` repo). If it reports % *used*, invert the comparison and record the finding in a code comment with the source line.
- `backup_jobs` (guest): `coveredByJob === false` gives issue "not in any enabled backup job". `newestBackupAt === null` gives issue "no backup found on backup storage". Age over `backupMaxAgeDays` gives issue "last backup <age> ago". `lastTask?.status` that is not `OK` gives issue "last backup task: <status>". Otherwise ok.
- `backup_storage` (node, applies only when `config.proxmox.backupStorage` is set): the storage is missing from the node, or `active !== 1`, or `enabled === 0`, which gives issue. `used/total*100 >= storageFillPct` gives issue "backup storage <pct>% full". `total` of 0 or missing gives unknown "size not reported". Otherwise ok.
- `clock_drift` (node): `|offsetSeconds| > clockDriftSeconds` gives issue "clock off by <n>s". Otherwise ok.

- [ ] **Steps 1–5:** TDD. Tests: one issue, one unknown and one ok per check; `disk with UNKNOWN health plus a good disk is unknown`; `wearout N/A on PASSED HDD is ok`; `storage missing on Main is issue`. Commit "Add disk, backup, storage and clock checks".

### Task 8: Pending reboot and Windows update checks

**Files:**
- Create: `src/checks/reboot.mjs`, `src/checks/windows.mjs`
- Test: `tests/checks-host.test.mjs`

**Interfaces:**
- Consumes: `wazuh.os` and `wazuh.packages` (Task 12 shapes).
- Produces:
  - `newestKernel(packages, platform) -> string|null`:
    - Debian/Proxmox: names matching `^(linux-image|proxmox-kernel|pve-kernel)-(\d[\w.+-]*?)(-signed)?$`, where the release is capture group 2.
    - Fedora: package `kernel-core`, where the release is `${version}.${architecture}` as Wazuh reports it.
    - It picks the max using `compareVersions`.
  - The CheckDefs `pendingReboot` (applies to Linux `host|guest|roaming`) and `windowsFailedUpdates` (applies to Windows only; on any other platform it is `not_applicable`).

Rules:
- `pending_reboot`: `newestKernel` null gives unknown "no kernel packages in inventory". `os.kernelRelease` missing gives unknown. `newest !== running` gives issue "running <running>, newest installed <newest>". Otherwise ok. macOS is `not_applicable` ("kernel updates not tracked on macOS").
- `windows_failed_updates` on Windows assets: unknown "failed-update events are collected from phase 3". This keeps the check honest until event collection exists.

- [ ] **Steps 1–5:** TDD. Tests: `proxmox newer kernel installed is issue`, `matching kernel is ok`, `fedora kernel-core compare`, `no kernel packages is unknown`, `windows check is not_applicable on debian`. Commit "Add pending reboot and Windows update checks".

### Task 9: Asset identity linking

**Files:**
- Create: `src/identity.mjs`
- Test: `tests/identity.test.mjs`

**Interfaces:**
- Consumes:
  - `nodes: [{name, ip}]`
  - `guests: [{vmid, type: 'qemu'|'lxc', name, node, macs: string[], ips: string[]}]`
  - `agents: [{id, name, ip, macs: string[], status}]`
  - `dockerHosts: [{name, assetKey}]`
  - `manualLinks: [{assetKey, source, sourceId}]`
  - `classes: {roaming: string[], appliances: string[] /* asset keys or agent names */}`
- Produces `linkAssets(input) -> {assets: Asset[], ambiguous: [{assetKey, name, reason}]}`. Asset keys are `pve:node:<name>`, `pve:guest:<vmid>` and `wazuh:agent:<id>` (an agent linked to nothing becomes its own asset, class `host` or `roaming`). Linked assets carry `sources: {pve?: {...}, wazuh?: {id}}`.

Rules, in this order, per guest or node:
1. A manual link wins.
2. MACs: compare lower-cased MACs against agent MACs, ignoring agents with status `never_connected`. Exactly one agent links it. More than one makes it ambiguous: "<n> Wazuh agents share this MAC; remove the old agent in Wazuh or set a manual link" (Review Focus 4).
3. No MAC match: an IP **and** short hostname (case-insensitive, text before the first dot) match exactly one agent, which links it. Several matches make it ambiguous.
4. Otherwise there is no agent. Nodes are matched with rule 3 only, using the `/cluster/status` IP.

An ambiguous asset is still emitted, with no `sources.wazuh`, and is marked `ambiguous: true`. Task 15 turns every check on it into `unknown` with the ambiguity reason, including `agent_present`. An agent may link to at most one asset. If a second asset claims it, both become ambiguous.

- [ ] **Steps 1–5:** TDD. One test per rule, plus `re-enrolled agent with same MAC is ambiguous`, `never_connected duplicate is ignored`, `manual link overrides ambiguity` and `unlinked roaming agent becomes roaming asset`. Commit "Add deterministic asset identity linking".

### Task 10: Hardened HTTP client and redaction

**Files:**
- Create: `src/http.mjs`, `tests/helpers/fixture-server.mjs`
- Test: `tests/http.test.mjs`

**Interfaces:**
- Produces:
  - `class CollectorError extends Error { code: 'timeout'|'tls'|'auth'|'http'|'too_large'|'parse'|'egress_denied'|'network' }`
  - `createHttp({allowHosts: string[]}) -> {fetchJson(url, {method='GET', headers={}, body, timeoutMs=10000, maxBytes=5_000_000, certSha256}) -> Promise<any>}`. It uses `node:https`. With `certSha256` set, it disables CA verification and accepts **only** a peer certificate whose `fingerprint256` (colons removed, lower-case) equals the pin. Without it, normal CA verification applies, which is what `endoflife.date` uses. `401` or `403` throws `auth`. Any other non-2xx throws `http` with the status only, never the body. It enforces `maxBytes` while streaming. Methods other than `GET` are allowed only when `method==='POST' && url.pathname==='/security/user/authenticate'`.
  - `redact(text: string, secrets?: string[]) -> string`. It removes every given secret, `PVEAPIToken=…` up to whitespace, `Bearer …`, `Authorization: …`, `password=…` and `token=…`.
  - `startFixtureServer(routes: Record<path, object|((req)=>[status, body])>) -> Promise<{url, certSha256, close()}>`: a self-signed HTTPS server for tests. It generates its key once per test run with `node:crypto` `generateKeyPairSync` plus a minimal self-signed cert. If that's impractical, it falls back to a committed test-only cert under `tests/fixtures/tls/`.

- [ ] **Step 1: Write the failing tests:** `pinned cert accepted`, `wrong pin rejected with tls`, `host outside allowlist rejected before connecting`, `timeout`, `oversize body is too_large`, `PUT refused`, and `redact strips PVEAPIToken and given secrets` (Review Focus 5).
- [ ] **Step 2: Run, and expect FAIL**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run, and expect PASS**
- [ ] **Step 5: Commit "Add pinned, size-capped, GET-only HTTP client with redaction"**

### Task 11: Proxmox collector

**Files:**
- Create: `src/collectors/proxmox.mjs`, `tests/fixtures/proxmox/*.json`
- Test: `tests/collector-proxmox.test.mjs`

**Interfaces:**
- Consumes: `fetchJson`, and config `proxmox: {baseUrl, tokenId, certSha256, backupStorage}` plus the secret `proxmox.tokenSecret`.
- Produces `collectProxmox({http, cfg, secret, now}) -> Promise<{evidence: EvidenceInput[], inventory: {nodes, guests}}>`. The inventory shapes match Task 9's input, and the evidence kinds are those in Task 7.

It sends the header `Authorization: PVEAPIToken=<tokenId>=<secret>`. Every path is under `/api2/json`:
- `/cluster/status`: nodes and their IPs
- `/cluster/resources?type=vm`: guests
- `/nodes/<n>/<qemu|lxc>/<vmid>/config`: MACs from `netN`. For qemu, `virtio=AA:..`; for lxc, `hwaddr=AA:..`.
- `/nodes/<n>/time`: computes `offsetSeconds = body.time - round((tBefore+tAfter)/2000)`
- `/nodes/<n>/disks/list`
- `/nodes/<n>/storage`
- `/cluster/backup`: the jobs. A guest is covered when the job is enabled and has `all=1` without the vmid in `exclude`, or the job's `vmid` list includes it.
- `/nodes/<n>/storage/<backupStorage>/content?content=backup`: the newest `ctime` per `vmid`
- `/nodes/<n>/tasks?typefilter=vzdump&limit=50`: the latest task whose `id` equals the vmid, or which is the job-level task when `id` is empty

A node that doesn't answer adds a warning and writes no evidence for that node. Its evidence ages to unknown, and the run still succeeds for the other node. An auth failure on any call fails the whole run.

- [ ] **Steps 1–5:** TDD against `startFixtureServer`. Tests: `parses MACs from qemu and lxc config`, `backup coverage honours exclude`, `newest backup per vmid`, `offsetSeconds uses request midpoint`, `one node down yields warning not failure`, `401 fails run with auth`. Commit "Add read-only Proxmox collector".

### Task 12: Wazuh 4.14 adapter and collector

**Files:**
- Create: `src/collectors/wazuh414.mjs`, `src/collectors/wazuh.mjs`, `tests/fixtures/wazuh414/*.json`
- Test: `tests/collector-wazuh.test.mjs`

**Interfaces:**
- Produces:
  - **The adapter contract.** Phase 5.x will add `wazuh5.mjs` with the same contract. `createWazuh414({http, baseUrl, user, password, certSha256}) -> WazuhAdapter`, where `WazuhAdapter = {version: '4.14', listAgents() -> Agent[], os(id), packages(id), hotfixes(id), ports(id), processes(id), hardware(id), netiface(id)}`. The normalized shapes are:
    - `Agent = {id, name, ip, status, lastKeepAlive: number|null}`
    - `os -> {platform, name, version, major, minor, kernelRelease}|null`
    - `packages -> {items:[{name, version, architecture, format}], scanned: boolean}`
    - `ports -> [{protocol, localIp, localPort, process, pid}]`
    - `netiface -> {macs: string[]}`
  - `collectWazuh({adapter, now}) -> Promise<{evidence, inventory: {agents}}>`. Its evidence kinds are `wazuh.agent`, `wazuh.os`, `wazuh.packages`, `wazuh.hotfixes`, `wazuh.ports`, `wazuh.processes` and `wazuh.hardware`, with asset keys `wazuh:agent:<id>`. Task 15 re-keys them onto linked assets.

Adapter details:
- Log in with `POST /security/user/authenticate` and HTTP Basic, reading `data.token`. On a `401` it logs in again **once** and retries.
- `GET /agents?limit=500&offset=…` pages until `total_affected_items`. It maps `status` and `lastKeepAlive` (ISO, parsed to ms; the value `9999-12-31…` becomes `null`).
- `GET /syscollector/<id>/<os|packages|hotfixes|ports|processes|hardware|netiface>` pages the same way and reads `data.affected_items`.
- `packages.scanned` is `false` when `total_affected_items === 0` (Review Focus 2).
- The agent `000` (the manager) is included.
- A per-agent syscollector failure adds a warning and skips that agent's inventory kinds. The `wazuh.agent` evidence is still written.

- [ ] **Steps 1–5:** TDD against fixture servers. Tests: `re-authenticates once on 401`, `pages agents`, `never-keepalive becomes null`, `empty package list is scanned:false`, `per-agent failure is a warning`. Commit "Add Wazuh 4.14 adapter and collector".

### Task 13: Docker collector (read-only socket proxy)

**Files:**
- Create: `src/collectors/docker.mjs`, `tests/fixtures/docker/*.json`
- Test: `tests/collector-docker.test.mjs`

**Interfaces:**
- Consumes config `docker: [{name, baseUrl, assetKey}]`. The proxy runs plain HTTP on the LAN, so `createHttp` must allow `http:` **only** for hosts listed in `docker`, and refuses `http:` everywhere else (add a test in Task 10's file).
- Produces `collectDocker({http, hosts, now}) -> {evidence}`. Evidence kind `docker.containers` sits on the host's `assetKey`, with `[{name, image, imageId, state, status, ports:[{privatePort, publicPort, type, ip}]}]`. Kind `docker.engine` comes from `/version` as `{version, apiVersion}`. It calls `GET /containers/json?all=1` and `GET /version`. A host that is down adds a warning, as in Task 11.

- [ ] **Steps 1–5:** TDD. Tests: `maps published ports`, `http refused for non-docker host`, `host down is warning`. Commit "Add Docker collector via read-only proxy".

### Task 14: Holds and exclusions

**Files:**
- Create: `src/holds.mjs`
- Test: `tests/holds.test.mjs`

**Interfaces:**
- Produces `new HoldStore(db, tenantId)` with:
  - `add({kind, assetKey, checkId?, product?, version?, reason, expiresAt?}, now) -> id` (`reason` is required)
  - `remove(id)`
  - `list() -> Hold[]`
  - `activeExclusion(assetKey, checkId, now) -> Hold|null`
  - `activeHold(assetKey, product, version, now) -> Hold|null`. It matches only the exact version, so a version change ends the hold's effect.
- Expired entries are inactive but stay listed, with `expired: true`.

- [ ] **Steps 1–5:** TDD. Tests: `hold ends when version changes`, `expired hold inactive`, `exclusion requires reason`, `tenant isolation`. Commit "Add holds and check exclusions".

### Task 15: Ledger evaluation and scheduler

**Files:**
- Create: `src/checks/index.mjs`, `src/ledger.mjs`, `src/scheduler.mjs`
- Test: `tests/ledger.test.mjs`, `tests/scheduler.test.mjs`

**Interfaces:**
- Consumes everything above.
- Produces:
  - `CHECKS`, the ordered array of the 12 CheckDefs: the 11 above plus `collector_coverage`, which applies only to `network` assets and always returns `unknown` "no collector for this device yet (phase 2)". Network assets come from config `network: [{name, ip}]` (for example the ER605) with keys `net:<name>`.
  - `evaluateAll({store, holds, assets, ambiguous, config, now}) -> LedgerRow[]`, where `LedgerRow = {assetKey, checkId, state, reason, evidence, roaming}`. For an asset with `ambiguous: true`, every check that `appliesTo` it is `unknown` with the ambiguity reason.
  - `new LedgerStore(db, tenantId)` with:
    - `write(rows, now)`, which upserts. `last_ok_at` updates only when the state is `ok`, and `state_since` changes only when the state changes. Rows for vanished (asset, check) pairs are deleted once their asset's `last_seen_at` is older than 7 days.
    - `counts()`
    - `issues()`
    - `unknowns()`
    - `forAsset(assetKey)`
  - `startScheduler({tasks: [{name, everyMs, run: () => Promise<void>}], now, setTimeout}) -> {stop()}`. Each task chains its own `setTimeout`, never overlaps itself, and runs immediately on start.
  - `collectionCycle(deps)`, which runs the Proxmox, Wazuh and Docker collectors, then `linkAssets`, adds the configured network assets, upserts `assets`, runs `evaluateAll` and writes the ledger. EOL runs as a separate scheduler task every `eolRefreshHours`.

- [ ] **Steps 1–5:** TDD. Tests: `ambiguous asset yields unknown on every applicable check`, `last_ok_at unchanged when state turns unknown`, `state_since only moves on change`, `scheduler never overlaps a slow task`, `router from config appears as unknown with "no collector" reason`, and `end-to-end cycle with fixture servers yields at least one of each state`. Commit "Add ledger, check registry and scheduler".

### Task 16: Secrets, credentials and config

**Files:**
- Create: `src/secrets.mjs`, `src/config.mjs`, `config.example.json`
- Test: `tests/secrets.test.mjs`, `tests/config.test.mjs`

**Interfaces:**
- Produces:
  - `createSecretBox(key: Buffer) -> {seal(plain: string) -> string, open(sealed: string) -> string}`. It uses AES-256-GCM with a random 12-byte IV, and the stored value is `v1.<iv>.<tag>.<ct>` in base64url. It throws if the key isn't 32 bytes.
  - `new CredentialStore(db, tenantId, box)` with `set(name, plain, now)`, `get(name) -> string|null` and `has(name)`. Its allowed names are exactly `proxmox.tokenSecret`, `wazuh.password` and `api.readToken`.
  - `loadConfig(file) -> Config`. It deep-merges onto the defaults from Global Constraints and validates types. It **rejects** any key named like `password|secret|token` whose value is a string, because secrets belong in the CredentialStore. It requires `listen.adminAllowIp` and `owner.authentikUser`.
  - `loadMasterKey(path) -> Buffer`. It refuses group- or world-readable files.

- [ ] **Steps 1–5:** TDD. Tests: `seal/open round-trip`, `tampered ciphertext throws`, `config rejects inline secret`, `defaults applied`, `world-readable key refused`. Commit "Add encrypted credentials and validated config".

### Task 17: Public read-only API

**Files:**
- Create: `src/api/public.mjs`
- Test: `tests/api-public.test.mjs`

**Interfaces:**
- Consumes: `LedgerStore`, the `assets` table, `EvidenceStore.lastRun`, and `CredentialStore.get('api.readToken')`.
- Produces `createPublicServer({db, tenantId, credentials, tls: {key, cert}, host, port, version}) -> Promise<{close(), port}>`. It is HTTPS. Routes are **GET only**: anything else is `405`, and unknown paths are `404`. Every route requires `Authorization: Bearer <token>`, compared with `crypto.timingSafeEqual` on sha256 digests; otherwise it returns `401` with no body detail. Responses are `application/json`, `Cache-Control: no-store`, with a body cap of 1 MiB. Lists take `?page` (default 1) and `?pageSize` (default 50, max 200) and return `{items, page, pageSize, total}`.

| Route | Body |
|---|---|
| `/api/v1/health` | `{ok: true, version}` |
| `/api/v1/summary` | `{engine:{version, now}, counts:{ok, issue, unknown, not_applicable, excluded}, roamingAway: number, collectors:[{name, status, lastSuccessAt, lastError}]}`. Roaming unknowns are excluded from `counts.unknown` and counted in `roamingAway`. `lastError` is already redacted. |
| `/api/v1/issues` | items `{assetKey, assetName, checkId, reason, since}` |
| `/api/v1/unknowns` | items `{assetKey, assetName, checkId, reason, since, roaming}` |
| `/api/v1/assets` | items `{assetKey, name, class, counts}` |
| `/api/v1/assets/:assetKey` | `{asset, checks: LedgerRow[], software: [{name, version}], ports: [...], containers: [...]}`. `software` is capped at 2,000 items, with `truncated: true` when it's cut. |

- [ ] **Steps 1–5:** TDD against a real listener on an ephemeral port. Tests: `POST is 405`, `missing token 401`, `wrong token 401`, `pageSize capped at 200`, `roaming unknowns not in counts.unknown`, `lastError contains no secret`, `asset with 5000 packages is truncated`. Commit "Add read-only public API".

### Task 18: Admin listener

**Files:**
- Create: `src/api/admin.mjs`, `src/api/admin-page.html`
- Test: `tests/api-admin.test.mjs`

**Interfaces:**
- Consumes: `HoldStore`, `CredentialStore`, `manual_links`, and config `listen.adminPort`, `listen.adminAllowIp`, `owner.authentikUser`.
- Produces `createAdminServer({db, tenantId, holds, credentials, config}) -> Promise<{close(), port}>`. It is plain HTTP on the LAN, because Caddy terminates TLS. Any connection whose `socket.remoteAddress` (with `::ffff:` stripped) isn't `adminAllowIp` is destroyed before parsing. Every request needs `X-Authentik-Username` equal to `owner.authentikUser`, or it gets `403`. Mutating routes need `Content-Type: application/json` and an `Origin` matching `config.owner.adminOrigin`, otherwise `403`.

Routes:
- `GET /`: the page
- `GET/POST /admin/holds`
- `DELETE /admin/holds/:id`
- `PUT /admin/credentials/:name`: write-only, returns `204`; there is no GET for values
- `GET /admin/credentials`: names and `updated_at` only
- `GET/POST/DELETE /admin/links`
- `POST /admin/api-token/rotate`: returns the new token **once**

The page is plain HTML with inline JS using `fetch`, listing holds, exclusions, links and which credentials are set.

- [ ] **Steps 1–5:** TDD. Tests: `connection from other IP dropped`, `missing Authentik header 403`, `wrong user 403`, `cross-origin POST 403`, `credential value never returned`, `token rotate returns token once and invalidates old`. Commit "Add Caddy-only admin listener".

### Task 19: Wiring, container, smoke test

**Files:**
- Create: `src/main.mjs`, `scripts/smoke.mjs`, `scripts/lint.mjs`, `Dockerfile`, `.dockerignore`, `README.md` (operator notes)
- Test: `tests/main.test.mjs`

**Interfaces:**
- Consumes all of the above.
- `main.mjs` startup order:
  1. `loadConfig(process.env.HS_CONFIG ?? '/data/config.json')`
  2. `loadMasterKey(process.env.HS_MASTER_KEY ?? '/run/secrets/master.key')`
  3. `openDb('/data/engine.db')`
  4. `failOpenRuns(now)`, logging the count
  5. If `api.readToken` isn't set yet, generate it and print it to stdout once, with the note "store this in Helmsman"
  6. TLS key and cert at `/data/tls/` (generate a self-signed pair on first start and log its sha256 fingerprint for pinning in Helmsman)
  7. Start both servers
  8. Start the scheduler

  On `SIGTERM` it stops the scheduler, waits up to 10 s for the in-flight run, closes the servers, then closes the db.
- The `Dockerfile` uses `node:24-alpine` pinned by digest (look up the current digest when writing it, and record the tag next to it). It runs as a non-root UID 10001, uses `/data` as a volume, runs `HEALTHCHECK` against `/api/v1/health` with `--insecure` on loopback, and makes the filesystem read-only except `/data`.
- `scripts/smoke.mjs` starts fixture servers for Proxmox, Wazuh, Docker and EOL, a temporary data dir and a generated master key. It runs one collection cycle and one EOL cycle, starts the public API, and asserts that `/api/v1/summary` has non-zero `ok`, `issue` and `unknown` counts and that every collector shows `status: 'ok'`. It exits 0 or 1.

- [ ] **Step 1: Write the failing test** `main recovers interrupted run on start`. Seed a db with a `running` row, start `main` with the fixture config, and assert that the row is `failed` and that the log contains "1 interrupted run".
- [ ] **Step 2: Run, and expect FAIL**
- [ ] **Step 3: Implement** `main.mjs`, `smoke.mjs`, `lint.mjs` and the `Dockerfile`.
- [ ] **Step 4: Run `npm run lint && npm test && npm run smoke`, and expect all to pass**
- [ ] **Step 5: Commit "Wire engine, add container and smoke test"**
