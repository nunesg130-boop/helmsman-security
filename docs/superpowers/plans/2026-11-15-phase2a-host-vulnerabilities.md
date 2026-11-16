# Phase 2A — Host Vulnerability Findings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The engine lists every Wazuh-detected vulnerability per machine with fix state, CISA KEV and EPSS context, and reports per-machine vulnerability coverage, never showing an unscanned machine as clean.

**Architecture:** A new hourly "vulns" cycle reads Wazuh's indexer (`wazuh-states-vulnerabilities-*`) through a version adapter, normalises each record into a finding, and replaces the findings table in one transaction. KEV and EPSS are daily feeds held in their own tables and joined at read time. A new ledger check reports coverage; new GET endpoints and `hs-report` expose the results.

**Tech Stack:** Node.js 24 (ESM), `node:sqlite`, `node:zlib`, `node --test`, no npm dependencies.

**Spec:** `docs/superpowers/specs/2026-11-15-security-phase2-design.md` (sections 4.1, 4.2, 4.4, 4.8). This is plan 1 of 3 for phase 2: **2A host findings** (this plan), **2B exposure, urgency, risk acceptance and posture score** (spec 4.5–4.7), **2C container images with Grype** (spec 4.3). Each ships as its own PR and is useful on its own.

## Global Constraints

- Node.js 24, ESM, no npm dependencies; storage is `node:sqlite`; tests are `node --test 'tests/**/*.test.mjs'`; `node scripts/lint.mjs` and `node scripts/smoke.mjs` must pass.
- Never guess: missing, stale, unparseable or failed-run evidence yields `unknown`, never `ok`. A machine with no vulnerability records is **not** clean.
- The engine is read-only. The indexer user may only read `wazuh-states-vulnerabilities-*`.
- Every table carries `tenant_id`; every store filters by it.
- Nothing lab-specific hardcoded: hosts, users and pins come from config.
- Egress stays allowlisted: only hosts derived from config plus the fixed feed hosts.
- Secrets never appear in config, logs, evidence or API responses.
- Every collector run is one transaction and must survive being killed (findings from an interrupted run are not written).
- Wazuh requests stay paced; the indexer is a separate service (port 9200) and gets its own pacing at 60 requests/min.
- All TLS connections to lab services pin the certificate SHA-256.

## Facts verified against the live lab (2026-11-15)

- Index name: `wazuh-states-vulnerabilities-wazuh`; 22 agents, about 29,000 documents; one agent has 9,256.
- Document fields used: `agent.id`, `agent.name`, `package.{name,version,architecture,type}`, `vulnerability.{id,severity,score.base,detected_at,under_evaluation,reference,scanner.condition,scanner.source}`.
- `vulnerability.scanner.condition` example: `"Package less than 6.12.100-1"`; `scanner.source` example: `"Debian Security Tracker"`; severity is capitalised (`"High"`).
- The Wazuh server's own host has no documents in the index.

## Review Focus

1. Two documents with identical sort keys straddling a page boundary: the collector must notice the count mismatch and fail the run (unknown), not store a short list.
2. An agent present in the index but not linked to any asset (removed or renamed agent): its findings are kept under `wazuh:agent:<id>` and not dropped or attached to another machine.
3. Unexpected `condition` wording or severity value (`"-"`, empty, new wording): fix state `unknown`, severity `unknown`, and the count of unrecognised conditions is visible in `hs-report`.
4. EPSS file truncated, not gzip, or over the size cap: the old EPSS table stays intact and the feed is marked failed.
5. KEV or EPSS older than 7 days: `kev` / `epss` read as `null` with `threatDataStale: true`, never as "not exploited".

---

### Task 1: Config, credential and egress for the indexer and feeds

**Files:**
- Modify: `src/config.mjs`, `src/secrets.mjs`, `src/api/admin.mjs`, `src/api/admin-page.html`, `src/main.mjs` (secret list only)
- Test: `tests/config.test.mjs`, `tests/secrets.test.mjs`, `tests/api-admin.test.mjs`

**Interfaces:**
- Produces: `config.wazuh.indexer = { baseUrl, user, certSha256, requestsPerMinute? }` (optional block); credential name `"wazuh.indexerPassword"`; `egressHosts(config)` additionally returns the indexer host and, when `config.wazuh.indexer` is set, the feed hosts `www.cisa.gov` and `epss.empiricalsecurity.com`; exported constants `KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"` and `EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"` from `src/config.mjs`; new thresholds `vulnsRefreshMinutes: 60`, `threatFeedRefreshHours: 24`, `threatFeedMaxAgeDays: 7`.

- [ ] **Step 1: Confirm the EPSS URL** — on `helmsec`: `curl -sI https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | head -1`. Expected: `HTTP/2 200` (or a 30x to a dated file on the same host). If it fails, use the host it redirects to, or FIRST's documented current download host, and record the ruling.
- [ ] **Step 2: Write the failing tests**

```js
test("wazuh.indexer needs baseUrl and user", () => {
  const w = { baseUrl: "https://10.0.0.2:55000", user: "u" };
  assert.throws(() => parseConfig({ ...minimal, wazuh: { ...w, indexer: { baseUrl: "https://10.0.0.2:9200" } } }), /indexer/u);
  assert.equal(parseConfig({ ...minimal, wazuh: { ...w, indexer: { baseUrl: "https://10.0.0.2:9200", user: "ro" } } }).wazuh.indexer.user, "ro");
});
test("egress includes the indexer and feed hosts only when an indexer is configured", () => {
  const w = { baseUrl: "https://10.0.0.2:55000", user: "u" };
  assert.ok(!egressHosts(parseConfig({ ...minimal, wazuh: w })).allowHosts.includes("www.cisa.gov"));
  const hosts = egressHosts(parseConfig({ ...minimal, wazuh: { ...w, indexer: { baseUrl: "https://10.0.0.9:9200", user: "ro" } } })).allowHosts;
  for (const h of ["10.0.0.9", "www.cisa.gov", "epss.empiricalsecurity.com"]) assert.ok(hosts.includes(h), h);
});
test("defaults include the vulnerability thresholds", () => {
  const t = parseConfig(minimal).thresholds;
  assert.deepEqual([t.vulnsRefreshMinutes, t.threatFeedRefreshHours, t.threatFeedMaxAgeDays], [60, 24, 7]);
});
```
Plus: `CREDENTIAL_NAMES` includes `"wazuh.indexerPassword"`; the admin API accepts setting it and never returns its value.
- [ ] **Step 3: Run** `node --test tests/config.test.mjs tests/secrets.test.mjs tests/api-admin.test.mjs` — Expected: the new tests FAIL.
- [ ] **Step 4: Implement** the config validation, constants, thresholds, credential name, `SETTABLE` entry, the admin page dropdown option, and add the name to `secretValues()` in `main.mjs`.
- [ ] **Step 5: Run** the same command — Expected: PASS. Commit: `feat: config and credential for the Wazuh indexer and threat feeds`.

### Task 2: Raw download helper

**Files:**
- Modify: `src/http.mjs`
- Test: `tests/http.test.mjs`

**Interfaces:**
- Produces: `http.fetchBuffer(url, { headers?, timeoutMs?, deadlineMs?, maxBytes = 50_000_000, certSha256? }) → Promise<Buffer>` with the same egress, TLS-pin, status and size rules as `fetchJson` (which becomes a thin wrapper that parses the buffer).

- [ ] **Step 1: Write the failing tests** — `fetchBuffer` returns the exact bytes of a binary fixture; rejects with code `too_large` over `maxBytes`; rejects with `egress_denied` for a host not on the allowlist.
- [ ] **Step 2: Run** `node --test tests/http.test.mjs` — Expected: FAIL (`fetchBuffer is not a function`).
- [ ] **Step 3: Implement** by extracting the request core from `fetchJson`; existing `fetchJson` tests must stay green.
- [ ] **Step 4: Run** — Expected: PASS. Commit: `feat: bounded raw download in the HTTP helper`.

### Task 3: Schema v2 and the findings store

**Files:**
- Modify: `src/db.mjs` (append migration v2)
- Create: `src/vuln/findings.mjs`
- Test: `tests/db.test.mjs`, `tests/findings.test.mjs`

**Interfaces:**
- Produces tables: `findings (tenant_id, source, asset_key, cve, pkg_name, pkg_version, pkg_arch, pkg_type, severity, cvss, fix_state, fixed_version, low_confidence, condition, detected_at, first_seen_at, last_confirmed_at, PRIMARY KEY (tenant_id, source, asset_key, cve, pkg_name, pkg_version, pkg_arch))`; `kev (tenant_id, cve, date_added, ransomware, PRIMARY KEY (tenant_id, cve))`; `epss (tenant_id, cve, score, percentile, PRIMARY KEY (tenant_id, cve))`; `feeds (tenant_id, name, fetched_at, count, PRIMARY KEY (tenant_id, name))`.
- Produces `class FindingStore(db, tenantId)`:
  - `replaceSource(source, findings, now) → number` — one transaction: upsert every finding (keeping an existing row's `first_seen_at`), set `last_confirmed_at = now`, delete rows of that source not in the new set.
  - `replaceKev(entries, now)`, `replaceEpss(rows, now)` — one transaction each, also writing `feeds`.
  - `feed(name) → { fetchedAt, count } | null`.
  - `list({ assetKey?, kev?, fixState?, severity?, limit = 100, offset = 0 }, { now, maxFeedAgeMs }) → { items, total }` — items carry `kev: true|false|null`, `epss: number|null`, `threatDataStale: boolean`; ordered by kev desc, cvss desc, cve.
  - `summaryByAsset({ now, maxFeedAgeMs }) → [{ assetKey, total, critical, high, medium, low, unknownSeverity, fixAvailable, noFix, fixUnknown, kev: number|null, lowConfidence, unrecognisedCondition }]`.
- Finding input shape (from Task 5): `{ assetKey, cve, pkg: { name, version, arch, type }, severity, cvss, fixState, fixedVersion, lowConfidence, condition, detectedAt }`.

- [ ] **Step 1: Write the failing tests**

```js
test("replaceSource keeps first_seen for a finding that persists and drops ones that vanished", () => {
  const s = new FindingStore(openDb(":memory:"), "t");
  s.replaceSource("wazuh", [f("CVE-1"), f("CVE-2")], 1000);
  s.replaceSource("wazuh", [f("CVE-1")], 2000);
  const { items, total } = s.list({}, { now: 2000, maxFeedAgeMs: 1 });
  assert.equal(total, 1);
  assert.deepEqual([items[0].cve, items[0].firstSeenAt, items[0].lastConfirmedAt], ["CVE-1", 1000, 2000]);
});
test("kev and epss are null and flagged stale when the feeds are missing or old", () => {
  const s = new FindingStore(openDb(":memory:"), "t");
  s.replaceSource("wazuh", [f("CVE-1")], 1000);
  assert.deepEqual(pick(s.list({}, { now: 1000, maxFeedAgeMs: 10 }).items[0]), { kev: null, epss: null, threatDataStale: true });
  s.replaceKev([{ cve: "CVE-1", dateAdded: "2026-01-01", ransomware: false }], 1000);
  s.replaceEpss([{ cve: "CVE-1", score: 0.42, percentile: 0.9 }], 1000);
  assert.deepEqual(pick(s.list({}, { now: 1005, maxFeedAgeMs: 10 }).items[0]), { kev: true, epss: 0.42, threatDataStale: false });
  assert.deepEqual(pick(s.list({}, { now: 2000, maxFeedAgeMs: 10 }).items[0]), { kev: null, epss: null, threatDataStale: true });
});
test("a fresh KEV feed that doesn't list the CVE reads kev:false, not null", ...);
test("one tenant cannot see another tenant's findings, kev or epss", ...);
test("summaryByAsset counts severities, fix states and KEV per asset", ...);
test("a failed replaceEpss (bad row) leaves the previous table intact", ...);
```
`f(cve)` builds a finding on `pve:guest:100` for package `openssl 3.0-1 amd64 deb`, severity `high`, cvss 7.5, fixState `fix-available-not-applied`. `db.test.mjs`: opening a v1 database migrates it to `SCHEMA_VERSION === 2` with data preserved.
- [ ] **Step 2: Run** `node --test tests/findings.test.mjs tests/db.test.mjs` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement** migration v2 and `FindingStore`.
- [ ] **Step 4: Run** — Expected: PASS. Commit: `feat: findings, KEV and EPSS storage`.

### Task 4: Fix state and confidence from a Wazuh record

**Files:**
- Create: `src/vuln/classify.mjs`
- Test: `tests/classify.test.mjs`

**Interfaces:**
- Produces:
  - `fixStateFromCondition(condition: string|null) → { fixState: "fix-available-not-applied"|"no-fix-exists"|"unknown", fixedVersion: string|null, recognised: boolean }`
  - `normaliseSeverity(value) → "critical"|"high"|"medium"|"low"|"unknown"`
  - `isLowConfidence({ source, underEvaluation }) → boolean`

Rules (spec 4.2, conservative): `^Package less than (\S+)$` → fix available with that version. `^Package default status$` → `no-fix-exists` (the vendor lists every version as affected). Anything else, including `Package less than or equal to …` (affected up to a version, fix not stated), empty or null → `unknown` with `recognised: false` unless it matched a rule. Low confidence when `underEvaluation === true` or `source` is `"National Vulnerability Database"` (CPE-based match rather than a vendor tracker); a missing source is low confidence.

- [ ] **Step 1: Write the failing tests**

```js
test("'Package less than X' means a fix exists in X", () =>
  assert.deepEqual(fixStateFromCondition("Package less than 6.12.100-1"), { fixState: "fix-available-not-applied", fixedVersion: "6.12.100-1", recognised: true }));
test("'Package default status' means no fix exists", () => assert.equal(fixStateFromCondition("Package default status").fixState, "no-fix-exists"));
for (const c of ["Package less than or equal to 1.2", "", null, "something new"]) test(`'${c}' is unknown and unrecognised`, () =>
  assert.deepEqual(fixStateFromCondition(c), { fixState: "unknown", fixedVersion: null, recognised: false }));
test("severity is normalised; odd values are unknown", () =>
  assert.deepEqual(["Critical", "HIGH", "medium", "Low", "-", "", undefined].map(normaliseSeverity), ["critical", "high", "medium", "low", "unknown", "unknown", "unknown"]));
test("vendor-tracker matches are confident; NVD, under-evaluation and missing source are not", () =>
  assert.deepEqual([{ source: "Debian Security Tracker" }, { source: "National Vulnerability Database" }, { source: "Canonical Security Tracker", underEvaluation: true }, {}].map(isLowConfidence), [false, true, true, true]));
```
- [ ] **Step 2: Run** `node --test tests/classify.test.mjs` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Commit: `feat: fix state and confidence from Wazuh records`.

### Task 5: Wazuh 4.14 indexer adapter

**Files:**
- Create: `src/collectors/wazuh-indexer414.mjs`, `tests/fixtures/wazuh-indexer-fixture.mjs`
- Test: `tests/collector-wazuh-indexer.test.mjs`

**Interfaces:**
- Consumes: `http.fetchJson` (POST with `body`), `fixStateFromCondition`, `normaliseSeverity`, `isLowConfidence`.
- Produces: `createWazuhIndexer414({ http, baseUrl, user, password, certSha256, requestsPerMinute = 60, pageSize = 1000, sleep?, now? }) → { version: "4.14", vulnerabilities(): Promise<{ records, total, agents: Map<agentId, count> }> }`. Each record: `{ agentId, agentName, cve, pkg: { name, version, arch, type }, severity, cvss: number|null, fixState, fixedVersion, lowConfidence, condition, recognisedCondition, detectedAt: number|null }`.

Paging: `POST {base}/wazuh-states-vulnerabilities-*/_search` with Basic auth, `track_total_hits: true`, `size: pageSize`, `_source` limited to the fields above, `sort: ["agent.id", "vulnerability.id", "package.name", "package.version", "package.architecture", "package.type"]`, and `search_after` from the last hit's `sort`. Stop on an empty page. After the last page, if `records.length !== total` reject with code `parse` and message `indexer returned N of M vulnerability records`. A hit missing `agent.id`, `vulnerability.id` or `package.name` rejects with code `parse` (never skipped silently). HTTP 429 is retried like the Wazuh adapter (15 s, 30 s, 45 s).

- [ ] **Step 1: Write the fixture** — a route handler serving three pages from an in-memory list of documents shaped like the live record in "Facts verified", honouring `size` and `search_after`, and recording requests.
- [ ] **Step 2: Write the failing tests**

```js
test("pages with search_after until empty and returns every record", ...);          // 2,500 docs, pageSize 1000 → 4 requests, records.length === 2500
test("sends Basic auth, pins the certificate and requests only the needed fields", ...);
test("a record is normalised: severity, cvss, fix state, confidence, detectedAt", ...); // the live record → high, 7.8, fix-available-not-applied, 6.12.100-1, lowConfidence false
test("a short result (count differs from total) fails the run", ...);                // server reports total 10, returns 9 → rejects /9 of 10/
test("a hit without a CVE id fails the run rather than being skipped", ...);
test("agents map counts records per agent", ...);
test("HTTP 401 fails with auth; HTTP 429 waits and retries", ...);
```
- [ ] **Step 3: Run** `node --test tests/collector-wazuh-indexer.test.mjs` — Expected: FAIL.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run** — Expected: PASS. Commit: `feat: Wazuh 4.14 indexer adapter for vulnerability records`.

### Task 6: Threat feeds (KEV and EPSS)

**Files:**
- Create: `src/collectors/threat-feeds.mjs`
- Test: `tests/threat-feeds.test.mjs`

**Interfaces:**
- Consumes: `http.fetchJson`, `http.fetchBuffer`, `FindingStore.replaceKev/replaceEpss`, `KEV_URL`, `EPSS_URL`.
- Produces: `parseKev(json) → [{ cve, dateAdded, ransomware }]`; `parseEpssCsvGz(buffer) → [{ cve, score, percentile }]` (gunzip, skip the `#` comment line and header, numbers validated 0–1); `refreshThreatFeeds({ http, findings, now, kevUrl?, epssUrl? }) → { evidence: [{ assetKey: "_global", kind: "threat.feeds", value: { kev: { fetchedAt, count } | { error }, epss: { … } } }], warnings }` — each feed is independent: one failing leaves the other updated and adds a warning.

- [ ] **Step 1: Write the failing tests**

```js
test("parseKev reads cveID, dateAdded and the ransomware flag", ...);                 // "Known" → true, "Unknown" → false
test("parseKev rejects a document without a vulnerabilities array", ...);
test("parseEpssCsvGz reads a gzipped CSV with its comment line and header", ...);     // 3 rows in, 3 rows out with numeric score/percentile
test("parseEpssCsvGz rejects non-gzip data and rows with scores outside 0–1", ...);
test("a failing EPSS download keeps the old EPSS table and still updates KEV", ...);
test("fewer than 100 KEV entries or 10,000 EPSS rows is rejected as implausible", ...); // guards against an error page or truncated file
```
- [ ] **Step 2: Run** `node --test tests/threat-feeds.test.mjs` — Expected: FAIL.
- [ ] **Step 3: Implement** (EPSS download uses `maxBytes: 30_000_000`).
- [ ] **Step 4: Run** — Expected: PASS. Commit: `feat: CISA KEV and EPSS feeds`.

### Task 7: Vulnerability cycle and the coverage check

**Files:**
- Create: `src/vuln/cycle.mjs`, `src/checks/vuln.mjs`
- Modify: `src/checks/index.mjs` (register the check), `src/checks/runner.mjs` (only if `evidenceKey` needs the new kind; `wazuh.*` already resolves to the agent key)
- Test: `tests/vuln-cycle.test.mjs`, `tests/checks-vuln.test.mjs`

**Interfaces:**
- Consumes: `runCollector`, `createWazuhIndexer414().vulnerabilities()`, `FindingStore.replaceSource`, the `assets` table (`sources_json` holds `wazuh.id`).
- Produces:
  - `vulnCycle({ db, tenantId, store, findings, indexer, config, now, secrets }) → { status }` — runs under collector name `"wazuh-vulns"` with stale limit `vulnsRefreshMinutes × staleFactor`. Maps each record's `agentId` to the asset whose `sources.wazuh.id` matches, else `wazuh:agent:<id>`. Writes findings via `replaceSource("wazuh", …)` **inside** the collector run so a failed or interrupted run writes nothing. Emits evidence per agent that has records: `{ assetKey: "wazuh:agent:<id>", kind: "wazuh.vulnscan", value: { count, newestDetectedAt } }`, plus `{ assetKey: "_inventory", kind: "inventory.wazuh-vulns", value: { agents: [ids], total } }`.
  - check `vulnCoverageHost` — `id: "vuln_coverage_host"`, `title: "Vulnerability scan coverage"`, `requires: ["wazuh.agent", "wazuh.packages"]`, applies to `HOST_CLASSES`. It reads `wazuh.vulnscan` itself from the store (it may be absent): present and fresh → `ok` with `"N known vulnerabilities, scan data current"`; absent while `inventory.wazuh-vulns` is fresh → `unknown` with `"Wazuh has no vulnerability records for this machine; can't tell 'clean' from 'not scanned'"`; `inventory.wazuh-vulns` missing, stale or its last run failed → `unknown` with the collector's reason. No indexer configured → `not_applicable` (`"vulnerability scanning not configured"`).

- [ ] **Step 1: Write the failing tests**

```js
test("records are filed under the linked Proxmox asset, else under the agent", ...);
test("a failed indexer read writes no findings and leaves the previous ones in place", ...);
test("an interrupted run (throw after fetching) writes no findings", ...);
test("an agent with records gets ok with its count", ...);
test("an agent with no records is unknown, never ok", ...);
test("stale or failed vulnerability collection makes every machine unknown with the reason", ...);
test("without an indexer configured the check is not_applicable", ...);
test("a whole-machine exclusion covers vuln_coverage_host", ...);
```
- [ ] **Step 2: Run** `node --test tests/vuln-cycle.test.mjs tests/checks-vuln.test.mjs` — Expected: FAIL.
- [ ] **Step 3: Implement.** If the check needs store access beyond `requires`, pass it through the existing evaluate context rather than adding a new mechanism; record the choice as a ruling if the runner must change.
- [ ] **Step 4: Run** the full suite `node --test 'tests/**/*.test.mjs'` — Expected: PASS. Commit: `feat: vulnerability cycle and coverage check`.

### Task 8: API endpoints, scheduler wiring and the report script

**Files:**
- Modify: `src/api/public.mjs`, `src/main.mjs`, `scripts/smoke.mjs`
- Create: `scripts/hs-report.sh`, `docs/rollout-phase2a.md`
- Test: `tests/api-public.test.mjs`, `tests/main.test.mjs`

**Interfaces:**
- Consumes: `FindingStore.list`, `FindingStore.summaryByAsset`, `FindingStore.feed`, `vulnCycle`, `refreshThreatFeeds`.
- Produces:
  - `GET /api/v1/vulnerabilities?asset=&kev=true|false&fix=fix-available-not-applied|no-fix-exists|unknown&severity=&limit=&offset=` → `{ items, total, limit, offset, feeds: { kev: { fetchedAt, count }|null, epss: … }, threatDataStale }` (limit capped at 200; items include `assetName`).
  - `GET /api/v1/vulnerabilities/summary` → `{ assets: [summary rows + assetName], totals, feeds, threatDataStale }`.
  - Scheduler tasks `vulns` (every `vulnsRefreshMinutes`) and `threat-feeds` (every `threatFeedRefreshHours`), created only when `config.wazuh.indexer` is set; `/api/v1/summary` lists their collector statuses with the others.
  - `scripts/hs-report.sh`: the existing report plus `=== VULNERABILITIES ===` — one line per machine, sorted by KEV count then total: `name | total | critical/high | fixable by update | KEV | unrecognised conditions`, then `=== ACTIVELY EXPLOITED (KEV) ===` listing `machine | CVE | package version | fixed in`. Reads the token from `/root/.hs-token`.
  - `docs/rollout-phase2a.md`: owner steps — create indexer role and user in the Wazuh dashboard (Indexer management → Security → Roles: index pattern `wazuh-states-vulnerabilities-*`, permissions `read` and `search` only; internal user mapped to it), read the indexer certificate fingerprint, add the `wazuh.indexer` block to config, set `wazuh.indexerPassword` on the admin page, install the new `hs-report`.

- [ ] **Step 1: Write the failing tests**

```js
test("GET /api/v1/vulnerabilities pages, filters by asset, kev, fix and severity, and caps limit at 200", ...);
test("vulnerability endpoints need the bearer token and reject non-GET", ...);
test("summary lists per-asset counts with names and reports stale threat data", ...);
test("vulns and threat-feeds tasks are scheduled only when an indexer is configured", ...);
test("the indexer password never appears in any API response or log line", ...);
```
- [ ] **Step 2: Run** `node --test tests/api-public.test.mjs tests/main.test.mjs` — Expected: FAIL.
- [ ] **Step 3: Implement**, extend the smoke script with an indexer fixture and both feeds, write the script and the rollout doc.
- [ ] **Step 4: Run** `node --test 'tests/**/*.test.mjs' && node scripts/lint.mjs && node scripts/smoke.mjs` — Expected: all PASS, smoke prints `ok   collector wazuh-vulns ok`.
- [ ] **Step 5: Commit** `feat: vulnerability API, schedule and report`, push, open the PR.
