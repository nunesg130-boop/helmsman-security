import { gunzipSync } from "node:zlib";
import { KEV_URL, EPSS_URL } from "../config.mjs";
import { redact } from "../redact.mjs";

// CISA's Known Exploited Vulnerabilities list and FIRST's EPSS scores, both
// public downloads. Each is validated and size-checked before it replaces
// the stored copy, so an error page or a truncated file never wipes good data.
const CVE = /^CVE-\d{4}-\d{4,}$/u;
const MAX_UNZIPPED = 200_000_000;

export function parseKev(doc) {
  const list = doc?.vulnerabilities;
  if (!Array.isArray(list)) throw new Error("KEV feed has no vulnerabilities list");
  return list.map((v) => {
    if (!CVE.test(String(v?.cveID ?? ""))) throw new Error("KEV feed has an entry without a valid CVE id");
    return { cve: v.cveID, dateAdded: typeof v.dateAdded === "string" ? v.dateAdded : null, ransomware: v.knownRansomwareCampaignUse === "Known" };
  });
}

// The date each feed says it was published, so a stale copy served fresh
// (a cache, a mirror) isn't taken as current.
export function kevContentDate(doc) {
  const t = Date.parse(doc?.dateReleased ?? "");
  return Number.isFinite(t) ? t : null;
}

function gunzipText(buffer) {
  try { return gunzipSync(buffer, { maxOutputLength: MAX_UNZIPPED }).toString("utf8"); }
  catch { throw new Error("EPSS feed is not valid gzip data"); }
}

export function epssContentDate(buffer) {
  const m = /score_date:([^,\s]+)/u.exec(gunzipText(buffer).slice(0, 500));
  const t = m ? Date.parse(m[1]) : NaN;
  return Number.isFinite(t) ? t : null;
}

export function parseEpssCsvGz(buffer) {
  const text = gunzipText(buffer);
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  if (lines.shift() !== "cve,epss,percentile") throw new Error("EPSS feed has an unexpected header");
  return lines.map((line) => {
    const [cve, s, p] = line.split(",");
    const score = Number(s);
    const percentile = Number(p);
    if (!CVE.test(cve ?? "") || !(score >= 0 && score <= 1) || !(percentile >= 0 && percentile <= 1)) throw new Error("EPSS feed has an invalid row");
    return { cve, score, percentile };
  });
}

export async function refreshThreatFeeds({ http, findings, now = Date.now, kevUrl = KEV_URL, epssUrl = EPSS_URL, certSha256, minKev = 100, minEpss = 10_000, maxContentAgeMs = 7 * 86400_000, secrets = [] }) {
  const pin = certSha256 ? { certSha256 } : {};
  const warnings = [];
  const value = {};
  const feed = async (label, key, min, load, store) => {
    try {
      const { rows, contentDate } = await load();
      if (rows.length < min) throw new Error(`only ${rows.length} entries (expected at least ${min})`);
      if (contentDate != null && now() - contentDate > maxContentAgeMs) throw new Error(`released ${new Date(contentDate).toISOString().slice(0, 10)}, too old to rely on`);
      store(rows, now());
      value[key] = findings.feed(key);
    } catch (error) {
      value[key] = { error: redact(`${error.code ? `${error.code}: ` : ""}${error.message}`, secrets) };
      warnings.push(`${label} feed not updated: ${value[key].error}`);
    }
  };
  await feed("KEV", "kev", minKev, async () => {
    const doc = await http.fetchJson(kevUrl, { ...pin, timeoutMs: 30_000, maxBytes: 20_000_000 });
    return { rows: parseKev(doc), contentDate: kevContentDate(doc) };
  }, (r, t) => findings.replaceKev(r, t));
  await feed("EPSS", "epss", minEpss, async () => {
    const buf = await http.fetchBuffer(epssUrl, { ...pin, timeoutMs: 60_000, maxBytes: 30_000_000 });
    return { rows: parseEpssCsvGz(buf), contentDate: epssContentDate(buf) };
  }, (r, t) => findings.replaceEpss(r, t));
  if (value.kev.error && value.epss.error) throw new Error(warnings.join("; "));
  return { evidence: [{ assetKey: "_global", kind: "threat.feeds", source: "threat-feeds", value }], warnings };
}
