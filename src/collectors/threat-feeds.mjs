import { gunzipSync } from "node:zlib";
import { KEV_URL, EPSS_URL } from "../config.mjs";

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

export function parseEpssCsvGz(buffer) {
  let text;
  try { text = gunzipSync(buffer, { maxOutputLength: MAX_UNZIPPED }).toString("utf8"); }
  catch { throw new Error("EPSS feed is not valid gzip data"); }
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

export async function refreshThreatFeeds({ http, findings, now = Date.now, kevUrl = KEV_URL, epssUrl = EPSS_URL, certSha256, minKev = 100, minEpss = 10_000 }) {
  const pin = certSha256 ? { certSha256 } : {};
  const warnings = [];
  const value = {};
  const feed = async (label, key, min, load, store) => {
    try {
      const rows = await load();
      if (rows.length < min) throw new Error(`only ${rows.length} entries (expected at least ${min})`);
      store(rows, now());
      value[key] = findings.feed(key);
    } catch (error) {
      value[key] = { error: `${error.code ? `${error.code}: ` : ""}${error.message}` };
      warnings.push(`${label} feed not updated: ${value[key].error}`);
    }
  };
  await feed("KEV", "kev", minKev, async () => parseKev(await http.fetchJson(kevUrl, { ...pin, timeoutMs: 30_000, maxBytes: 20_000_000 })), (r, t) => findings.replaceKev(r, t));
  await feed("EPSS", "epss", minEpss, async () => parseEpssCsvGz(await http.fetchBuffer(epssUrl, { ...pin, timeoutMs: 60_000, maxBytes: 30_000_000 })), (r, t) => findings.replaceEpss(r, t));
  if (value.kev.error && value.epss.error) throw new Error(warnings.join("; "));
  return { evidence: [{ assetKey: "_global", kind: "threat.feeds", value }], warnings };
}
