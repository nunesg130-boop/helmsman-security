// Downloads end-of-life dates from endoflife.date (v1 API). If any product
// fails, the whole run fails: a partial dataset would make some checks look
// fine when we simply didn't get their data.
export const EOL_BASE = "https://endoflife.date/api/v1/products/";

export async function collectEolDataset({ fetchJson, products, now = Date.now, maxAgeMs, base = EOL_BASE }) {
  const out = {};
  for (const slug of products) {
    let body;
    try {
      body = await fetchJson(`${base}${encodeURIComponent(slug)}`);
    } catch (error) {
      throw Object.assign(new Error(`endoflife.date ${slug}: ${error.message}`), { code: error.code });
    }
    const releases = body?.result?.releases;
    if (!Array.isArray(releases)) throw Object.assign(new Error(`endoflife.date ${slug}: unexpected response shape`), { code: "parse" });
    out[slug] = releases.map((r) => ({ name: String(r.name), isEol: r.isEol === true, eolFrom: typeof r.eolFrom === "string" ? r.eolFrom : null }));
  }
  const fetchedAt = now();
  return { evidence: [{ assetKey: "_global", kind: "eol.dataset", source: "eol", value: { fetchedAt, products: out }, collectedAt: fetchedAt, staleAfterMs: maxAgeMs }] };
}
