// Read-only view of what Cloudflare sends into the lab: tunnel ingress rules,
// Access applications with their policies, and which names are in public DNS.
// One API token with three read permissions. Any failing call fails the run.
const parseError = (message) => Object.assign(new Error(message), { code: "parse" });
const PER_PAGE = 100;
const MAX_PAGES = 50;

function splitDomain(domain) {
  const text = String(domain ?? "").trim().replace(/^https?:\/\//u, "");
  if (!text) return null;
  const slash = text.indexOf("/");
  const hostname = (slash === -1 ? text : text.slice(0, slash)).toLowerCase();
  const path = slash === -1 ? null : text.slice(slash).replace(/\*+$/u, "") || null;
  return hostname ? { hostname, path: path === "/" ? null : path } : null;
}

const includesEveryone = (policy) => (policy?.include ?? []).some((rule) => rule && typeof rule === "object" && "everyone" in rule);

export async function collectCloudflare({ http, cfg, token, now = Date.now, base = "https://api.cloudflare.com/client/v4", certSha256 }) {
  const headers = { authorization: `Bearer ${token}` };
  const pin = certSha256 ? { certSha256 } : {};
  async function call(path) {
    const body = await http.fetchJson(`${base}${path}`, { ...pin, headers, timeoutMs: 20_000, maxBytes: 10_000_000 });
    if (body?.success !== true || body.result === undefined || body.result === null) throw parseError(`unexpected answer from Cloudflare for ${path.split("?")[0]}`);
    return body;
  }
  async function paged(path) {
    const items = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      const body = await call(`${path}${path.includes("?") ? "&" : "?"}page=${page}&per_page=${PER_PAGE}`);
      if (!Array.isArray(body.result)) throw parseError(`unexpected list from Cloudflare for ${path}`);
      items.push(...body.result);
      const total = Number(body.result_info?.total_count);
      if (!Number.isFinite(total)) { if (body.result.length < PER_PAGE) return items; continue; }
      if (items.length >= total || body.result.length === 0) {
        if (items.length !== total) throw parseError(`Cloudflare returned ${items.length} of ${total} items for ${path}`);
        return items;
      }
    }
    throw parseError(`too many pages from Cloudflare for ${path}`);
  }

  const acct = `/accounts/${encodeURIComponent(cfg.accountId)}`;
  const tunnels = [];
  for (const id of cfg.tunnelIds) {
    const ingress = (await call(`${acct}/cfd_tunnel/${encodeURIComponent(id)}/configurations`)).result?.config?.ingress;
    if (!Array.isArray(ingress)) throw parseError(`tunnel ${id} has no ingress list (is it remotely managed?)`);
    tunnels.push({
      id,
      ingress: ingress.map((r) => ({
        hostname: r.hostname ? String(r.hostname).toLowerCase() : null,
        path: r.path || null,
        service: String(r.service ?? ""),
        catchAll: !r.hostname,
        // The Host header cloudflared sends on, when it overrides the visitor's.
        hostHeader: r.originRequest?.httpHostHeader ? String(r.originRequest.httpHostHeader).toLowerCase() : null,
        // Tunnel-side enforcement: cloudflared itself rejects requests without a valid Access token.
        jwtRequired: r.originRequest?.access?.required === true,
        audTags: Array.isArray(r.originRequest?.access?.audTag) ? r.originRequest.access.audTag.length : 0
      }))
    });
  }

  const apps = [];
  for (const app of await paged(`${acct}/access/apps`)) {
    const domains = [app.domain, ...(app.self_hosted_domains ?? [])].map(splitDomain).filter(Boolean);
    const seen = new Set();
    const unique = domains.filter((d) => { const k = `${d.hostname}|${d.path}`; if (seen.has(k)) return false; seen.add(k); return true; });
    let policies = app.policies;
    if (!Array.isArray(policies) || policies.some((p) => typeof p !== "object" || p === null || p.decision === undefined)) {
      policies = await paged(`${acct}/access/apps/${encodeURIComponent(app.id)}/policies`);
    }
    apps.push({
      id: String(app.id),
      type: app.type ?? null,
      domains: unique,
      policies: policies.map((p) => ({ decision: String(p.decision ?? ""), precedence: Number.isFinite(p.precedence) ? p.precedence : null, includesEveryone: includesEveryone(p) }))
    });
  }

  const names = [...new Set((await paged(`/zones/${encodeURIComponent(cfg.zoneId)}/dns_records`)).map((r) => String(r.name ?? "").toLowerCase()).filter(Boolean))].sort();

  const t = now();
  return {
    evidence: [
      { assetKey: cfg.assetKey, kind: "cloudflare.tunnel", value: { tunnels }, collectedAt: t },
      { assetKey: cfg.assetKey, kind: "cloudflare.access", value: { apps }, collectedAt: t },
      { assetKey: cfg.assetKey, kind: "cloudflare.dns", value: { names }, collectedAt: t }
    ]
  };
}

const hostCovers = (pattern, hostname) => pattern === hostname || (pattern.startsWith("*.") && hostname.endsWith(pattern.slice(1)) && hostname.length > pattern.length - 1);
const RANK = { protected: 0, unknown: 1, bypassed: 2, none: 3 };
const weakest = (list) => list.reduce((a, b) => (RANK[b] > RANK[a] ? b : a));

// What one application's policies amount to. Only allow/deny/service-auth
// policies with no bypass count as protection; anything unrecognised is unknown.
function appProtection(app) {
  if (!Array.isArray(app.policies)) return "unknown";
  let result = "protected";
  for (const p of app.policies) {
    if (p.decision === "bypass") result = weakest([result, p.includesEveryone ? "bypassed" : "unknown"]);
    else if (!["allow", "deny", "non_identity"].includes(p.decision)) result = weakest([result, "unknown"]);
  }
  return result;
}

// Is a request for hostname + path behind Cloudflare Access?
//   path given: the most specific application covering it decides.
//   path null ("the whole host"): the host-wide application decides, weakened
//   by any more specific application on the same host that is weaker.
export function accessProtection(hostname, path, apps) {
  if (!Array.isArray(apps)) return "unknown";
  const host = String(hostname ?? "").toLowerCase();
  const covering = [];
  for (const app of apps) for (const d of app.domains ?? []) if (hostCovers(d.hostname, host)) covering.push({ path: d.path, protection: appProtection(app) });
  if (path == null) {
    const wide = covering.filter((c) => c.path == null);
    if (!wide.length) return "none";
    return weakest([weakest(wide.map((c) => c.protection)), ...covering.filter((c) => c.path != null).map((c) => c.protection)]);
  }
  const matching = covering.filter((c) => c.path == null || path.startsWith(c.path));
  if (!matching.length) return "none";
  const longest = Math.max(...matching.map((c) => (c.path ?? "").length));
  return weakest(matching.filter((c) => (c.path ?? "").length === longest).map((c) => c.protection));
}
