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
  // Every tunnel in the account is a possible way in. One that isn't read
  // would make "LAN-only" claims unsound, so an unlisted tunnel fails the run.
  const unlisted = (await paged(`${acct}/cfd_tunnel?is_deleted=false`)).filter((t) => !t.deleted_at && !cfg.tunnelIds.includes(String(t.id)));
  if (unlisted.length) {
    throw parseError(`Cloudflare tunnel ${unlisted.map((t) => `${t.id} ("${t.name ?? "unnamed"}")`).join(", ")} exists but isn't in exposure.cloudflare.tunnelIds; add it so its routes are read`);
  }
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

// Application types that put Access in front of an origin. Others (bookmark,
// SaaS, launcher) protect nothing on the hostname.
const PROTECTING_TYPES = new Set(["self_hosted", "ssh", "vnc", "rdp"]);

// What one application's policies amount to, or null if it doesn't apply.
// Only allow/deny/service-auth for specific identities count as protection.
function appProtection(app) {
  if (app.type == null) return "unknown";
  if (!PROTECTING_TYPES.has(app.type)) return null;
  if (!Array.isArray(app.policies)) return "unknown";
  let result = "protected";
  for (const p of app.policies) {
    if (p.decision === "bypass") result = weakest([result, p.includesEveryone ? "bypassed" : "unknown"]);
    else if (p.decision === "non_identity" && p.includesEveryone) result = weakest([result, "bypassed"]);
    else if (p.decision === "allow" && p.includesEveryone) result = weakest([result, "unknown"]); // anyone who can log in
    else if (!["allow", "deny", "non_identity"].includes(p.decision)) result = weakest([result, "unknown"]);
  }
  return result;
}

// Is a request for hostname + path behind Cloudflare Access?
//   The most specific application covering the path decides, weakened by any
//   application deeper under it (a bypass on /app/webhook weakens /app/).
//   path null means "anywhere on the host". A wildcard hostname is weakened by
//   applications on any name it covers.
export function accessProtection(hostname, path, apps) {
  if (!Array.isArray(apps)) return "unknown";
  const host = String(hostname ?? "").toLowerCase();
  const wild = host.includes("*");
  const related = [];
  for (const app of apps) {
    const protection = appProtection(app);
    if (protection == null) continue;
    for (const d of app.domains ?? []) {
      if (hostCovers(d.hostname, host)) related.push({ path: d.path, protection, covers: true });
      else if (wild && hostCovers(host, d.hostname)) related.push({ path: d.path, protection, covers: false });
    }
  }
  const matching = related.filter((c) => c.covers && (c.path == null || (path != null && path.startsWith(c.path))));
  const deeper = related.filter((c) => !matching.includes(c) && (!c.covers || (c.path != null && c.path.startsWith(path ?? ""))));
  let base = "none";
  if (matching.length) {
    const longest = Math.max(...matching.map((c) => (c.path ?? "").length));
    base = weakest(matching.filter((c) => (c.path ?? "").length === longest).map((c) => c.protection));
  }
  return weakest([base, ...deeper.map((c) => c.protection)]);
}
