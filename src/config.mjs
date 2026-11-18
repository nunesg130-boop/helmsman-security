import { readFileSync } from "node:fs";
import { DEFAULT_THRESHOLDS } from "./checks/thresholds.mjs";
import { DEFAULT_SOFTWARE } from "./checks/eol.mjs";
import { parseV4 } from "./exposure/ip.mjs";

const SECRET_KEY = /password|secret|token/iu;
const ALLOWED_SECRETLIKE_KEYS = new Set(["tokenId"]);

function rejectInlineSecrets(value, path = "") {
  if (Array.isArray(value)) value.forEach((v, i) => rejectInlineSecrets(v, `${path}[${i}]`));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      const p = path ? `${path}.${k}` : k;
      if (typeof v === "string" && SECRET_KEY.test(k) && !ALLOWED_SECRETLIKE_KEYS.has(k)) {
        throw new Error(`config must not contain a secret (${p}); set it in the engine's admin page instead`);
      }
      rejectInlineSecrets(v, p);
    }
  }
}

export const CLOUDFLARE_API_HOST = "api.cloudflare.com";
export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

const isStr = (v) => typeof v === "string" && v.length > 0;
const isV4 = (v) => typeof v === "string" && parseV4(v) != null;
function need(cond, msg) { if (!cond) throw new Error(`config: ${msg}`); }

export function parseConfig(raw) {
  need(raw && typeof raw === "object" && !Array.isArray(raw), "must be a JSON object");
  rejectInlineSecrets(raw);
  const c = {
    tenant: raw.tenant ?? "default",
    thresholds: { ...DEFAULT_THRESHOLDS, ...(raw.thresholds ?? {}) },
    listen: { apiHost: "0.0.0.0", apiPort: 8443, adminHost: "0.0.0.0", adminPort: 8081, ...(raw.listen ?? {}) },
    owner: { ...(raw.owner ?? {}) },
    proxmox: raw.proxmox ?? null,
    wazuh: raw.wazuh ?? null,
    docker: raw.docker ?? [],
    eol: { products: ["debian", "ubuntu", "fedora", "macos", "proxmox-ve", "docker-engine"], software: DEFAULT_SOFTWARE, ...(raw.eol ?? {}) },
    assets: { roaming: [], appliances: [], ...(raw.assets ?? {}) },
    network: raw.network ?? [],
    exposure: raw.exposure ?? null
  };
  need(isStr(c.tenant), "tenant must be a string");
  for (const [k, v] of Object.entries(c.thresholds)) need(Number.isFinite(v) && v >= 0, `thresholds.${k} must be a non-negative number`);
  need(isStr(c.listen.adminAllowIp), "listen.adminAllowIp (the Caddy host's IP) is required");
  need(Number.isInteger(c.listen.apiPort) && Number.isInteger(c.listen.adminPort), "listen ports must be integers");
  need(isStr(c.owner.authentikUser), "owner.authentikUser is required");
  need(isStr(c.owner.adminOrigin ?? "x"), "owner.adminOrigin must be a string");
  if (c.proxmox) need(isStr(c.proxmox.baseUrl) && isStr(c.proxmox.tokenId), "proxmox needs baseUrl and tokenId");
  if (c.proxmox?.backupStorage != null) {
    const bs = c.proxmox.backupStorage;
    need(isStr(bs) || (typeof bs === "object" && !Array.isArray(bs) && Object.values(bs).every(isStr)),
      "proxmox.backupStorage must be a storage name or a map of node name to storage name");
  }
  if (c.wazuh) need(isStr(c.wazuh.baseUrl) && isStr(c.wazuh.user), "wazuh needs baseUrl and user");
  if (c.wazuh?.requestsPerMinute != null) need(Number.isFinite(c.wazuh.requestsPerMinute) && c.wazuh.requestsPerMinute > 0, "wazuh.requestsPerMinute must be a positive number");
  if (c.wazuh?.indexer != null) {
    const ix = c.wazuh.indexer;
    need(isStr(ix.baseUrl) && isStr(ix.user), "wazuh.indexer needs baseUrl and user");
    need(/^https:\/\//u.test(ix.baseUrl), "wazuh.indexer.baseUrl must be https");
    need(isStr(ix.certSha256), "wazuh.indexer needs certSha256 (the indexer's certificate fingerprint)");
    need(!ix.user.includes(":"), "wazuh.indexer.user can't contain a colon");
    if (ix.requestsPerMinute != null) need(Number.isFinite(ix.requestsPerMinute) && ix.requestsPerMinute > 0, "wazuh.indexer.requestsPerMinute must be a positive number");
  }
  need(Array.isArray(c.docker), "docker must be a list");
  c.docker.forEach((d, i) => need(isStr(d?.name) && isStr(d?.baseUrl) && isStr(d?.assetKey), `docker[${i}] needs name, baseUrl and assetKey`));
  need(Array.isArray(c.network), "network must be a list");
  c.network.forEach((n, i) => {
    need(isStr(n?.name), `network[${i}] needs a name`);
    const port = (v) => Number.isInteger(v) && v >= 1 && v <= 65535;
    if (n.portForwards != null) {
      need(Array.isArray(n.portForwards) && n.portForwards.every((f) => port(f?.wanPort) && port(f?.lanPort) && isV4(f?.lanIp) && ["tcp", "udp"].includes(f?.protocol)),
        `network[${i}].portForwards entries need wanPort, lanIp, lanPort and protocol tcp|udp`);
    }
    for (const k of ["upnp", "ipv6Inbound"]) need(n[k] == null || typeof n[k] === "boolean", `network[${i}].${k} must be true or false`);
    need(n.dmz == null || typeof n.dmz === "boolean" || isV4(n.dmz), `network[${i}].dmz must be true, false or an IPv4 address`);
  });
  if (c.exposure != null) {
    const e = c.exposure;
    need(typeof e === "object" && !Array.isArray(e), "exposure must be an object");
    if (e.caddy != null) {
      let ok = false;
      try { ok = ["http:", "https:"].includes(new URL(e.caddy.url).protocol); } catch { /* reported below */ }
      need(ok, "exposure.caddy.url must be an http(s) URL");
      need(isStr(e.caddy.assetKey), "exposure.caddy needs assetKey");
      need(isV4(e.caddy.address), "exposure.caddy.address must be Caddy's IPv4 address");
      e.caddy = { maxAgeMinutes: 30, trustedClientIpHeaders: ["Cf-Connecting-Ip"], ...e.caddy };
      need(Number.isFinite(e.caddy.maxAgeMinutes) && e.caddy.maxAgeMinutes > 0, "exposure.caddy.maxAgeMinutes must be a positive number");
      need(Array.isArray(e.caddy.trustedClientIpHeaders) && e.caddy.trustedClientIpHeaders.every(isStr), "exposure.caddy.trustedClientIpHeaders must be a list of header names");
    }
    if (e.cloudflare != null) {
      const cf = e.cloudflare;
      need(isStr(cf.accountId) && isStr(cf.zoneId) && isStr(cf.assetKey), "exposure.cloudflare needs accountId, zoneId and assetKey");
      need(Array.isArray(cf.tunnelIds) && cf.tunnelIds.length > 0 && cf.tunnelIds.every(isStr), "exposure.cloudflare.tunnelIds must be a non-empty list");
      need(isV4(cf.connectorAddress), "exposure.cloudflare.connectorAddress must be cloudflared's IPv4 address");
    }
    e.expectedPrivate = e.expectedPrivate ?? [];
    need(Array.isArray(e.expectedPrivate) && e.expectedPrivate.every(isStr), "exposure.expectedPrivate must be a list of hostnames");
  }
  need(Array.isArray(c.eol.products) && c.eol.products.every(isStr), "eol.products must be a list of product slugs");
  need(Array.isArray(c.assets.roaming) && Array.isArray(c.assets.appliances), "assets.roaming and assets.appliances must be lists");
  return c;
}

// The backup storage to check on one node: a single name applies to every node,
// a map names each node's own storage (e.g. local directory on one, NFS on another).
export function backupStorageFor(proxmox, node) {
  const bs = proxmox?.backupStorage;
  if (typeof bs === "string") return bs || null;
  if (bs && typeof bs === "object" && Object.hasOwn(bs, node)) return bs[node] || null;
  return null;
}

export function loadConfig(file) {
  return parseConfig(JSON.parse(readFileSync(file, "utf8")));
}

// Every host the engine may contact. Nothing else is reachable.
export function egressHosts(config) {
  const host = (u) => new URL(u).hostname.toLowerCase();
  const httpsHosts = ["endoflife.date"];
  if (config.proxmox) httpsHosts.push(host(config.proxmox.baseUrl));
  if (config.wazuh) httpsHosts.push(host(config.wazuh.baseUrl));
  if (config.wazuh?.indexer) httpsHosts.push(host(config.wazuh.indexer.baseUrl), host(KEV_URL), host(EPSS_URL));
  const httpHosts = config.docker.map((d) => host(d.baseUrl));
  if (config.exposure?.caddy) {
    const u = new URL(config.exposure.caddy.url);
    (u.protocol === "https:" ? httpsHosts : httpHosts).push(u.hostname.toLowerCase());
  }
  if (config.exposure?.cloudflare) httpsHosts.push(CLOUDFLARE_API_HOST);
  return { allowHosts: httpsHosts, allowHttpHosts: httpHosts };
}
