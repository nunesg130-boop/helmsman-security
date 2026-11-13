import { readFileSync } from "node:fs";
import { DEFAULT_THRESHOLDS } from "./checks/thresholds.mjs";
import { DEFAULT_SOFTWARE } from "./checks/eol.mjs";

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

const isStr = (v) => typeof v === "string" && v.length > 0;
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
    network: raw.network ?? []
  };
  need(isStr(c.tenant), "tenant must be a string");
  for (const [k, v] of Object.entries(c.thresholds)) need(Number.isFinite(v) && v >= 0, `thresholds.${k} must be a non-negative number`);
  need(isStr(c.listen.adminAllowIp), "listen.adminAllowIp (the Caddy host's IP) is required");
  need(Number.isInteger(c.listen.apiPort) && Number.isInteger(c.listen.adminPort), "listen ports must be integers");
  need(isStr(c.owner.authentikUser), "owner.authentikUser is required");
  need(isStr(c.owner.adminOrigin ?? "x"), "owner.adminOrigin must be a string");
  if (c.proxmox) need(isStr(c.proxmox.baseUrl) && isStr(c.proxmox.tokenId), "proxmox needs baseUrl and tokenId");
  if (c.wazuh) need(isStr(c.wazuh.baseUrl) && isStr(c.wazuh.user), "wazuh needs baseUrl and user");
  need(Array.isArray(c.docker), "docker must be a list");
  c.docker.forEach((d, i) => need(isStr(d?.name) && isStr(d?.baseUrl) && isStr(d?.assetKey), `docker[${i}] needs name, baseUrl and assetKey`));
  need(Array.isArray(c.network), "network must be a list");
  c.network.forEach((n, i) => need(isStr(n?.name), `network[${i}] needs a name`));
  need(Array.isArray(c.eol.products) && c.eol.products.every(isStr), "eol.products must be a list of product slugs");
  need(Array.isArray(c.assets.roaming) && Array.isArray(c.assets.appliances), "assets.roaming and assets.appliances must be lists");
  return c;
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
  return { allowHosts: httpsHosts, allowHttpHosts: config.docker.map((d) => host(d.baseUrl)) };
}
