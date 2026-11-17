import { createPacer } from "./pacing.mjs";

// Wazuh 4.14 adapter. The rest of the engine only sees this normalized
// contract, so moving to Wazuh 5.x means writing wazuh5.mjs with the same
// methods and shapes:
//   listAgents() -> [{id, name, ip, status, lastKeepAlive}]
//   os(id) -> {platform, name, version, major, minor, kernelRelease} | null
//   packages(id) -> {items:[{name, version, architecture, format}], scanned}
//   hotfixes(id) -> [{hotfix}]
//   ports(id) -> [{protocol, localIp, localPort, process, pid}]
//   processes(id) -> [{name, pid, user}]
//   hardware(id) -> {cpu, cores, ramTotalKb} | null
//   netiface(id) -> {macs: string[]}
const PAGE = 500;
const LOGIN = "/security/user/authenticate";
const STATUSES = new Set(["active", "disconnected", "never_connected", "pending"]);

function parseKeepAlive(v) {
  if (typeof v !== "string" || v.startsWith("9999")) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

// syscollector scan times come as ISO or "YYYY/MM/DD HH:MM:SS" (UTC).
export function parseScanTime(v) {
  if (typeof v !== "string" || !v) return null;
  let s = v.trim().replace(/^(\d{4})\/(\d{2})\/(\d{2})/u, "$1-$2-$3").replace(" ", "T");
  if (!/[zZ]|[+-]\d{2}:?\d{2}$/u.test(s)) s += "Z";
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

// The Wazuh API allows a fixed number of requests per minute (300 by default,
// shared with the dashboard), so requests go through a pacer.
export function createWazuh414({ http, baseUrl, user, password, certSha256, requestsPerMinute = 120, sleep, now }) {
  const base = baseUrl.replace(/\/+$/u, "");
  let token = null;
  const paced = createPacer({ requestsPerMinute, sleep, now });
  const scans = new Map(); // `${id}/${table}` -> newest scan time (ms)
  const metas = new Map(); // `${id}/${table}` -> { rows, total, pages } of the last read

  async function login() {
    const body = await paced(() => http.fetchJson(`${base}${LOGIN}`, {
      method: "POST",
      certSha256,
      headers: { authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}` }
    }));
    token = body?.data?.token;
    if (!token) throw Object.assign(new Error("Wazuh login returned no token"), { code: "auth" });
  }

  async function get(path) {
    if (!token) await login();
    try {
      return await paced(() => http.fetchJson(`${base}${path}`, { certSha256, headers: { authorization: `Bearer ${token}` } }));
    } catch (error) {
      if (error.code !== "auth") throw error;
      await login();
      return paced(() => http.fetchJson(`${base}${path}`, { certSha256, headers: { authorization: `Bearer ${token}` } }));
    }
  }

  // Reads every page. `total` is what the API says exists (null if it doesn't
  // say), so a caller can tell a complete read from one that stopped short.
  async function allWithMeta(path) {
    const items = [];
    let total = null;
    for (let offset = 0, pages = 1; ; offset += PAGE, pages++) {
      const body = await get(`${path}?limit=${PAGE}&offset=${offset}`);
      const page = body?.data?.affected_items;
      if (!Array.isArray(page)) throw Object.assign(new Error(`unexpected response for ${path}`), { code: "parse" });
      items.push(...page);
      const reported = body.data.total_affected_items;
      total = Number.isFinite(Number(reported)) && reported != null ? Number(reported) : null;
      if (items.length >= (total ?? items.length) || page.length === 0) return { items, total, pages };
    }
  }
  const all = async (path) => (await allWithMeta(path)).items;

  // os and hardware are single-item endpoints: Wazuh rejects limit/offset
  // on them with HTTP 400. Every other syscollector table is a paged list.
  const SINGLE = new Set(["os", "hardware"]);

  async function one(path) {
    const body = await get(path);
    const page = body?.data?.affected_items;
    if (!Array.isArray(page)) throw Object.assign(new Error(`unexpected response for ${path}`), { code: "parse" });
    return page;
  }

  async function sys(id, table) {
    const path = `/syscollector/${encodeURIComponent(id)}/${table}`;
    let items;
    if (SINGLE.has(table)) items = await one(path);
    else {
      const read = await allWithMeta(path);
      items = read.items;
      metas.set(`${id}/${table}`, { rows: items.length, total: read.total, pages: read.pages });
    }
    const times = items.map((i) => parseScanTime(i?.scan?.time)).filter((t) => t != null);
    scans.set(`${id}/${table}`, times.length ? Math.max(...times) : null);
    return items;
  }

  return {
    version: "4.14",
    // Newest syscollector scan time seen for (agent, table), or null.
    scanTime: (id, table) => scans.get(`${id}/${table}`) ?? null,
    // How the last read of a paged table went: { rows, total, pages }, or null.
    tableMeta: (id, table) => metas.get(`${id}/${table}`) ?? null,
    async listAgents() {
      return (await all("/agents")).map((a) => ({
        id: String(a.id),
        name: String(a.name ?? ""),
        ip: String(a.ip ?? ""),
        status: STATUSES.has(a.status) ? a.status : "pending",
        lastKeepAlive: parseKeepAlive(a.lastKeepAlive)
      }));
    },
    async os(id) {
      const [item] = await sys(id, "os");
      if (!item) return null;
      const o = item.os ?? {};
      return {
        platform: String(o.platform ?? "").toLowerCase(),
        name: o.name ?? null,
        version: o.version ?? null,
        major: o.major != null ? String(o.major) : null,
        minor: o.minor ? String(o.minor) : null,
        kernelRelease: item.release ?? null
      };
    },
    async packages(id) {
      const items = (await sys(id, "packages")).map((p) => ({ name: p.name, version: p.version, architecture: p.architecture ?? null, format: p.format ?? null }));
      return { items, scanned: items.length > 0 };
    },
    async hotfixes(id) {
      return (await sys(id, "hotfixes")).map((h) => ({ hotfix: h.hotfix }));
    },
    async ports(id) {
      return (await sys(id, "ports")).map((p) => ({ protocol: p.protocol, localIp: p.local?.ip ?? null, localPort: Number(p.local?.port), process: p.process ?? null, pid: p.pid != null ? Number(p.pid) : null }));
    },
    async processes(id) {
      return (await sys(id, "processes")).map((p) => ({ name: p.name, pid: Number(p.pid), user: p.euser ?? p.ruser ?? null }));
    },
    async hardware(id) {
      const [h] = await sys(id, "hardware");
      return h ? { cpu: h.cpu?.name ?? null, cores: h.cpu?.cores ?? null, ramTotalKb: h.ram?.total ?? null } : null;
    },
    async netiface(id) {
      const macs = (await sys(id, "netiface"))
        .map((n) => String(n.mac ?? "").toLowerCase())
        .filter((m) => /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/u.test(m) && m !== "00:00:00:00:00:00");
      return { macs: [...new Set(macs)] };
    }
  };
}
