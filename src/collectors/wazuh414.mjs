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

export function createWazuh414({ http, baseUrl, user, password, certSha256 }) {
  const base = baseUrl.replace(/\/+$/u, "");
  let token = null;

  async function login() {
    const body = await http.fetchJson(`${base}${LOGIN}`, {
      method: "POST",
      certSha256,
      headers: { authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}` }
    });
    token = body?.data?.token;
    if (!token) throw Object.assign(new Error("Wazuh login returned no token"), { code: "auth" });
  }

  async function get(path) {
    if (!token) await login();
    try {
      return await http.fetchJson(`${base}${path}`, { certSha256, headers: { authorization: `Bearer ${token}` } });
    } catch (error) {
      if (error.code !== "auth") throw error;
      await login();
      return http.fetchJson(`${base}${path}`, { certSha256, headers: { authorization: `Bearer ${token}` } });
    }
  }

  async function all(path) {
    const items = [];
    for (let offset = 0; ; offset += PAGE) {
      const body = await get(`${path}?limit=${PAGE}&offset=${offset}`);
      const page = body?.data?.affected_items;
      if (!Array.isArray(page)) throw Object.assign(new Error(`unexpected response for ${path}`), { code: "parse" });
      items.push(...page);
      const total = Number(body.data.total_affected_items ?? items.length);
      if (items.length >= total || page.length === 0) return items;
    }
  }

  const sys = (id, table) => all(`/syscollector/${encodeURIComponent(id)}/${table}`);

  return {
    version: "4.14",
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
