// Read-only Proxmox VE collector. Uses a PVEAuditor API token. Every call is
// a GET under /api2/json. One node failing is a warning (its evidence ages
// out to unknown); an auth failure fails the whole run.
const MAC = /(?:^|,)(?:[a-z0-9]+=)?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:,|$)/u;
const HWADDR = /(?:^|,)hwaddr=([0-9A-Fa-f:]{17})/u;
const STATIC_IP = /(?:^|,)ip=(\d{1,3}(?:\.\d{1,3}){3})\/\d+/u;

export function parseNet(config) {
  const macs = [];
  const ips = [];
  for (const [k, v] of Object.entries(config ?? {})) {
    if (!/^net\d+$/u.test(k) || typeof v !== "string") continue;
    const mac = (HWADDR.exec(v) ?? MAC.exec(v))?.[1];
    if (mac) macs.push(mac.toUpperCase());
    const ip = STATIC_IP.exec(v)?.[1];
    if (ip) ips.push(ip);
  }
  return { macs, ips };
}

function parseIdList(s) {
  return new Set(String(s ?? "").split(/[,\s]+/u).filter(Boolean).map((x) => Number(x)));
}

export async function collectProxmox({ http, cfg, secret, now = Date.now }) {
  const base = cfg.baseUrl.replace(/\/+$/u, "");
  const headers = { authorization: `PVEAPIToken=${cfg.tokenId}=${secret}` };
  const get = async (path) => (await http.fetchJson(`${base}/api2/json${path}`, { headers, certSha256: cfg.certSha256 }))?.data;
  const warnings = [];
  const evidence = [];
  const isAuth = (e) => e?.code === "auth";

  const status = await get("/cluster/status");
  const nodes = (status ?? []).filter((x) => x.type === "node").map((n) => ({ name: n.name, ip: n.ip, online: n.online !== 0 }));
  const resources = (await get("/cluster/resources?type=vm")) ?? [];
  const jobs = (await get("/cluster/backup")) ?? [];

  const poolMembers = new Map();
  for (const job of jobs) {
    if (job.pool && !poolMembers.has(job.pool)) {
      const pool = await get(`/pools/${encodeURIComponent(job.pool)}`);
      poolMembers.set(job.pool, new Set((pool?.members ?? []).map((m) => Number(m.vmid)).filter(Number.isFinite)));
    }
  }

  const newestBackup = new Map();
  const tasksByNode = new Map(); // only nodes whose backup data was fully read
  for (const node of nodes) {
    const key = `pve:node:${node.name}`;
    if (!node.online) { warnings.push(`node ${node.name} is offline`); continue; }
    try {
      const before = now();
      const time = await get(`/nodes/${node.name}/time`);
      const after = now();
      evidence.push({ assetKey: key, kind: "pve.time", value: { offsetSeconds: Number(time.time) - Math.round((before + after) / 2000) } });
      evidence.push({ assetKey: key, kind: "pve.disks", value: (await get(`/nodes/${node.name}/disks/list`)) ?? [] });
      const storage = (await get(`/nodes/${node.name}/storage`)) ?? [];
      evidence.push({ assetKey: key, kind: "pve.storage", value: storage.map((s) => ({ storage: s.storage, active: s.active, enabled: s.enabled ?? 1, used: s.used, total: s.total, shared: s.shared })) });
      if (cfg.backupStorage && storage.some((s) => s.storage === cfg.backupStorage && Number(s.active) === 1)) {
        const content = (await get(`/nodes/${node.name}/storage/${encodeURIComponent(cfg.backupStorage)}/content?content=backup`)) ?? [];
        for (const c of content) {
          const vmid = Number(c.vmid);
          const t = Number(c.ctime) * 1000;
          if (Number.isFinite(vmid) && Number.isFinite(t) && t > (newestBackup.get(vmid) ?? -Infinity)) newestBackup.set(vmid, t);
        }
      }
      const tasks = ((await get(`/nodes/${node.name}/tasks?typefilter=vzdump&limit=50`)) ?? []).filter((t) => t.type === "vzdump" && t.endtime);
      tasksByNode.set(node.name, tasks);
    } catch (error) {
      if (isAuth(error)) throw error;
      warnings.push(`node ${node.name}: ${error.code ?? "error"} ${error.message}`);
      for (const kind of ["pve.time", "pve.disks", "pve.storage"]) {
        const i = evidence.findIndex((e) => e.assetKey === key && e.kind === kind);
        if (i >= 0) evidence.splice(i, 1);
      }
    }
  }

  const guests = [];
  for (const r of resources) {
    if (r.template) continue;
    const vmid = Number(r.vmid);
    const node = nodes.find((n) => n.name === r.node);
    let net = { macs: [], ips: [] };
    if (node?.online) {
      try { net = parseNet(await get(`/nodes/${r.node}/${r.type}/${vmid}/config`)); }
      catch (error) { if (isAuth(error)) throw error; warnings.push(`guest ${vmid} config: ${error.code ?? "error"}`); }
    }
    guests.push({ vmid, type: r.type, name: r.name, node: r.node, ...net });

    // Without this node's task list we can't say whether last night's job
    // failed, so the guest gets no backup evidence (it reads unknown).
    if (!tasksByNode.has(r.node)) {
      evidence.push({ assetKey: `pve:guest:${vmid}`, kind: "pve.guest", value: { name: r.name, node: r.node, type: r.type, status: r.status } });
      continue;
    }
    const covered = jobs.some((j) => {
      if (Number(j.enabled ?? 1) === 0) return false;
      if (j.node && j.node !== r.node) return false;
      if (Number(j.all) === 1) return !parseIdList(j.exclude).has(vmid);
      if (j.pool) return poolMembers.get(j.pool)?.has(vmid) ?? false;
      return parseIdList(j.vmid).has(vmid);
    });
    const tasks = tasksByNode.get(r.node);
    const byId = tasks.filter((t) => String(t.id) === String(vmid)).sort((a, b) => b.endtime - a.endtime)[0];
    const jobLevel = tasks.filter((t) => !t.id).sort((a, b) => b.endtime - a.endtime)[0];
    // A job-level task only names a node, not a job. Attribute it to this
    // guest only when exactly one enabled job can run on this node.
    const jobsOnNode = jobs.filter((j) => Number(j.enabled ?? 1) !== 0 && (!j.node || j.node === r.node));
    let last = byId ?? null;
    let attribution = byId ? "guest" : "none";
    if (!byId && jobLevel) {
      if (jobsOnNode.length === 1) { last = jobLevel; attribution = "job"; }
      else attribution = "ambiguous";
    }
    evidence.push({
      assetKey: `pve:guest:${vmid}`,
      kind: "pve.backups",
      value: {
        coveredByJob: covered,
        jobIds: jobs.filter((j) => Number(j.enabled ?? 1) !== 0).map((j) => j.id),
        newestBackupAt: newestBackup.get(vmid) ?? null,
        lastTask: last ? { status: last.status, endtime: Number(last.endtime) * 1000 } : null,
        lastTaskAttribution: attribution
      }
    });
    evidence.push({ assetKey: `pve:guest:${vmid}`, kind: "pve.guest", value: { name: r.name, node: r.node, type: r.type, status: r.status } });
  }

  return { evidence, warnings, inventory: { nodes: nodes.map(({ name, ip }) => ({ name, ip })), guests } };
}
