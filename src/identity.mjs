// Deterministic linking of Proxmox nodes/guests to Wazuh agents. Order:
// manual link, then exactly-one MAC match, then exactly-one IP + short
// hostname match. Anything ambiguous is never auto-linked.
const norm = (mac) => String(mac ?? "").trim().toLowerCase();
const shortName = (n) => String(n ?? "").split(".")[0].trim().toLowerCase();

export function linkAssets({ nodes = [], guests = [], agents = [], dockerHosts = [], manualLinks = [], classes = {} }) {
  const roaming = new Set((classes.roaming ?? []).map((x) => x.toLowerCase()));
  const appliances = new Set((classes.appliances ?? []).map((x) => x.toLowerCase()));
  const agentById = new Map(agents.map((a) => [String(a.id), a]));
  const manualByAsset = new Map();
  const manuallyClaimed = new Set();
  for (const l of manualLinks) {
    if (l.source !== "wazuh" || !agentById.has(String(l.sourceId))) continue;
    manualByAsset.set(l.assetKey, String(l.sourceId));
    manuallyClaimed.add(String(l.sourceId));
  }
  const candidates = agents.filter((a) => !manuallyClaimed.has(String(a.id)));

  const pveAssets = [
    ...nodes.map((n) => ({ assetKey: `pve:node:${n.name}`, name: n.name, class: "host", sources: { pve: { node: n.name } }, macs: [], ips: n.ip ? [n.ip] : [] })),
    ...guests.map((g) => {
      const key = `pve:guest:${g.vmid}`;
      const isAppliance = appliances.has(key.toLowerCase()) || appliances.has(String(g.name).toLowerCase());
      return { assetKey: key, name: g.name, class: isAppliance ? "appliance" : "guest", sources: { pve: { vmid: g.vmid, node: g.node, type: g.type } }, macs: (g.macs ?? []).map(norm), ips: g.ips ?? [] };
    })
  ];

  const proposals = new Map(); // assetKey -> { agentId, method } | { ambiguous: reason }
  for (const a of pveAssets) {
    const manual = manualByAsset.get(a.assetKey);
    if (manual) { proposals.set(a.assetKey, { agentId: manual, method: "manual" }); continue; }
    const live = candidates.filter((ag) => ag.status !== "never_connected");
    const macHits = a.macs.length ? live.filter((ag) => (ag.macs ?? []).map(norm).some((m) => a.macs.includes(m))) : [];
    if (macHits.length === 1) { proposals.set(a.assetKey, { agentId: String(macHits[0].id), method: "mac" }); continue; }
    if (macHits.length > 1) {
      proposals.set(a.assetKey, { ambiguous: `${macHits.length} Wazuh agents share this MAC; remove the old agent in Wazuh or set a manual link` });
      continue;
    }
    const ipHits = candidates.filter((ag) => ag.ip && a.ips.includes(ag.ip) && shortName(ag.name) === shortName(a.name));
    if (ipHits.length === 1) proposals.set(a.assetKey, { agentId: String(ipHits[0].id), method: "ip_hostname" });
    else if (ipHits.length > 1) proposals.set(a.assetKey, { ambiguous: `${ipHits.length} Wazuh agents match this IP and hostname; set a manual link` });
  }

  // An agent may belong to at most one asset (manual links excepted).
  const claims = new Map();
  for (const [key, p] of proposals) {
    if (p.agentId && p.method !== "manual") claims.set(p.agentId, [...(claims.get(p.agentId) ?? []), key]);
  }
  for (const [agentId, keys] of claims) {
    if (keys.length < 2) continue;
    for (const key of keys) proposals.set(key, { ambiguous: `Wazuh agent ${agentId} matches ${keys.length} machines; set a manual link` });
  }

  const linked = new Set();
  const ambiguous = [];
  const assets = pveAssets.map(({ macs, ips, ...a }) => {
    const p = proposals.get(a.assetKey);
    if (p?.agentId) {
      linked.add(p.agentId);
      return { ...a, sources: { ...a.sources, wazuh: { id: p.agentId } }, linkMethod: p.method };
    }
    if (p?.ambiguous) {
      ambiguous.push({ assetKey: a.assetKey, name: a.name, reason: p.ambiguous });
      return { ...a, ambiguous: true, ambiguousReason: p.ambiguous };
    }
    return a;
  });

  for (const ag of agents) {
    if (linked.has(String(ag.id))) continue;
    const isRoaming = roaming.has(String(ag.name).toLowerCase());
    assets.push({ assetKey: `wazuh:agent:${ag.id}`, name: ag.name, class: isRoaming ? "roaming" : "host", sources: { wazuh: { id: String(ag.id) } } });
  }

  for (const d of dockerHosts) {
    const target = assets.find((a) => a.assetKey === d.assetKey);
    if (target) target.sources = { ...target.sources, docker: { name: d.name } };
    else assets.push({ assetKey: d.assetKey, name: d.name, class: "host", sources: { docker: { name: d.name } } });
  }

  return { assets, ambiguous };
}
