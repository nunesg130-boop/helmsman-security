// Gathers what the exposure resolver needs from stored evidence and config,
// and shapes its answer for storage. Deciding whether a source may be used at
// all (fresh, last run succeeded) happens here, not in the resolver.
import { resolveExposure } from "./resolve.mjs";
import { listenerEvidence } from "./listeners.mjs";
import { parseV4 } from "./ip.mjs";

const FUTURE_TOLERANCE_MS = 60_000;

// What the owner declared about the router(s). Undeclared stays null.
export function declaredRouter(network = []) {
  const forwards = network.filter((n) => Array.isArray(n.portForwards)).flatMap((n) => n.portForwards);
  const flag = (key) => {
    const values = network.map((n) => n[key]).filter((v) => typeof v === "boolean");
    return values.includes(true) ? true : values.length ? false : null;
  };
  const dmzHost = network.map((n) => n.dmz).find((v) => typeof v === "string");
  return {
    portForwards: network.some((n) => Array.isArray(n.portForwards)) ? forwards : null,
    upnp: flag("upnp"),
    dmz: dmzHost ?? flag("dmz"),
    ipv6Inbound: flag("ipv6Inbound")
  };
}

function readSource(store, collector, assetKey, kinds, now) {
  if (!assetKey) return { status: "missing" };
  const failed = store.lastRun(collector)?.status === "failed";
  const found = kinds.map((k) => store.get(assetKey, k));
  if (failed) return { status: "failed" };
  if (found.some((e) => !e)) return { status: "missing" };
  if (found.some((e) => e.collectedAt > now + FUTURE_TOLERANCE_MS || now - e.collectedAt > e.staleAfterMs)) return { status: "stale" };
  return { status: "ok", values: found.map((e) => e.value) };
}

export function buildExposureMap({ store, config, assets, inventories, now }) {
  const ex = config.exposure ?? {};
  const shape = readSource(store, "caddy", ex.caddy?.assetKey, ["caddy.shape"], now);
  const cf = readSource(store, "cloudflare", ex.cloudflare?.assetKey, ["cloudflare.tunnel", "cloudflare.access", "cloudflare.dns"], now);
  const caddy = { status: shape.status, shape: shape.values?.[0] ?? null };
  const cloudflare = cf.status === "ok" ? { status: "ok", tunnels: cf.values[0].tunnels, apps: cf.values[1].apps, names: cf.values[2].names } : { status: cf.status };

  // Addresses come from Proxmox (guest and node addresses) and from each
  // agent's own registration address.
  const machines = assets.filter((a) => a.class !== "network");
  const ips = new Map(machines.map((a) => [a.assetKey, new Set()]));
  const add = (key, ip) => { if (ips.has(key) && parseV4(ip) != null) ips.get(key).add(ip); };
  for (const n of inventories.proxmox?.nodes ?? []) add(`pve:node:${n.name}`, n.ip);
  for (const g of inventories.proxmox?.guests ?? []) for (const ip of g.ips ?? []) add(`pve:guest:${g.vmid}`, ip);
  for (const agent of inventories.wazuh?.agents ?? []) {
    const owner = machines.find((a) => !a.assetKey.startsWith("wazuh:agent:") && a.sources?.wazuh?.id === String(agent.id)) ?? machines.find((a) => a.assetKey === `wazuh:agent:${agent.id}`);
    if (owner) add(owner.assetKey, agent.ip);
  }
  const byKey = new Map(machines.map((a) => [a.assetKey, a]));
  const router = declaredRouter(config.network);

  const out = resolveExposure({
    caddy, cloudflare, router,
    assets: machines.map((a) => ({ assetKey: a.assetKey, name: a.name, ips: [...ips.get(a.assetKey)] })),
    listeners: (assetKey) => (byKey.has(assetKey) ? listenerEvidence(byKey.get(assetKey), store, now) : undefined),
    config: ex
  });
  return {
    services: out.services,
    problems: out.problems,
    sources: out.sources,
    machines: [...out.machines].map(([assetKey, m]) => ({ assetKey, name: byKey.get(assetKey)?.name ?? assetKey, ...m })),
    router: { portForwards: router.portForwards?.length ?? null, upnp: router.upnp, dmz: router.dmz, ipv6Inbound: router.ipv6Inbound }
  };
}
