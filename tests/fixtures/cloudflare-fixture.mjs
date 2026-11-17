// A stand-in for the three Cloudflare API endpoints the engine reads.
const ok = (result, total) => ({ success: true, errors: [], result, ...(total !== undefined ? { result_info: { total_count: total } } : {}) });
const pageOf = (items) => (req) => {
  const u = new URL(req.url, "https://x");
  const page = Number(u.searchParams.get("page") ?? 1);
  const per = Number(u.searchParams.get("per_page") ?? 100);
  return [200, ok(items.slice((page - 1) * per, page * per), items.length)];
};

export function cloudflareRoutes({ ingress, apps = [], dns = [], policies = {}, tunnelList = [{ id: "t1", name: "home", status: "healthy" }] } = {}) {
  const routes = {
    "/client/v4/accounts/acc/cfd_tunnel/t1/configurations": ok({ tunnel_id: "t1", config: { ingress: ingress ?? [
      { hostname: "ha.jellofin.com", service: "http://192.168.0.197:8123", originRequest: { access: { required: true, teamName: "x", audTag: ["aud1"] } } },
      { hostname: "manage.jellofin.com", service: "https://192.168.0.201:443" },
      { service: "http_status:404" }
    ] } }),
    "/client/v4/accounts/acc/cfd_tunnel": pageOf(tunnelList),
    "/client/v4/accounts/acc/access/apps": pageOf(apps),
    "/client/v4/zones/zone/dns_records": pageOf(dns)
  };
  for (const [id, list] of Object.entries(policies)) routes[`/client/v4/accounts/acc/access/apps/${id}/policies`] = pageOf(list);
  return routes;
}
export const CF_CFG = { accountId: "acc", zoneId: "zone", tunnelIds: ["t1"], assetKey: "pve:guest:107", connectorAddress: "192.168.0.108" };
