// Reads Docker through a read-only socket proxy on each Docker host (only GET
// on containers/version is allowed there). The engine stores no Docker
// credential. A host that's down is a warning; its evidence ages to unknown.
export async function collectDocker({ http, hosts, now = Date.now }) {
  const evidence = [];
  const warnings = [];
  for (const h of hosts) {
    const base = h.baseUrl.replace(/\/+$/u, "");
    try {
      const list = await http.fetchJson(`${base}/containers/json?all=1`, { timeoutMs: 8000 });
      const version = await http.fetchJson(`${base}/version`, { timeoutMs: 8000 });
      const t = now();
      evidence.push({
        assetKey: h.assetKey,
        kind: "docker.containers",
        collectedAt: t,
        value: (Array.isArray(list) ? list : []).map((c) => ({
          name: String(c.Names?.[0] ?? c.Id ?? "").replace(/^\//u, ""),
          image: c.Image ?? null,
          imageId: c.ImageID ?? null,
          state: c.State ?? null,
          status: c.Status ?? null,
          ports: (c.Ports ?? []).map((p) => ({ privatePort: p.PrivatePort ?? null, publicPort: p.PublicPort ?? null, type: p.Type ?? null, ip: p.IP ?? null }))
        }))
      });
      evidence.push({ assetKey: h.assetKey, kind: "docker.engine", collectedAt: t, value: { version: version?.Version ?? null, apiVersion: version?.ApiVersion ?? null } });
    } catch (error) {
      warnings.push(`docker host ${h.name}: ${error.code ?? "error"} ${error.message}`);
    }
  }
  return { evidence, warnings };
}
