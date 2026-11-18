// Which image each running container uses, identified by registry digest.
// Tags move (":latest" changes in place); digests don't, so findings are
// matched by digest. An image with no registry digest was built locally and
// can't be pulled for scanning.
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const DOCKER_HUB = new Set(["docker.io", "index.docker.io", "registry-1.docker.io"]);

// "nginx:1" -> docker.io/library/nginx; "ghcr.io/a/b@sha256:..." -> ghcr.io/a/b
export function normaliseRepo(reference) {
  let name = String(reference ?? "").trim();
  const at = name.indexOf("@");
  if (at !== -1) name = name.slice(0, at);
  const lastSlash = name.lastIndexOf("/");
  const colon = name.lastIndexOf(":");
  if (colon > lastSlash) name = name.slice(0, colon); // drop the tag, not a registry port
  const parts = name.split("/");
  const first = parts[0];
  const isRegistry = parts.length > 1 && (first.includes(".") || first.includes(":") || first === "localhost");
  let registry = isRegistry ? first.toLowerCase() : "docker.io";
  let path = isRegistry ? parts.slice(1).join("/") : name;
  if (DOCKER_HUB.has(registry)) registry = "docker.io";
  if (registry === "docker.io" && !path.includes("/")) path = `library/${path}`;
  return { registry, repo: `${registry}/${path.toLowerCase()}` };
}

export function runningImages(containers, images) {
  const byId = new Map((images ?? []).map((i) => [i.id, i]));
  const out = [];
  for (const c of containers ?? []) {
    if (c.state !== "running") continue;
    const base = { container: c.name, imageRef: c.image };
    const image = byId.get(c.imageId);
    if (!image) { out.push({ ...base, status: "unknown", reason: "image not in the host's image list" }); continue; }
    const digests = image.repoDigests ?? [];
    if (!digests.length) { out.push({ ...base, status: "local", reason: "built locally, no registry digest" }); continue; }
    // The container's own reference names the repo; one started by image id falls back to the image's tags.
    const wanted = new Set([c.image, ...(String(c.image).startsWith("sha256:") ? image.repoTags ?? [] : [])].filter((r) => !String(r).startsWith("sha256:")).map((r) => normaliseRepo(r).repo));
    const matching = digests.map((d) => ({ ...normaliseRepo(d), digest: d.slice(d.indexOf("@") + 1) })).filter((d) => wanted.has(d.repo)).sort((a, b) => a.digest.localeCompare(b.digest));
    if (!matching.length) { out.push({ ...base, status: "unknown", reason: "no registry digest matches the container's image name" }); continue; }
    const pick = matching[0];
    if (!DIGEST.test(pick.digest)) { out.push({ ...base, status: "unknown", reason: "malformed registry digest" }); continue; }
    out.push({ ...base, status: "registry", registry: pick.registry, repo: pick.repo, digest: pick.digest });
  }
  return out;
}

// Hosts a pull from this registry may need to contact.
export function registryHosts(registry) {
  if (registry === "docker.io") return ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"];
  if (registry === "ghcr.io") return ["ghcr.io", "pkg-containers.githubusercontent.com"];
  if (registry === "lscr.io") return ["lscr.io", "ghcr.io", "pkg-containers.githubusercontent.com"];
  return [String(registry).split(":")[0]];
}
