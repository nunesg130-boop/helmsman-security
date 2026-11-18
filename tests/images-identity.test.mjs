import test from "node:test";
import assert from "node:assert/strict";
import { runningImages, normaliseRepo, registryHosts } from "../src/images/identity.mjs";

const D = (n) => `sha256:${String(n).repeat(64).slice(0, 64)}`;
const c = (name, image, imageId, state = "running") => ({ name, image, imageId, state, ports: [] });
const img = (id, repoTags, repoDigests) => ({ id, repoTags, repoDigests });

test("repository names are normalised the way Docker resolves them", () => {
  assert.deepEqual(normaliseRepo("nginx:1.30.6-alpine"), { registry: "docker.io", repo: "docker.io/library/nginx" });
  assert.deepEqual(normaliseRepo("grafana/grafana:13.1.3"), { registry: "docker.io", repo: "docker.io/grafana/grafana" });
  assert.deepEqual(normaliseRepo("docker.io/library/postgres:16-alpine"), { registry: "docker.io", repo: "docker.io/library/postgres" });
  assert.deepEqual(normaliseRepo("ghcr.io/goauthentik/server@sha256:abc"), { registry: "ghcr.io", repo: "ghcr.io/goauthentik/server" });
  assert.deepEqual(normaliseRepo("lscr.io/linuxserver/sonarr:latest"), { registry: "lscr.io", repo: "lscr.io/linuxserver/sonarr" });
  assert.deepEqual(normaliseRepo("localhost:5000/app:1"), { registry: "localhost:5000", repo: "localhost:5000/app" });
  assert.deepEqual(normaliseRepo("Index.Docker.io/library/nginx"), { registry: "docker.io", repo: "docker.io/library/nginx" });
});
test("live-lab shapes: shared images, Docker Hub short names, local builds", () => {
  const containers = [
    c("authentik-server-1", "ghcr.io/goauthentik/server:2026.5.6", "sha256:a1"),
    c("authentik-worker-1", "ghcr.io/goauthentik/server:2026.5.6", "sha256:a1"),
    c("hs-docker-proxy", "nginx:1.30.6-alpine", "sha256:n1"),
    c("palmetto-tech-site", "palmetto-tech-site-palmetto-tech-site", "sha256:p1"),
    c("old", "nginx:1.30.6-alpine", "sha256:n1", "exited")
  ];
  const images = [img("sha256:a1", ["ghcr.io/goauthentik/server:2026.5.6"], [`ghcr.io/goauthentik/server@${D(1)}`]),
    img("sha256:n1", ["nginx:1.30.6-alpine"], [`nginx@${D(2)}`]), img("sha256:p1", ["palmetto-tech-site-palmetto-tech-site:latest"], [])];
  assert.deepEqual(runningImages(containers, images), [
    { container: "authentik-server-1", imageRef: "ghcr.io/goauthentik/server:2026.5.6", status: "registry", registry: "ghcr.io", repo: "ghcr.io/goauthentik/server", digest: D(1) },
    { container: "authentik-worker-1", imageRef: "ghcr.io/goauthentik/server:2026.5.6", status: "registry", registry: "ghcr.io", repo: "ghcr.io/goauthentik/server", digest: D(1) },
    { container: "hs-docker-proxy", imageRef: "nginx:1.30.6-alpine", status: "registry", registry: "docker.io", repo: "docker.io/library/nginx", digest: D(2) },
    { container: "palmetto-tech-site", imageRef: "palmetto-tech-site-palmetto-tech-site", status: "local", reason: "built locally, no registry digest" }
  ]);
});
test("an image missing from the image list, or with only other repos' digests, is unknown", () => {
  const out = runningImages([c("a", "nginx:1", "sha256:x"), c("b", "nginx:1", "sha256:y")], [img("sha256:y", ["other:1"], [`docker.io/library/other@${D(3)}`])]);
  assert.deepEqual(out.map((r) => [r.container, r.status]), [["a", "unknown"], ["b", "unknown"]]);
  assert.match(out[0].reason, /not in the host's image list/u);
  assert.match(out[1].reason, /no registry digest matches/u);
});
test("a container started by image id uses the image's own tag to pick the digest", () => {
  const out = runningImages([c("a", "sha256:a1", "sha256:a1")], [img("sha256:a1", ["ghcr.io/x/y:1"], [`ghcr.io/x/y@${D(4)}`])]);
  assert.equal(out[0].digest, D(4));
});
test("a malformed digest is unknown, never trusted", () => {
  const out = runningImages([c("a", "nginx:1", "sha256:n")], [img("sha256:n", ["nginx:1"], ["nginx@sha256:not-hex"])]);
  assert.equal(out[0].status, "unknown");
});
test("registry hosts a pull may contact", () => {
  assert.deepEqual(registryHosts("docker.io").slice(0, 3), ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"]);
  assert.deepEqual(registryHosts("ghcr.io"), ["ghcr.io", "pkg-containers.githubusercontent.com"]);
  assert.deepEqual(registryHosts("lscr.io"), ["lscr.io", "ghcr.io", "pkg-containers.githubusercontent.com"]);
  assert.deepEqual(registryHosts("quay.io"), ["quay.io"]);
});
test("registries given by IP address, port or localhost are not scanned", () => {
  const out = runningImages([c("a", "127.0.0.1:5000/x:1", "sha256:a"), c("b", "registry.lan:5000/y:1", "sha256:b")],
    [img("sha256:a", ["127.0.0.1:5000/x:1"], [`127.0.0.1:5000/x@${D(1)}`]), img("sha256:b", ["registry.lan:5000/y:1"], [`registry.lan:5000/y@${D(2)}`])]);
  assert.deepEqual(out.map((r) => [r.status, r.reason]), [["unknown", "registry given by address or port; not scanned"], ["unknown", "registry given by address or port; not scanned"]]);
});
test("Docker Hub pulls may use its Cloudflare R2 layer storage", () => {
  assert.ok(registryHosts("docker.io").includes("docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com"));
});
