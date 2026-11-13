import test from "node:test";
import assert from "node:assert/strict";
import { collectDocker } from "../src/collectors/docker.mjs";
import { createHttp } from "../src/http.mjs";
import { startFixtureServer } from "./helpers/fixture-server.mjs";

const CONTAINERS = [{
  Names: ["/sonarr"], Image: "lscr.io/linuxserver/sonarr:4.0.9", ImageID: "sha256:abc", State: "running", Status: "Up 3 days",
  Ports: [{ PrivatePort: 8989, PublicPort: 8989, Type: "tcp", IP: "0.0.0.0" }, { PrivatePort: 9898, Type: "tcp" }]
}];

async function run(routes) {
  const srv = await startFixtureServer(routes, { tls: false });
  try {
    const out = await collectDocker({ http: createHttp({ allowHttpHosts: ["127.0.0.1"] }), hosts: [{ name: "docker-vm", baseUrl: srv.url, assetKey: "pve:guest:109" }, { name: "gone", baseUrl: "http://127.0.0.1:1", assetKey: "pve:guest:200" }], now: () => 1000 });
    return { out, srv };
  } finally { await srv.close(); }
}

test("maps containers and published ports onto the host asset", async () => {
  const { out, srv } = await run({ "/containers/json": CONTAINERS, "/version": { Version: "27.3.1", ApiVersion: "1.47" } });
  const c = out.evidence.find((e) => e.assetKey === "pve:guest:109" && e.kind === "docker.containers").value;
  assert.deepEqual(c, [{ name: "sonarr", image: "lscr.io/linuxserver/sonarr:4.0.9", imageId: "sha256:abc", state: "running", status: "Up 3 days", ports: [{ privatePort: 8989, publicPort: 8989, type: "tcp", ip: "0.0.0.0" }, { privatePort: 9898, publicPort: null, type: "tcp", ip: null }] }]);
  assert.deepEqual(out.evidence.find((e) => e.kind === "docker.engine").value, { version: "27.3.1", apiVersion: "1.47" });
  assert.ok(srv.requests.some((r) => r.url === "/containers/json?all=1"));
  assert.ok(srv.requests.every((r) => r.method === "GET"));
});

test("a host that is down is a warning", async () => {
  const { out } = await run({ "/containers/json": CONTAINERS, "/version": { Version: "27.3.1", ApiVersion: "1.47" } });
  assert.ok(out.warnings.some((w) => /gone/u.test(w)));
  assert.equal(out.evidence.filter((e) => e.assetKey === "pve:guest:200").length, 0);
});
