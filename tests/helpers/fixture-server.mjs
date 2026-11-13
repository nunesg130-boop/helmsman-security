// Test helper: a local HTTPS (or HTTP) server answering fixed routes.
// Uses the committed TEST-ONLY certificate in tests/fixtures/tls.
import { createServer as createHttps } from "node:https";
import { createServer as createHttp } from "node:http";
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";

const key = readFileSync(new URL("../fixtures/tls/key.pem", import.meta.url));
const cert = readFileSync(new URL("../fixtures/tls/cert.pem", import.meta.url));
export const FIXTURE_CERT_SHA256 = new X509Certificate(cert).fingerprint256.replace(/:/gu, "").toLowerCase();

// routes: { "GET /path?query": body | (req, bodyText) => [status, body, headers?] }
// Lookup tries "METHOD path+query", then "METHOD path", then "path".
export async function startFixtureServer(routes, { tls = true } = {}) {
  const requests = [];
  const handler = (req, res) => {
    let text = "";
    req.on("data", (d) => { text += d; });
    req.on("end", async () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body: text });
      const path = req.url.split("?")[0];
      const route = routes[`${req.method} ${req.url}`] ?? routes[`${req.method} ${path}`] ?? routes[req.url] ?? routes[path];
      let status = 404;
      let body = { error: "no route" };
      let headers = {};
      if (typeof route === "function") [status, body, headers = {}] = await route(req, text);
      else if (route !== undefined) [status, body] = [200, route];
      const payload = typeof body === "string" ? body : JSON.stringify(body);
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(payload);
    });
  };
  const server = tls ? createHttps({ key, cert }, handler) : createHttp(handler);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    url: `${tls ? "https" : "http"}://127.0.0.1:${port}`,
    host: "127.0.0.1",
    certSha256: FIXTURE_CERT_SHA256,
    requests,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); })
  };
}
