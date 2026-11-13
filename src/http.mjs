import https from "node:https";
import http from "node:http";
import tls from "node:tls";
import { redact } from "./redact.mjs";

export { redact };

export class CollectorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CollectorError";
    this.code = code;
  }
}

const LOGIN_PATH = "/security/user/authenticate";
const normFp = (fp) => String(fp ?? "").replace(/:/gu, "").toLowerCase();

// An agent whose connections are verified against a pinned SHA-256
// fingerprint BEFORE the socket is handed to the request, so no header
// (and no credential) is ever written to an unverified peer.
function pinnedAgent(pin, timeoutMs) {
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = (options, oncreate) => {
    const socket = tls.connect({ ...options, rejectUnauthorized: false });
    let done = false;
    const finish = (err, s) => { if (!done) { done = true; oncreate(err, s); } };
    // The request's own timeout only starts once it has the socket, so the
    // TCP connect + TLS handshake needs its own limit.
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish(new CollectorError("timeout", `no TLS handshake within ${timeoutMs} ms`));
    });
    socket.once("secureConnect", () => {
      socket.setTimeout(0);
      const fp = normFp(socket.getPeerCertificate()?.fingerprint256);
      if (fp !== pin) {
        socket.destroy();
        finish(new CollectorError("tls", "server certificate does not match the pinned fingerprint"));
      } else finish(null, socket);
    });
    socket.once("error", (e) => finish(e));
    return undefined;
  };
  return agent;
}

export function createHttp({ allowHosts = [], allowHttpHosts = [] } = {}) {
  const httpsHosts = new Set(allowHosts.map((h) => h.toLowerCase()));
  const plainHosts = new Set(allowHttpHosts.map((h) => h.toLowerCase()));

  function fetchJson(url, { method = "GET", headers = {}, body, timeoutMs = 10_000, deadlineMs = timeoutMs * 3, maxBytes = 5_000_000, certSha256 } = {}) {
    return new Promise((resolve, reject) => {
      let u;
      try { u = new URL(url); } catch { return reject(new CollectorError("egress_denied", "invalid URL")); }
      const host = u.hostname.toLowerCase().replace(/^\[|\]$/gu, "");
      if (u.protocol === "https:" ? !httpsHosts.has(host) : !(u.protocol === "http:" && plainHosts.has(host))) {
        return reject(new CollectorError("egress_denied", `${u.protocol}//${host} is not an allowed destination`));
      }
      if (method !== "GET" && !(method === "POST" && u.pathname === LOGIN_PATH)) {
        return reject(new CollectorError("egress_denied", `${method} ${u.pathname} is not allowed (read-only engine)`));
      }
      const lib = u.protocol === "https:" ? https : http;
      const opts = { method, headers: { accept: "application/json", ...headers } };
      if (u.protocol === "https:") {
        if (certSha256) opts.agent = pinnedAgent(normFp(certSha256), timeoutMs);
        else opts.rejectUnauthorized = true;
      }
      let settled = false;
      let deadline = null;
      const fail = (e) => { if (!settled) { settled = true; clearTimeout(deadline); reject(e); } };
      const req = lib.request(u, opts, (res) => {
        const status = res.statusCode ?? 0;
        if (status === 401 || status === 403) { res.resume(); return fail(new CollectorError("auth", `HTTP ${status}`)); }
        if (status < 200 || status >= 300) { res.resume(); return fail(new CollectorError("http", `HTTP ${status}`)); }
        const chunks = [];
        let size = 0;
        res.on("data", (c) => {
          size += c.length;
          if (size > maxBytes) { req.destroy(); return fail(new CollectorError("too_large", `response larger than ${maxBytes} bytes`)); }
          chunks.push(c);
        });
        res.on("end", () => {
          if (settled) return;
          try {
            settled = true;
            clearTimeout(deadline);
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            clearTimeout(deadline);
            reject(new CollectorError("parse", "response was not valid JSON"));
          }
        });
        res.on("error", (e) => fail(new CollectorError("network", e.message)));
      });
      req.setTimeout(timeoutMs, () => { req.destroy(); fail(new CollectorError("timeout", `no answer within ${timeoutMs} ms`)); });
      // Overall limit, so a server trickling bytes can't hold a run forever.
      deadline = setTimeout(() => { req.destroy(); fail(new CollectorError("timeout", `request took longer than ${deadlineMs} ms`)); }, deadlineMs);
      req.on("error", (e) => {
        if (e instanceof CollectorError) return fail(e);
        const code = /certificate|self[- ]signed|SSL|TLS/iu.test(`${e.code} ${e.message}`) ? "tls" : "network";
        fail(new CollectorError(code, redact(`${e.code ?? ""} ${e.message}`.trim())));
      });
      if (body !== undefined) req.write(typeof body === "string" ? body : JSON.stringify(body));
      req.end();
    });
  }

  return { fetchJson };
}
