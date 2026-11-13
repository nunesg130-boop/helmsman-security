# helmsman-security

A LAN-only security and operations engine for [Helmsman](https://github.com/nunesg130-boop/helmsman).
It collects evidence from Proxmox, Wazuh, Docker and endoflife.date and reports every check as
`ok`, `issue`, `unknown`, `not_applicable` or `excluded`. Missing or stale evidence is always
`unknown`, never `ok`. Phase 1 is read-only: the engine never changes any system.

- Design: `docs/superpowers/specs/2026-11-12-security-phase1-design.md`
- Plan: `docs/superpowers/plans/2026-11-12-security-engine-phase1.md`

Node.js 24, no npm dependencies. `npm test`, `npm run lint`, `npm run smoke`.

## Running it (operator notes)

The engine runs as one container in its own LXC on the LAN. It must never get a public route.

1. **Master key**: `openssl rand -hex 32 > master.key && chmod 600 master.key`. Mount it read-only at
   `/run/secrets/master.key`. Back it up somewhere safe: without it, stored credentials can't be read.
2. **Config**: copy `config.example.json` to the data volume as `/data/config.json` and fill it in.
   It must not contain passwords or tokens. The engine refuses to start if it does.
3. **Start** the container with `/data` as a persistent volume and ports 8443 (API) and 8081 (admin)
   published on the LAN interface only. The read-only container filesystem needs nothing else.
4. On first start the log shows:
   - the **Helmsman API token**, shown once. Paste it into Helmsman's Security connection.
   - the **API certificate fingerprint**. Helmsman pins this.
5. **Admin page** (holds, exclusions, manual links, credentials): proxy `http://<engine>:8081` through
   Caddy with Authentik `forward_auth` that copies `X-Authentik-Username`. Set
   `listen.adminAllowIp` to Caddy's IP. Every other source is dropped. Set the Proxmox token
   secret and Wazuh password there.

Every collector is read-only: a PVEAuditor token for Proxmox, a read-only RBAC user for Wazuh, and a
read-only socket proxy for Docker that only allows `GET` on containers and version. The engine
contacts only the hosts in its config plus `endoflife.date`.
