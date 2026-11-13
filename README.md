# helmsman-security

A LAN-only security and operations engine for [Helmsman](https://github.com/nunesg130-boop/helmsman).
It collects evidence from Proxmox, Wazuh, Docker and endoflife.date and reports every check as
`ok`, `issue`, `unknown`, `not_applicable` or `excluded`. Missing or stale evidence is always
`unknown`, never `ok`. Phase 1 is read-only: the engine never changes any system.

- Design: `docs/superpowers/specs/2026-11-12-security-phase1-design.md`
- Plan: `docs/superpowers/plans/2026-11-12-security-engine-phase1.md`

Node.js 24, no npm dependencies. `npm test`, `npm run lint`, `npm run smoke`.
