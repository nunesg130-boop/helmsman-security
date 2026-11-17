# Rollout — phase 2B (exposure, urgency, risk acceptance, posture score)

Owner steps, in order. Two things are added outside the engine: a small exporter on the Caddy LXC that writes a secret-free summary of Caddy's routes, and a read-only Cloudflare API token. Nothing here changes how any site is served.

## What this phase adds, and why each piece exists

- **Caddy route shape.** The engine needs to know which hostname leads to which machine and whether a login gate sits in front. Caddy's live config holds that, but it also holds secrets, so the engine never reads it. Instead a filter on the Caddy LXC reduces the config to names and structure only (`shape.json`), and Caddy serves that one file to the engine alone.
- **Cloudflare (read-only).** A tunnel is a second way in that bypasses the router. The engine reads the tunnel's rules and the Access policies in front of them, so "LAN-only" is only claimed when *no* path reaches a route.
- **Router facts, declared.** The ER605 has no collector, so port forwards, UPnP, DMZ and inbound IPv6 are written into the config by hand and always shown as "declared, not verified".

## 1. Install the exporter on the Caddy LXC

The four files in `deploy/caddy/` contain no secrets. Serve them briefly from `helmsec` and fetch them from the Caddy LXC.

On `helmsec`:
```
cd /opt/helmsman-security && git pull
cd deploy/caddy && python3 -m http.server 8099 --bind 192.168.0.116
```
Leave it running. On the **Caddy LXC**:
```
apt-get install -y jq curl
useradd --system --no-create-home --shell /usr/sbin/nologin hs-caddy
install -d -m 0755 /usr/local/share/hs-caddy
install -d -m 0755 -o hs-caddy -g hs-caddy /var/lib/hs-caddy
cd /usr/local/share/hs-caddy
curl -fsS -O http://192.168.0.116:8099/shape.jq -O http://192.168.0.116:8099/export-shape.sh
chmod 0755 export-shape.sh
cd /etc/systemd/system
curl -fsS -O http://192.168.0.116:8099/hs-caddy-shape.service -O http://192.168.0.116:8099/hs-caddy-shape.timer
systemctl daemon-reload && systemctl enable --now hs-caddy-shape.timer && systemctl start hs-caddy-shape.service
jq '{version, routes: (.servers[0].routes | length)}' /var/lib/hs-caddy/shape.json
```
Expected last line: `"version": 2` and a route count of 11 or more. Back on `helmsec`, stop the file server with Ctrl+C.

The exporter runs every 5 minutes as its own unprivileged user. It **fails closed**: if Caddy's admin API errors, or the filter fails, or the result doesn't validate, the previous file is left alone. The engine treats a file older than 30 minutes as stale and reports exposure as unknown rather than using old routes.

To confirm no secret leaves Caddy: `grep -ciE 'token|secret|password|key' /var/lib/hs-caddy/shape.json` prints `0` (header *names* such as `X-Authentik-Jwt` may appear; values never do — if the count isn't 0, look at the matching lines before going on).

## 2. Serve that one file to the engine only

Add this site to the Caddyfile on the Caddy LXC:
```
http://192.168.0.105:2020 {
    bind 192.168.0.105
    @engine remote_ip 192.168.0.116
    handle @engine {
        root * /var/lib/hs-caddy
        rewrite * /shape.json
        file_server
    }
    handle {
        respond 403
    }
}
```
Then:
```
caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
```
Check from `helmsec`: `curl -s http://192.168.0.105:2020/shape.json | head -c 80` shows the start of the JSON. From any other machine the same command returns nothing (403).

Port 2020 isn't forwarded by the router and no tunnel points at it. After rollout the engine itself lists this route as `lan` — a small proof that the reasoning works.

## 3. Create a read-only Cloudflare API token

Cloudflare dashboard → **My Profile → API Tokens → Create Token → Custom token**:

| Scope | Permission |
|---|---|
| Account → Cloudflare Tunnel | Read |
| Account → Access: Apps and Policies | Read |
| Zone → DNS (zone `jellofin.com`) | Read |

Nothing else, and no Edit permissions. Save the token in the password manager; **don't paste it into chat or into `config.json`**.

Note three ids (these are identifiers, not secrets):
- **Account ID** and **Zone ID**: on the `jellofin.com` overview page, right-hand column.
- **Tunnel ID**: Zero Trust → Networks → Tunnels → your tunnel (a UUID).

## 4. Update the engine's config

You need two machine keys. On the Proxmox nodes, `pct list` / `qm list` shows the id of the Caddy LXC and of the machine running `cloudflared`; the keys are `pve:guest:<id>`.

On `helmsec` (replace the six UPPERCASE values):
```
node -e '
const f="/etc/helmsman-security/config.json",fs=require("fs"),c=JSON.parse(fs.readFileSync(f));
c.exposure={
  caddy:{url:"http://192.168.0.105:2020/shape.json",assetKey:"pve:guest:CADDY_ID",address:"192.168.0.105"},
  cloudflare:{accountId:"ACCOUNT_ID",zoneId:"ZONE_ID",tunnelIds:["TUNNEL_ID"],assetKey:"pve:guest:CLOUDFLARED_ID",connectorAddress:"192.168.0.108"},
  expectedPrivate:["security.jellofin.com","vault.jellofin.com","paperless.jellofin.com","sure.jellofin.com"]
};
const r=c.network.find(n=>n.name==="er605");
r.portForwards=[{wanPort:80,lanIp:"192.168.0.105",lanPort:80,protocol:"tcp"},{wanPort:443,lanIp:"192.168.0.105",lanPort:443,protocol:"tcp"}];
r.upnp=false; r.dmz=false; r.ipv6Inbound=false;
fs.writeFileSync(f,JSON.stringify(c,null,2)+"\n")'
systemctl restart helmsman-security
```
- `expectedPrivate` is your own list of sites that should **not** be reachable from the internet. Today they all are (none has a LAN-only rule in Caddy), so the engine will report each as an issue until you add those rules — that is the to-do it is there to track. Edit the list to taste, or leave it `[]`.
- The router lines are your statement of what the ER605 does. If you later add a port forward or enable UPnP, change them here too; the engine can't see the router.
- The database upgrades itself on start (schema version 3).

## 5. Enter the Cloudflare token

https://security.jellofin.com → **Credentials** → `cloudflare.apiToken` → paste from the password manager (don't autofill) → Save. Then:
```
systemctl restart helmsman-security
```
Wait about three minutes, then `hs-report`.

## 6. What to expect in `hs-report`

- Collectors `caddy`, `cloudflare` and `exposure` are `ok`.
- **`=== PUBLIC ROUTES ===`** — one line per hostname (and per path where a path is treated differently, e.g. `paperless … /api/*`), with how it is reached, its login gate, the machine behind it and whether something is listening there.
  - `UNVERIFIED` in the gate column means a gate-like block exists but doesn't match the one pattern the engine can vouch for. It is treated as no gate until fixed or verified.
  - `listening: unknown` is normal for machines without an agent or where Docker isn't being read.
- **`=== ROUTE PROBLEMS ===`** — routes pointing at nothing, at an address no known machine has, or restrictions a tunnel walks around.
- **`=== URGENT ===`** — confirmed: internet-facing and either actively exploited or high/critical with a fix waiting.
- **`=== POSSIBLY URGENT ===`** — would be urgent if an open question went the wrong way; each line says what is uncertain.
- **`POSTURE …`** — two numbers, or `incomplete` with the reasons. See `docs/scoring.md`. With most machines unpatched the confirmed score will be low; that is expected and is what patching will move.

Expected new entries under ISSUES/UNKNOWNS: `exposure_expected_private` on the Caddy machine (the sites from step 4), and `paperless.jellofin.com /api/*` showing gate `none` in the routes table.

## Accepting a risk

Admin page → **Holds, exclusions and risk acceptances** → Kind `acceptance`: machine key, CVE, package and version exactly as the report shows them, a reason, and optionally an expiry. The engine records the finding's situation at that moment (exploited or not, how exposed, which gate) and the acceptance **stops applying by itself** if the package version changes, the CVE becomes actively exploited, the machine becomes more exposed, or its login gate stops being verified. Accepted findings stay listed, marked as accepted.

## Known limits

- Router settings are declared, not read. A forward added on the ER605 and not in the config is invisible to the engine.
- Which *package* answers a public route is inferred from the listening process name, and is always labelled as such ("possibly urgent"); it never changes the confirmed result.
- A login gate is verified by its shape in Caddy's config (Authentik forward-auth) or by Cloudflare Access policies. The engine does not test the gate by logging in.
- Hostnames used as upstreams (instead of IP addresses) aren't resolved; they are reported as a route problem.
- Without a Cloudflare section in the config, nothing is ever reported as `lan`: the engine can't rule a tunnel out.
