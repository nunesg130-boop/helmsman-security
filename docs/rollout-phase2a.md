# Rollout — phase 2A (host vulnerability findings)

Owner steps, in order. Nothing here changes a machine other than adding one read-only login to Wazuh and editing the engine's own config.

## 1. Check the engine can reach Wazuh's indexer and the two public lists
On `helmsec`:
```
curl -sk -o /dev/null -w "%{http_code}\n" https://192.168.0.115:9200
curl -sI https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | head -1
curl -sI https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | head -1
```
Expected: `401` (reachable, login required), `200`, then `302` for EPSS (a redirect to the dated file, which the engine follows).

If the first prints `000`, the indexer only listens on the Wazuh VM itself (`network.host: "127.0.0.1"`, the all-in-one default). Don't open it to the LAN. Add a doorway on the Wazuh VM that only accepts helmsec, leaving Wazuh's own settings untouched (from the Proxmox node's shell, VM 116):
```
cat > /root/wazuh-indexer-gate.sh <<'GATE'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq socat
cat > /etc/systemd/system/hs-indexer-gate.service <<'UNIT'
[Unit]
Description=Doorway to the Wazuh indexer for helmsman-security (only from 192.168.0.116)
After=network-online.target wazuh-indexer.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:9201,bind=192.168.0.115,fork,reuseaddr,range=192.168.0.116/32 TCP:127.0.0.1:9200
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now hs-indexer-gate
GATE
qm guest exec 116 --timeout 300 --pass-stdin 1 -- bash < /root/wazuh-indexer-gate.sh
```
It passes the TLS connection through untouched, so the certificate pin still works; the read-only part comes from the indexer login in step 2. Socat 1.8 needs `TCP4-LISTEN` for the `range=` rule. Use port **9201** in place of 9200 in steps 3 and 4. Test: from helmsec `curl -sk -o /dev/null -w "%{http_code}\n" https://192.168.0.115:9201` prints `401`; from any other machine it prints `000`.

## 2. Create the read-only indexer login (Wazuh dashboard)
1. **☰ → Indexer management → Security → Roles → Create role.** Name `helmsec_vuln_read`. Under **Index permissions**: index `wazuh-states-vulnerabilities-*`, permission `read`. No cluster or tenant permissions. Create.
2. **Security → Internal users → Create internal user.** Username `helmsec-vuln-ro`, a new strong password (save it in the password manager). Create.
3. Open the role `helmsec_vuln_read` → **Mapped users → Manage mapping** → add `helmsec-vuln-ro` → Map.

This login can only read vulnerability records. It cannot read alerts, change settings or see other indices.

## 3. Read the indexer's certificate fingerprint
On the Wazuh VM:
```
openssl s_client -connect 127.0.0.1:9200 </dev/null   # or, from helmsec, 192.168.0.115:9201 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```
Fingerprints are public; it is safe to share.

## 4. Update the engine
On `helmsec`, after the PR is merged (replace `FINGERPRINT` with the value from step 3, colons included or not):
```
cd /opt/helmsman-security && git pull
node -e 'const f="/etc/helmsman-security/config.json",fs=require("fs"),c=JSON.parse(fs.readFileSync(f));c.wazuh.indexer={baseUrl:"https://192.168.0.115:9200",user:"helmsec-vuln-ro",certSha256:"FINGERPRINT"};fs.writeFileSync(f,JSON.stringify(c,null,2)+"\n")'
printf '#!/bin/sh\nexec node --no-warnings /opt/helmsman-security/scripts/hs-report.mjs "$@"\n' > /usr/local/bin/hs-report && chmod 755 /usr/local/bin/hs-report
systemctl restart helmsman-security
```
The database upgrades itself on start (schema version 2). The engine needs outbound HTTPS to `www.cisa.gov` and `epss.empiricalsecurity.com` in addition to `endoflife.date`.

## 5. Enter the password
On https://security.jellofin.com → **Credentials** → choose `wazuh.indexerPassword` → paste the password from step 2 → Save. Copy and paste it from the password manager; don't use the browser's autofill on that field, which may fill the site's own login instead. To confirm the password itself is right: `curl -sk -u helmsec-vuln-ro https://192.168.0.115:9201/_plugins/_security/authinfo` should list `helmsec_vuln_read` under roles.

## 6. Restart once more, then check
The engine tried to read vulnerabilities at the restart in step 4, before it had the password, and won't retry for an hour. Restart it so it reads now:
```
systemctl restart helmsman-security
```
Wait about three minutes (the first read follows the normal collection), then:
```
hs-report
```
Expected: collectors `threat-feeds` and `wazuh-vulns` are `ok`; a `=== VULNERABILITIES ===` section lists every machine; the Wazuh server itself appears under UNKNOWNS for `vuln_coverage_host`.

## Known limit
The engine confirms that Wazuh holds vulnerability records for each machine and that it read all of them recently. It cannot yet confirm that Wazuh's own vulnerability database is up to date; that depends on the Wazuh server reaching its update service.

## What the columns mean
- **fixable by update**: a newer package version that fixes the flaw exists and isn't installed. Updating the machine clears these.
- **actively exploited (KEV)**: on CISA's list of flaws attackers are known to be using.
- **unrecognised**: records whose fix information the engine didn't recognise; their fix state is "unknown" rather than guessed.
