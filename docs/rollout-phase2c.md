# Rollout — phase 2C (container image vulnerabilities)

Owner steps, in order. This adds a scanner service on the engine machine (`helmsec`). Nothing changes on the Docker hosts: their read-only gates already allow the image list the engine needs.

## How it fits together

- The **engine** works out which image each running container uses, identified by its registry digest, which doesn't change the way a `:latest` tag can. It drops a scan request for each image into `/var/lib/hs-grype/spool`.
- A separate **scanner service**, `hs-grype`, runs as its own user. It downloads each image once with Syft and records everything installed inside it (an SBOM). Grype then checks that record against its vulnerability database. When the database updates (daily), Grype re-checks the saved record without downloading the image again. Results go to `/var/lib/hs-grype/out`.
- The scanner **can't read the engine's database, config or master key**. It can only reach the registries your images come from (Docker Hub, ghcr.io, lscr.io) and Grype's database server; any other connection is refused. Docker Hub downloads are capped at 8 per hour, because Docker Hub limits anonymous pulls.
- Grype and Syft are **pinned** (Grype 0.122.0, Syft 1.57.2). The installer checks their published checksums, and the service refuses to start if a binary has changed since install.

## 1. Give helmsec room (on norco)

Images are up to 2.7 GB each, and helmsec has 1 GB of memory and about 6 GB free.

```
pct set 117 --memory 2048
pct resize 117 rootfs +15G
pct reboot 117
```

Check inside helmsec: `free -m` shows about 2048 total, and `df -h /` shows about 23 GB.

## 2. Install the scanner (on helmsec)

```
cd /opt/helmsman-security && git pull
which node
sh deploy/grype/install.sh
```

- `which node` should print `/usr/bin/node`. If it prints another path, tell Claude before continuing; the service file assumes `/usr/bin/node`.
- The installer downloads Grype and Syft and checks both checksums. It stops with `CHECKSUM MISMATCH` and installs nothing if either is wrong.
- It creates the user `hs-grype` and its folders, installs the service, and runs an isolation check. Both check lines must say **refused**. If either says READABLE, stop and tell Claude.

Start it:

```
systemctl enable --now hs-grype
sleep 60; journalctl -u hs-grype -n 20 --no-pager
cat /var/lib/hs-grype/out/db.json
```

- The log should show `started: grype 0.122.0, syft 1.57.2`.
- `db.json` should show `"status":"ok"` and a `built` date from today or yesterday. The first database download is a few hundred MB.

If the service fails with `226/NAMESPACE`, the container doesn't allow the unit's sandboxing (as in 2B). Remove the `ProtectSystem`, `ProtectHome`, `PrivateTmp` and `InaccessiblePaths` lines from `/etc/systemd/system/hs-grype.service`, then run `systemctl daemon-reload && systemctl restart hs-grype`, and run the isolation check again:

```
runuser -u hs-grype -- ls /var/lib/helmsman-security; runuser -u hs-grype -- ls /etc/helmsman-security
```

Both must fail with "Permission denied".

## 3. Let the engine write requests

The engine needs to write into `/var/lib/hs-grype/spool`. Check that its own service isn't sandboxed away from it:

```
systemctl show helmsman-security -p ProtectSystem -p ReadWritePaths
```

If `ProtectSystem=strict` (or `full`) is set, add the folder:

```
mkdir -p /etc/systemd/system/helmsman-security.service.d
printf '[Service]\nReadWritePaths=/var/lib/hs-grype/spool\n' > /etc/systemd/system/helmsman-security.service.d/hs-grype.conf
systemctl daemon-reload
```

## 4. Turn it on in the engine's config

```
node -e 'const f="/etc/helmsman-security/config.json",fs=require("fs"),c=JSON.parse(fs.readFileSync(f));c.images={enabled:true};fs.writeFileSync(f,JSON.stringify(c,null,2)+"\n")'
systemctl restart helmsman-security
```

The database upgrades itself on start (schema version 4). The engine reads results every 15 minutes.

## 5. Watch the first scan

The first full pass takes a few hours. There are 22 images, several gigabytes in total, and the Docker Hub images are spread over hours by the cap. Check progress with:

```
ls /var/lib/hs-grype/out | grep -c '^scan-'
hs-report | sed -n '/=== CONTAINER IMAGES/,/^POSTURE/p'
```

Images move from `PENDING: not scanned yet` to `scanned`. A failed image shows its reason:
- `pull-denied`: a private image, such as your own Helmsman image if its package isn't public.
- `rate-limited`: retried after an hour.
- `blocked-host <name>`: the registry needed a host that isn't on the list. Tell Claude the name.

## 6. Decide on the two locally built images

`palmetto-tech-site` and `palmetto-tech-site-form-handler` were built on docker-auth, so there's no registry copy to scan. They stay **unknown** until you either leave them that way or exclude them with a reason. To exclude, go to the admin page → Kind `exclusion` → Asset `pve:guest:201` → Check `image:palmetto-tech-site-palmetto-tech-site` → Reason, e.g. "built locally from my own source". Repeat with `image:palmetto-tech-site-form-handler`. Excluded images stay listed as excluded.

## What changes in the report

- New section **CONTAINER IMAGES**: every running container, its image, whether it was scanned, and its findings with the critical/high split and KEV count.
- Urgent lines name the container, e.g. `docker-apps [aliasvault]`.
  - When a public route lands on a container (`vault` → `aliasvault`), that container's flaws count as **internet-facing**, confirmed rather than guessed: urgent when severe with a fix waiting, or actively exploited.
  - Containers no route reaches count as reachable machines: urgent only when actively exploited.
- **Kasm** shows "Docker is installed but has no read-only gate". Adding the same nginx gate as on the other Docker hosts is optional and can come later.
- The posture score now also needs image coverage. Until the first pass finishes, it shows `incomplete` with the share of unscanned machines.

## Known limits

- Only images used by **running** containers are scanned.
- A finding with only a GitHub advisory id (no CVE number) shows KEV status **unknown**, because the KEV list names CVEs only.
- The scanner reads the amd64 variant of each image (`images.platform`).
- After a restart of the scanner service, its Docker Hub hourly count starts again from zero.
