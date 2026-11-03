<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# Install with Docker

Tesla Charger Monitoring (`tcmon`) runs on any Linux host with Docker
(amd64 or arm64, including a Raspberry Pi 4/5). On TrueNAS SCALE, follow
[INSTALL_TRUENAS.md](INSTALL_TRUENAS.md) instead.

The image is `ghcr.io/bhager42/teslachargingmonitor`. Tags: `X.Y.Z`, `X.Y` and
`latest`. It is about 8 MB to download, runs as a non-root user (UID 568) with
a read-only filesystem, and contains no shell.

## Docker Compose (recommended)

```bash
mkdir tcmon && cd tcmon
curl -fsSLO https://raw.githubusercontent.com/bhager42/teslachargingmonitor/main/deploy/compose.yaml
mkdir data && sudo chown 568:568 data
```

Edit `compose.yaml`: set `TZ` to your time zone. Then:

```bash
docker compose up -d
```

```bash
docker compose logs tcmon | grep FIRST-RUN
```

Copy the `setup_token` from that line (valid for 30 minutes; `docker compose
restart` prints a new one), open `https://<host-ip>:8443/`, accept the
one-time self-signed certificate warning, and follow the setup page. Then
add your Wall Connector under **Settings → Wall Connectors** and Gmail under
**Notifications**.

Everything the app stores is in `./data`: `tcmon.db`, `secret.key` (encrypts
the saved Gmail password) and `tls/` (the HTTPS certificate).

## docker run

```bash
docker volume create tcmon-data
```

```bash
docker run -d --name tcmon --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,mode=1777 \
  -p 8443:8443 -e TZ=America/Chicago \
  -v tcmon-data:/data \
  ghcr.io/bhager42/teslachargingmonitor:latest
```

A named volume gets the right owner automatically. With a host folder
instead (`-v /srv/tcmon:/data`), `chown 568:568` the folder first, or run
with `--user <uid>:<gid>` of a user that owns it.

## Podman (rootless)

```bash
mkdir data && podman unshare chown 568:568 data
```

```bash
podman run -d --name tcmon --read-only --cap-drop ALL \
  -p 8443:8443 -e TZ=America/Chicago -v ./data:/data:Z \
  ghcr.io/bhager42/teslachargingmonitor:latest
```

## Settings

Everything else (Wall Connector address, polling, alerts, email, prices,
retention) is set in the web UI. Environment variables cover only what must
be known before the web server starts:

| Variable | Default | Purpose |
|---|---|---|
| `TZ` | `UTC` | Time zone for days, quiet hours and costs |
| `TCMON_LISTEN` | `:8443` | Listen address inside the container |
| `TCMON_TLS` | `auto` | `auto` (self-signed), `file` (your certificate), `off` (plain HTTP behind a proxy) |
| `TCMON_TLS_CERT_FILE`, `TCMON_TLS_KEY_FILE` | — | For `TCMON_TLS=file` |
| `TCMON_PUBLIC_HOSTNAMES` | — | Host names used in the browser (IPs always work); added to the certificate |
| `TCMON_TRUSTED_PROXIES` | — | CIDRs of a reverse proxy whose `X-Forwarded-For` is trusted |
| `TCMON_ALLOWED_CLIENT_CIDRS` | private and loopback ranges | Who may connect (LAN only by default) |
| `TCMON_ALLOW_INSECURE_HTTP` | `false` | Required with `TCMON_TLS=off` |
| `TCMON_PASSWORD_FILE` / `TCMON_PASSWORD_HASH_FILE` | — | Set the password from a Docker secret instead of the setup page |
| `TCMON_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## Updating

```bash
docker compose pull && docker compose up -d
```

The database is upgraded automatically on start. Back up `./data` first
(below). For repeatable installs, pin a version (`:0.7.0`) or a digest
(`:0.7.0@sha256:…`) instead of `latest`.

## Backup and restore

- Stop the app and copy the `data` folder, or use **Settings → Backup** in
  the web UI (database only — also keep `secret.key` and `tls/`).
- From the command line, while running:

  ```bash
  docker exec tcmon /tcmon backup /data/backup.db
  ```

To restore, stop the app, put `tcmon.db` (and the original `secret.key`) back
into `data/`, delete `tcmon.db-wal` and `tcmon.db-shm`, and start it again.

## Forgotten password

```bash
docker exec -it tcmon /tcmon reset-password
```

## Verify the image {#verify}

Release images are signed with [cosign](https://docs.sigstore.dev/) (keyless,
from this repository's release workflow) and carry an SBOM and SLSA
provenance.

```bash
cosign verify ghcr.io/bhager42/teslachargingmonitor:0.7.0 \
  --certificate-identity-regexp '^https://github\.com/bhager42/teslachargingmonitor/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

```bash
gh attestation verify oci://ghcr.io/bhager42/teslachargingmonitor:0.7.0 --repo bhager42/teslachargingmonitor
```

```bash
docker buildx imagetools inspect ghcr.io/bhager42/teslachargingmonitor:0.7.0 --format '{{json .SBOM}}'
```

## Building the image yourself

```bash
make image IMAGE=tcmon:dev
```

```bash
sudo make image-test IMAGE=tcmon:dev
```
