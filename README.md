# Tesla Charger Monitoring

Self-hosted monitoring and email alerting for the **Tesla Universal Wall
Connector**, packaged as a small, hardened container for **TrueNAS SCALE
25.10+** or any Docker host.

> **Status: v1.1.0.** Polling, alerts, Gmail email, the HTTPS web UI (live
> dashboard, charts, alert rules, settings, diagnostics), charging costs,
> the optional weekly summary and dead-man's-switch ping all work, and
> everything is configured in the browser, including the Wall Connector's
> IP address. See the [CHANGELOG](CHANGELOG.md) and the
> [development plan](docs/DEVELOPMENT_PLAN.md).

## Install

### TrueNAS SCALE 25.10+

1. **Apps** → **Discover Apps** → **⋮** (top right) → **Install via YAML**.
2. **Name:** `tcmon`. Paste the YAML below and set `TZ` to your time zone.
   That is the only change needed: the data is kept in a volume TrueNAS
   manages on your apps pool.
3. **Save**, then open **Apps** → **tcmon** → **Workloads** → **View Logs**
   and copy the `setup_token` from the `FIRST-RUN SETUP` line.
4. Open `https://<truenas-ip>:8443/`, accept the one-time self-signed
   certificate warning, enter the token and choose a password.

```yaml
services:
  tcmon:
    image: ghcr.io/bhager42/teslachargingmonitor:latest
    container_name: tcmon
    restart: unless-stopped
    user: "568:568"                 # the TrueNAS "apps" user
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m,mode=1777"]
    ports: ["8443:8443"]
    environment:
      TZ: America/New_York          # EDIT: your time zone
      TCMON_TLS: auto
    volumes:
      - tcmon-data:/data
      # Optional: keep the data in your own dataset instead (owned by apps,
      # 568), replacing the line above:
      # - /mnt/tank/apps/tcmon:/data
    deploy:
      resources:
        limits: { cpus: "0.50", memory: 128M }
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "3" }
volumes:
  tcmon-data:
# TrueNAS: shows the "Web UI" button on the app page (0.0.0.0 = this server).
x-portals:
  - name: Web UI
    scheme: https
    host: 0.0.0.0
    port: 8443
    path: /
```

The full guide (updating, backups, your own dataset, password reset,
troubleshooting) is [docs/INSTALL_TRUENAS.md](docs/INSTALL_TRUENAS.md). The
same YAML is in [`deploy/truenas/custom-app.yaml`](deploy/truenas/custom-app.yaml).

### Docker / Podman

See [docs/INSTALL_DOCKER.md](docs/INSTALL_DOCKER.md) and
[`deploy/compose.yaml`](deploy/compose.yaml).

The image `ghcr.io/bhager42/teslachargingmonitor` is published for amd64 and
arm64 from release tags, signed with cosign and shipped with an SBOM and
provenance ([how to verify](docs/INSTALL_DOCKER.md#verify)).

## What it does

- Poll the Wall Connector's local API (`/api/1/vitals`, `/lifetime`,
  `/wifi_status`, `/version`) on a schedule — every 60 minutes by default and
  every 5 minutes while a car is plugged in, both adjustable in the web UI.
- Store readings in SQLite (2-year default retention, adjustable).
- Alert by **email (Gmail and other SMTP providers)** on concerning metrics:
  high temperatures, thermal foldbacks, device alerts, grid voltage/frequency
  out of range, overcurrent, charger offline, unexpected reboots, firmware or
  grid-profile changes, and more.
- Optional weekly summary email every Monday: last week's charging energy
  and cost, alerts, and Wall Connector health.
- Optionally ping a dead-man's-switch service (healthchecks.io, Uptime
  Kuma push monitor) after each successful poll, so you hear about it if
  tcmon itself stops.
- Dark-mode-first web dashboard protected by a single password, LAN-only,
  served over HTTPS (self-signed by default).

## Supported hardware

| Device | Status |
|---|---|
| Tesla Universal Wall Connector | Primary target; tested against firmware 26.26.10 and 26.34.0 |
| Tesla Wall Connector (Gen 3) | Expected to work (same API family), untested |

## Development

Requirements: Go (the toolchain version pinned in `go.mod` is downloaded
automatically), `make`, and optionally `golangci-lint` v2.

```bash
make check     # SPDX headers, lint, tests
make build     # -> bin/tcmon
./bin/tcmon version
```

Running the Wall Connector simulator (no hardware needed):

```bash
make sim SCENARIO=charging SPEED=60     # 1 simulated minute per second
go run ./cmd/wcsim -list                 # all scenarios
curl -d name=overheat http://127.0.0.1:8099/_sim/scenario
```

First run: `tcmon serve` prints a **one-time setup token** in its log; open
`https://<host>:8443/setup`, accept the self-signed certificate warning
(compare the SHA-256 fingerprint shown in the log), enter the token and choose
a password. Forgot it? `tcmon reset-password` in the container shell.

Headless end-to-end run against the simulator:

```bash
make sim SCENARIO=charging SPEED=60 &
go run ./cmd/tcmon device add -data-dir ./data -address 127.0.0.1:8099 -breaker 60
go run ./cmd/tcmon serve -data-dir ./data
```

Email alerts via Gmail (create an app password at
<https://myaccount.google.com/apppasswords> — it needs 2-Step Verification):

```bash
go run ./cmd/tcmon notify add-email -data-dir ./data -username you@gmail.com -to you@gmail.com -password-stdin
```

The password is read from standard input (or `-password-file`), encrypted
with the key in `./data/secret.key`, and a test email is sent. Back up
`secret.key` together with the database.

Browser tests (Playwright + axe, plus the Lighthouse budget in Chromium; needs
Node 22): `make e2e` (Chromium) or
`make e2e E2E_BROWSERS=chromium,firefox,webkit`.

Fuzzing: `make fuzz FUZZTIME=60s`. Soak test: `make soak`.

Capturing fixtures from a real Wall Connector (identifiers are redacted
automatically):

```bash
scripts/capture.sh 192.168.1.50            # idle
scripts/capture.sh 192.168.1.50 charging   # while a car is charging
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CLAUDE.md](CLAUDE.md).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 Brad Hager and contributors.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for details.

If you run a modified version of this software as a network service, the AGPL
requires you to offer your users the corresponding source code; the web UI's
"Source code" link exists for that purpose (set it to your fork's URL).

## Trademarks

"Tesla" and "Wall Connector" are trademarks of Tesla, Inc. Tesla Charger
Monitoring is an independent project and is not affiliated with, endorsed by,
or sponsored by Tesla, Inc. The name is used only to describe compatibility.
