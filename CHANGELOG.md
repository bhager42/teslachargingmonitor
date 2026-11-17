# Changelog

All notable changes to Tesla Charger Monitoring (`tcmon`) are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/). Container
images for every release are at `ghcr.io/bhager42/teslachargingmonitor`,
signed with cosign ([how to verify](docs/INSTALL_DOCKER.md#verify)).

## [1.6.0] - 2026-11-17

### Added
- **Solar production and savings.** The dashboard's Solar Gateway card
  shows the solar produced today and this week and the money it saved,
  updated live. The Costs page adds a *Solar production and savings*
  table: today, this week, this month, this year, since tcmon started,
  and the Gateway meter's lifetime production.
- **Settings → Energy cost → Solar savings** chooses how savings are
  counted: *Solar used at home* (the default: solar the home used
  directly, plus Powerwall energy estimated to have come from solar;
  exports earn nothing) or *All solar produced* (every kWh, as with full
  net metering). Energy is priced at your rate when it was produced or
  used, off-peak included. See [docs/SOLAR.md](docs/SOLAR.md).

## [1.5.2] - 2026-11-17

No change to the app itself; this release adds real-hardware test data.

### Added
- Test fixtures from the owner's hardware, exported with `tcmon fixture
  export`: Universal Wall Connector firmware 26.34.0 while charging and
  while plugged in after charging, and Backup Gateway firmware 26.34.2 at
  night with the Powerwalls at the backup reserve.
- Tests that these real captures raise no default alerts and that the
  dashboard shows the night capture as *Using grid* and the midday one as
  *Self-powered*.

## [1.5.1] - 2026-11-17

### Fixed
- A Wall Connector or Gateway saved in the web UI in the first moment
  after tcmon started could stop being polled until the next restart.

### Changed
- Dependency updates: `golang.org/x/crypto` 0.59.0, `golang.org/x/text`
  0.44.0, `modernc.org/sqlite` 1.62.0; Playwright 1.65.1 for the browser
  tests (not in the image).

## [1.5.0] - 2026-11-17

### Added
- **Dashboard status for solar and Powerwall:** the Solar Gateway card
  shows a status line with a coloured dot, like a Wall Connector's
  "Plugged in": *Self-powered* or *Exporting to grid* (green), *Using
  grid* or *Grid outage* (red). Below it, a bar splits what the home (car
  included) is using right now between solar plus Powerwall (green) and
  the grid (red), with the percentages written out. Both update live, on
  the dashboard and on the Solar page.
- **Add Solar Gateway** button on the dashboard, next to *Add Wall
  Connector*, until a Gateway is set up.

## [1.4.1] - 2026-11-16

### Added
- `tcmon fixture export` writes a redacted copy of a stored Wall Connector
  or Gateway poll (latest, charging, plugged in, night or grid outage) as
  test fixtures, so captures no longer need a live capture session or a
  Gateway login.

## [1.4.0] - 2026-11-16

### Added
- **Solar and Powerwall** (optional): tcmon can read a Tesla Backup Gateway
  2 (Powerwall 2 or Powerwall+) on the LAN, read only and without Tesla's
  cloud. See [Solar and Powerwall](docs/SOLAR.md).
  - **Settings → Solar Gateway** adds it:
    - tcmon finds the Gateway and shows its certificate fingerprint for you
      to confirm; the certificate is then pinned;
    - you enter the customer password, which is stored encrypted;
    - saving tests the password with one login.

    The page then shows the Gateway's status and recent polls, and lets you
    accept a changed certificate, poll it now or remove it.
    `tcmon gateway` does the same from the command line.
  - **Polling:** every 15 minutes, and every 5 minutes while a car is
    plugged in. A rejected password is never retried at once: tcmon waits
    5 minutes, doubling up to 6 hours, also across restarts, so it cannot
    lock you out of the Gateway.
  - **Dashboard:** a live power-flow card (solar, home, car charging, grid
    import or export, Powerwall charging or supplying, battery %, grid
    status).
  - **Solar page:**
    - totals for today, this month, this year and all time: production,
      home use, grid import and export, solar used on site,
      self-sufficiency;
    - production per day, week, month or year;
    - the last 24 hours of power and battery level.
  - **Costs page:** charging split into solar, Powerwall and grid energy,
    with the solar savings. This is approximate: the car is assumed to get
    the home's mix in each polling interval. The daily and sessions CSV
    downloads gain `attributed_kwh`, `solar_kwh`, `powerwall_kwh`,
    `grid_kwh` and `solar_savings` columns, empty without Gateway data.
    These columns are added at the end, so anything reading the CSV by
    column count needs updating.
  - **Alerts:** Gateway unreachable, login failed and certificate changed;
    grid outage, with a notice when the grid is back; Powerwall battery low
    (a warning during an outage); no solar in daylight; a low solar day
    (off by default); Powerwall capacity dropped; Gateway firmware updates
    and restarts. They can be previewed against stored readings, snoozed,
    and are emailed like the Wall Connector's.
  - **Summary emails:** the weekly and monthly summaries gain a solar
    section.
  - **Diagnostics:** shows the Gateway's data quality and recent polls.
  - Battery percentages match the Tesla app.

### Fixed
- With a time-of-use rate whose off-peak window starts or ends inside the
  hour skipped by the spring daylight-saving change, charging across that
  night could be priced as if part of it were off-peak twice. Found by
  fuzzing.

### Changed
- The database schema moves to version 10, which adds the Gateway's
  tables and lets alerts belong to a Gateway. Existing alert history,
  open alerts and snoozes are kept. Back up the data directory before
  upgrading, as for every release.

## [1.3.1] - 2026-11-15

### Changed
- The container image is built on the latest distroless `static-debian13`
  base image.

## [1.3.0] - 2026-11-15

### Added
- An optional monthly summary email, sent on the 1st of each month at 08:00
  for the previous calendar month. It has the same content as the weekly
  summary, compared with the month before, and its costs include the
  monthly fee from your rate plan. Turn it on per email channel under
  Notifications; it can be previewed and sent on demand like the weekly one.

## [1.2.0] - 2026-11-15

### Added
- A "Firmware not updated" alert rule (`firmware_stale`, off by default) that
  fires when the firmware version has not changed for a configurable number
  of days (default 180). The Wall Connector does not report whether a newer
  version exists, so the rule counts from when tcmon first saw the current
  version, and mentions a missing internet connection when that is the likely
  cause.

### Security
- Built with Go 1.27.4, which fixes GO-2026-6859 in the standard library's
  `net/http`.

## [1.1.2] - 2026-11-10

### Fixed
- Acknowledging an alert in the Alerts history returns to that alert
  instead of the top of the page.

## [1.1.1] - 2026-11-10

### Changed
- The charts on a device page redraw live after each poll, like the status
  card, instead of only when the page is loaded.

## [1.1.0] - 2026-11-09

### Added
- Costs: a **year** tab on the cost chart, with one bar per year from the
  first year with charging data to the current one (monthly fees included
  for each month with usage).

### Changed
- Charging costs are now complete for all time: pruning old readings keeps
  the energy counter readings that costs need (it removes only the inside
  of idle stretches), so "All time" and the year chart no longer lose
  data older than the readings retention (2 years by default).

## [1.0.0] - 2026-11-08

First stable release. From 1.0.0 on, the configuration (environment
variables, data directory layout, database migrations) is kept backward
compatible within 1.x; upgrading is replacing the image.

### Changed
- All user-facing text (web pages, alert rules, status names, validation
  errors, alert emails and the weekly summary) now comes from one message
  catalog, `internal/i18n/locales/en.json`, so another language can be added
  later as one file ([ADR 0006](docs/adr/0006-message-catalog.md)). English
  wording is unchanged.

### Fixed
- The weekly summary said "identity mismatchs"; it now says "identity
  mismatches".

### Testing
- Lighthouse runs in CI on the main pages, signed in, as a desktop and as a
  throttled phone: performance must score at least 95, accessibility and
  best practices 100.

## [0.8.0] - 2026-11-06

### Added
- Optional weekly summary email every Monday at 08:00 (opt-in per email
  channel): last week's charging energy and cost per Wall Connector compared
  with the week before, charging sessions, polls, highest temperatures, grid
  voltage range, device events and alerts. Previewable and sendable on
  demand from Notifications.
- Optional dead-man's-switch ping: an HTTPS URL (healthchecks.io, Uptime
  Kuma push monitor, …) called after each successful poll, so you hear about
  it if tcmon itself stops. Stored encrypted; status in Diagnostics.

### Fixed
- "Car plugged in but not ready" no longer fires while a car sits plugged in
  and idle (after charging or waiting for a schedule); reason `1`, which the
  Universal Wall Connector reports normally, is ignored.
- Directory listings of the static files are no longer served.
- The theme cookie now has the `tcmon_` prefix like the others.
- Email From names that could not be read back by mail software are rejected.
- Off-peak windows on daylight-saving-change days were shifted or counted
  twice, which could make a cost negative.
- The default maximum current for breakers above 125 A exceeded 100 A.

### Security
- Threat model finalised and the OWASP ASVS 5.0 Level 1–2 checklist
  completed (`docs/security/asvs.md`, `docs/security/controls.md`).
- Fuzzing extended to 10 targets, run in CI.

## [0.7.2] - 2026-11-04

### Fixed
- "Car plugged in but not ready" no longer warns a few minutes into every
  charge.
- Charging state 11 is shown as "Charging", based on a real capture from a
  Universal Wall Connector.

### Changed
- Updated `modernc.org/sqlite` to 1.61.1.

## [0.7.1] - 2026-11-03

### Fixed
- Settings could not be saved while a retention was set to "Keep forever".

### Changed
- The README shows the TrueNAS install YAML and steps up front.
- TrueNAS: the app page has a **Web UI** button that opens the HTTPS address.
- Install examples use `America/New_York` as the time zone.

## [0.7.0] - 2026-11-03

First published release.

### Added
- Polling of the Wall Connector's local API (`/api/1/vitals`, `/lifetime`,
  `/wifi_status`, `/version`) every 60 minutes, every 5 minutes while a car is
  plugged in; both adjustable. Wall Connectors are added and edited in the
  web UI.
- Readings stored in SQLite with adjustable retention (2 years by default).
- Alert rules with debounce, hysteresis, cooldown, repeats and snoozes:
  temperatures, thermal foldback, device alerts, grid voltage and frequency,
  overcurrent, charger offline, reboots, firmware and grid-profile changes,
  and more. Thresholds are editable, with a preview against recent data.
- Email alerts over TLS (Gmail preset and other SMTP providers), batched,
  with per-channel severity filters and quiet hours.
- HTTPS web UI behind a single password (self-signed certificate by
  default, LAN only): live dashboard, device charts, alert history and rules,
  notification channels, settings, diagnostics; dark and light themes;
  WCAG 2.2 AA; works from 320 px wide.
- Charging cost: electricity price with history, optional off-peak price and
  monthly fee, cost on the dashboard, Costs page with day/week/month charts,
  sessions table and CSV export.
- Container image under 25 MB for amd64 and arm64: non-root, read-only, no
  shell, signed with cosign, with SBOM and provenance. Install guides for
  TrueNAS SCALE 25.10+ and Docker/Podman.

[1.6.0]: https://github.com/bhager42/teslachargingmonitor/compare/v1.5.2...v1.6.0
[1.5.2]: https://github.com/bhager42/teslachargingmonitor/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/bhager42/teslachargingmonitor/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/bhager42/teslachargingmonitor/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/bhager42/teslachargingmonitor/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/bhager42/teslachargingmonitor/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/bhager42/teslachargingmonitor/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/bhager42/teslachargingmonitor/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/bhager42/teslachargingmonitor/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/bhager42/teslachargingmonitor/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/bhager42/teslachargingmonitor/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/bhager42/teslachargingmonitor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/bhager42/teslachargingmonitor/compare/v0.8.0...v1.0.0
[0.8.0]: https://github.com/bhager42/teslachargingmonitor/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/bhager42/teslachargingmonitor/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/bhager42/teslachargingmonitor/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/bhager42/teslachargingmonitor/releases/tag/v0.7.0
