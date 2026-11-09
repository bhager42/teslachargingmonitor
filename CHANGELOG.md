# Changelog

All notable changes to Tesla Charger Monitoring (`tcmon`) are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/). Container
images for every release are at `ghcr.io/bhager42/teslachargingmonitor`,
signed with cosign ([how to verify](docs/INSTALL_DOCKER.md#verify)).

## [Unreleased]

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

[Unreleased]: https://github.com/bhager42/teslachargingmonitor/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/bhager42/teslachargingmonitor/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/bhager42/teslachargingmonitor/compare/v0.8.0...v1.0.0
[0.8.0]: https://github.com/bhager42/teslachargingmonitor/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/bhager42/teslachargingmonitor/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/bhager42/teslachargingmonitor/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/bhager42/teslachargingmonitor/releases/tag/v0.7.0
