# Wall Connector Monitor — Development Plan

> **Audience:** Claude Code (and human contributors).
> **Status:** Draft v2 — 2026-11-02. Owner decisions so far are recorded in [§15.0](#150-resolved-decisions); remaining open questions follow it.
> **License:** AGPL-3.0 (see §12).

A small, self-hosted, containerized web app that polls the local HTTP API of a
**Tesla Universal Wall Connector** (the owner's only hardware — the primary and
tested target) on a schedule, stores the readings, shows them in a dark-mode-first web
dashboard, and sends alerts when metrics look concerning. The Gen 3 Wall
Connector uses the same `/api/1/*` API family, so it should work too, but it is
**best-effort/untested** unless a contributor supplies fixtures. The data model
still supports multiple devices so a second unit can be added later. The primary deployment
target is **TrueNAS SCALE 25.10 ("Goldeye") or later**, but it must run on any
OCI/Docker host (Docker Engine, Podman, Compose, Portainer, Unraid, k8s).

Working name in this document: **`wcmon`** (rename freely — see §15).

---

## Table of contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [The Wall Connector local API](#2-the-wall-connector-local-api)
3. [Architecture](#3-architecture)
4. [Technology choices](#4-technology-choices)
5. [Data model](#5-data-model)
6. [Polling and the alert engine](#6-polling-and-the-alert-engine)
7. [Notifications](#7-notifications)
8. [Web UI (2026 web platform, dark mode)](#8-web-ui-2026-web-platform-dark-mode)
9. [Authentication (single password)](#9-authentication-single-password)
10. [Security baseline (2026)](#10-security-baseline-2026)
11. [Container and deployment (TrueNAS SCALE + generic Docker)](#11-container-and-deployment)
12. [Licensing (AGPL-3.0)](#12-licensing-agpl-30)
13. [Testing strategy](#13-testing-strategy)
14. [Phased delivery plan with acceptance criteria](#14-phased-delivery-plan)
15. [Open questions / inputs needed from the owner](#15-open-questions--inputs-needed-from-the-owner)
16. [Working rules for Claude Code](#16-working-rules-for-claude-code)

---

## 1. Goals and non-goals

### Goals
- Poll each configured Wall Connector's local API on a configurable schedule.
- Persist readings with a retention policy; show live and historical data.
- Evaluate configurable alert rules (thresholds, state changes, error codes,
  device offline, counters incrementing) with debounce, hysteresis, cooldown and
  recovery messages.
- Deliver alerts over one or more notification channels.
- Single-password protected web GUI; dark mode by default with light/system toggle.
- One small, non-root, read-only-rootfs container; multi-arch (amd64 + arm64).
- First-class TrueNAS SCALE 25.10+ install path ("Install via YAML" custom app),
  plus plain `docker run` / `compose.yaml`.
- AGPL-3.0 licensed, supply-chain-hardened builds (SBOM, signatures, provenance).

### Non-goals (v1)
- Controlling the charger (the local API is read-only; Tesla Fleet API / vehicle
  control is out of scope).
- Multi-user accounts, roles, SSO/OIDC.
- Cloud hosting / internet exposure as a supported configuration (LAN or
  reverse-proxy/VPN only; document the risk).
- Mobile native apps (the web UI is responsive and installable as a PWA).

---

## 2. The Wall Connector local API

The **Universal Wall Connector (UWC)** — like the Gen 3 Wall Connector it
descends from — exposes an **unauthenticated, read-only JSON API over plain HTTP
on port 80** on the LAN once it is joined to Wi-Fi. The endpoint list and field
names below come from the Gen 3 and are expected to match the UWC, but **they
must be verified against the owner's UWC in Phase 0** (capture real payloads;
the UWC may add, omit or rename fields, e.g. because of its built-in NACS/J1772
adapter). Endpoints marked *unverified* below are hypotheses until fixtures exist.

**Verification status (owner's UWC, part `1734412-52-F`, firmware `26.26.10`)**
— fixtures in `testdata/fixtures/uwc/26.26.10/`:

| Endpoint | Status | Findings |
|---|---|---|
| `/api/1/version` | ✅ verified | Gen 3 fields present **plus** `git_branch` and three IEEE 1547 CRCs: `IEEE1547VfTripsCrc`, `IEEE1547RideThruMomentaryCessationCrc`, `IEEE1547CombinedComplianceCrc` (8-hex-digit strings). `firmware_version` is semver-like with build metadata (`26.26.10+g<git-sha>`) — parse major.minor.patch and keep the full string. |
| `/api/1/lifetime` | ✅ verified | Field set identical to Gen 3. `avg_startup_temp` reported `0.0` (likely unused — don't alert on it). |
| `/api/1/vitals` | ✅ idle verified / ⏳ charging | **Differs from Gen 3:** `relay_coil_v` is absent; the UWC reports **`relay_k1_v` and `relay_k2_v`** (two relays, 0.0 when open). Idle with no vehicle: `evse_state` = 1, `config_status` = 5, `evse_not_ready_reasons` = `[2,4,8]` (so not-ready reasons are **normal when unplugged**), `pilot_high_v`/`pilot_low_v` = 12.0 (no vehicle on the pilot), per-phase `voltageX_v` ≈ 0 while the contactor is open (only `grid_v` is meaningful then). `uptime_s` here is **time since boot** (16 s at capture) whereas `lifetime.uptime_s` is cumulative — don't confuse them. Need a capture **while charging**. |
| `/api/1/wifi_status` | ⏳ unverified | Need capture. |

Note: the device stores lifetime counters (e.g. `alert_count` was already 3 at
first capture). Counter-based rules must take a **baseline on first sighting**
and only fire on increases afterwards — never on initial import.

| Endpoint | Purpose | Suggested poll cadence |
|---|---|---|
| `GET /api/1/vitals` | Live electrical/thermal state, alerts, EVSE state | every poll (default 30 s) |
| `GET /api/1/lifetime` | Lifetime counters (energy, contactor cycles, thermal foldbacks, alert count) | every 5 min |
| `GET /api/1/wifi_status` | RSSI, SNR, signal strength, connectivity | every 5 min |
| `GET /api/1/version` | Firmware version, part/serial number | on start + hourly |

Commonly observed fields (treat as **unverified until Phase 0 captures real
payloads**; the parser must tolerate unknown/missing fields):

- **vitals (idle verified on UWC):** `contactor_closed`, `vehicle_connected`, `session_s`, `grid_v`,
  `grid_hz`, `vehicle_current_a`, `currentA_a`, `currentB_a`, `currentC_a`,
  `currentN_a`, `voltageA_v`, `voltageB_v`, `voltageC_v`,
  `relay_k1_v` + `relay_k2_v` (UWC, verified) *or* `relay_coil_v` (Gen 3),
  `pcba_temp_c`, `handle_temp_c`, `mcu_temp_c`, `uptime_s`,
  `input_thermopile_uv`, `prox_v`, `pilot_high_v`, `pilot_low_v`,
  `session_energy_wh`, `config_status`, `evse_state`, `current_alerts[]`,
  `evse_not_ready_reasons[]`.
- **lifetime (verified on UWC):** `contactor_cycles`, `contactor_cycles_loaded`, `alert_count`,
  `thermal_foldbacks`, `avg_startup_temp`, `charge_starts`, `energy_wh`,
  `connector_cycles`, `uptime_s`, `charging_time_s`.
- **wifi_status:** `wifi_ssid` (base64), `wifi_signal_strength`, `wifi_rssi`,
  `wifi_snr`, `wifi_connected`, `wifi_infra_ip`, `internet`, `wifi_mac`.
- **version (verified on UWC):** `firmware_version`, `git_branch`,
  `part_number`, `serial_number`, `web_service`, `IEEE1547VfTripsCrc`,
  `IEEE1547RideThruMomentaryCessationCrc`, `IEEE1547CombinedComplianceCrc`.

Implications for the design:
- The device is a small embedded controller: **never poll faster than every
  10 s**, use one request at a time per device, short timeouts (5 s), and
  exponential backoff when it is unreachable.
- Because the API is plain HTTP and unauthenticated, the app must treat responses
  as **untrusted input** (strict decoding, size limits, numeric range checks).
- Firmware updates may add/rename fields. Store the **raw JSON** alongside the
  parsed columns (short retention) so new fields can be back-filled, and surface
  "unknown field seen" in the diagnostics page.
- `evse_state` and alert codes are numeric/opaque. Keep a mapping table in code
  (`internal/wallconnector/codes.go`) that can grow; show raw values when unknown.
  Seed it only with **observed** meanings (UWC fw 26.26.10: `evse_state` 1 =
  idle/unplugged; `config_status` 5 = normal configured state; not-ready
  reasons 2, 4, 8 present while unplugged). Unconfirmed meanings are labelled
  "unknown (code N)" rather than guessed. The UI should also learn the
  "normal" code set per device and highlight codes never seen before.

---

## 3. Architecture

Single process, single container, no external services required.

```
                ┌──────────────────────────── wcmon container ────────────────────────────┐
                │                                                                          │
 Wall           │  ┌───────────┐   readings   ┌──────────────┐  events  ┌───────────────┐ │
 Connector(s) ◄─┼──│  Poller   │─────────────►│ Alert engine │─────────►│ Notifier queue│─┼─► ntfy / email /
 HTTP :80       │  │ (per dev) │              │ (rules, state│          │ (retry, dedupe)│ │   webhook / …
                │  └─────┬─────┘              │  machine)    │          └───────────────┘ │
                │        │                    └──────┬───────┘                            │
                │        ▼                           ▼                                    │
                │  ┌──────────────────────── SQLite (WAL) /data/wcmon.db ───────────────┐ │
                │  └─────────────────────────────────▲───────────────────────────────────┘ │
                │                                    │                                    │
                │  ┌──────────────────── HTTP(S) server :8443 ──────────────────────────┐ │
 Browser ◄──────┼──│ auth · CSRF · CSP · SSR pages · JSON API · SSE live stream         │ │
                │  └─────────────────────────────────────────────────────────────────────┘ │
                └──────────────────────────────────────────────────────────────────────────┘
```

Components (Go packages under `internal/`):

| Package | Responsibility |
|---|---|
| `config` | Load env vars / `*_FILE` secrets / settings stored in DB; validate. |
| `wallconnector` | HTTP client + typed models + tolerant decoder + code tables. |
| `poller` | Per-device scheduler (ticker + jitter + backoff), writes readings, publishes to an in-process event bus. |
| `store` | SQLite access, migrations (embedded), retention/downsampling jobs. |
| `alerts` | Rule definitions, evaluation, debounce/hysteresis/cooldown state machine, alert history. |
| `notify` | Channel implementations, delivery queue with retries, templating, test-send. |
| `auth` | Password hashing (Argon2id), sessions, login rate limiting/lockout. |
| `web` | Router, middleware (security headers, CSRF, auth), templates, static assets (embedded), SSE. |
| `cli` | Sub-commands: `serve`, `healthcheck`, `reset-password`, `hash-password`, `migrate`, `version`. |

---

## 4. Technology choices

Chosen to minimize attack surface, image size and supply-chain exposure while
staying easy for Claude Code to build and maintain.

| Concern | Choice | Why |
|---|---|---|
| Language | **Go (latest stable, ≥ 1.25)** | Static binary, memory-safe, excellent stdlib HTTP, built-in `http.CrossOriginProtection` (Fetch-Metadata CSRF defense), tiny distroless image. |
| HTTP routing | stdlib `net/http` `ServeMux` (method + path patterns) | No framework dependency. |
| Database | **SQLite** via `modernc.org/sqlite` (pure Go, no cgo), WAL mode | Zero ops, single file on a TrueNAS dataset, works on read-only rootfs with `/data` volume. |
| Migrations | Embedded SQL files + a tiny in-house runner (or `pressly/goose` embedded) | Deterministic, offline. |
| Templates | `html/template` (contextual auto-escaping) | XSS-safe server rendering. |
| Frontend | **No build step**: semantic HTML + modern CSS + native ES modules; progressive enhancement | Nothing to `npm install` at runtime → smaller supply chain. |
| Charts | Vendored **uPlot** (MIT) pinned + checksum-verified, or hand-rolled SVG sparklines | Fast, tiny, CSP-friendly (no `eval`). |
| Live updates | **Server-Sent Events** | Simple, one-way, works through proxies. |
| Password hashing | `golang.org/x/crypto/argon2` (Argon2id) | OWASP-recommended. |
| Notifications | In-house small channel implementations (ntfy, SMTP, webhook, …) **or** `shoutrrr` (maintained fork) — decide in Phase 4 after dependency/licence review | Keep dependency count low. |
| Logging | `log/slog` JSON to stdout | Container-native; TrueNAS shows container logs. |
| Metrics (optional) | Prometheus text format at `/metrics`, bearer-token protected, off by default | For Grafana users. |
| Container base | `gcr.io/distroless/static-debian12:nonroot` (or `scratch` + CA certs), pinned by **digest** | No shell, no package manager. |

If the owner prefers Python/TypeScript, the architecture still applies; only §4
and the Dockerfile change (see §15).

---

## 5. Data model

SQLite, WAL, `foreign_keys=ON`, `busy_timeout=5000`. All timestamps UTC epoch ms.

```
devices(id, name, base_url, enabled, poll_interval_s, nominal_voltage_v,
        breaker_a, phase_config, created_at, updated_at)
device_info(device_id PK, firmware_version, git_branch, part_number,
        serial_number, web_service, ieee1547_vf_trips_crc,
        ieee1547_ride_thru_crc, ieee1547_combined_crc, last_seen_at,
        first_seen_at)
readings_vitals(id, device_id, ts, contactor_closed, vehicle_connected,
        grid_v, grid_hz, vehicle_current_a, currentA_a, currentB_a, currentC_a,
        currentN_a, voltageA_v, voltageB_v, voltageC_v, relay_k1_v,
        relay_k2_v, relay_coil_v NULL /* Gen 3 only */,
        pcba_temp_c, handle_temp_c, mcu_temp_c, uptime_s, session_s,
        session_energy_wh, evse_state, config_status, alerts_json,
        not_ready_json)                                  -- index (device_id, ts)
readings_lifetime(id, device_id, ts, contactor_cycles, contactor_cycles_loaded,
        alert_count, thermal_foldbacks, charge_starts, energy_wh,
        connector_cycles, charging_time_s, uptime_s)
readings_wifi(id, device_id, ts, rssi, snr, signal_strength, connected, internet)
raw_payloads(id, device_id, ts, endpoint, body)          -- short retention (default 7 d)
rollups_5m / rollups_1h(device_id, bucket_ts, metric, min, max, avg, count)
sessions_charging(id, device_id, start_ts, end_ts, energy_wh, max_current_a,
        max_handle_temp_c)                                -- derived
alert_rules(id, key, device_id NULL=all, enabled, severity, params_json,
        for_s, cooldown_s, repeat_s, notify_channels_json)
alert_state(rule_id, device_id, state, since_ts, last_value, last_notified_ts)
alert_events(id, rule_id, device_id, ts, kind[firing|resolved|repeat],
        severity, message, value, acked_at)
notify_channels(id, type, name, enabled, config_enc BLOB, created_at)
notify_deliveries(id, event_id, channel_id, ts, status, attempts, error)
settings(key PK, value_json)
auth(id=1, password_hash, password_changed_at)
web_sessions(id_hash PK, created_at, last_seen_at, expires_at, ua_hash, ip)
login_attempts(ip, ts)                                   -- for throttling
audit_log(id, ts, actor_ip, action, details_json)
```

Retention defaults (all configurable): raw vitals 30 d → 5-min rollups 1 y →
1-h rollups forever; raw payloads 7 d; alert events 2 y; audit log 1 y. Nightly
`VACUUM`/`PRAGMA optimize`; online backup via `VACUUM INTO` exposed as a
downloadable backup in Settings.

**Secrets at rest:** notification channel credentials are encrypted with
AES-256-GCM (or XChaCha20-Poly1305) using a key from `WCMON_SECRET_KEY_FILE`
(auto-generated into `/data/secret.key` with `0600` on first start if not
provided). Never return decrypted secrets to the browser — show "•••• set".

---

## 6. Polling and the alert engine

### Poller
- One goroutine per enabled device; `time.Ticker` at `poll_interval_s`
  (default **30 s**, min 10 s, max 3600 s) with ±10 % jitter.
- Optional "active charging" cadence: poll faster (e.g. 15 s) while
  `vehicle_connected || contactor_closed`, slower (e.g. 60 s) when idle.
- Per-request timeout 5 s; response body limit 64 KiB; reject non-JSON.
- Unreachable → exponential backoff (cap 5 min) and emit `device_unreachable`
  signal for the alert engine.
- The device address comes **only from the Web GUI** (see §8 "Device
  management"); changes take effect immediately — the poller for that device is
  restarted without restarting the container.
- Device address validation: IPv4, IPv6 or hostname (optional `:port`),
  normalised to `http://<host>[:port]`; must resolve to a **private/LAN
  address** by default (SSRF guard; an "allow non-private address" checkbox
  exists for odd networks). No redirects followed. Resolved IP is re-checked at
  connect time (DNS-rebinding safe).
- Detect reboot (uptime decreased) and firmware change (version differs).

### Alert rule semantics
Each rule produces a boolean "breaching" condition per device per evaluation.
A per-(rule, device) state machine provides:

- `for_s` (debounce): must breach continuously this long before **FIRING**.
- **Hysteresis**: resolve threshold is offset from fire threshold (e.g. fire at
  ≥ 70 °C, resolve at ≤ 65 °C).
- `cooldown_s`: minimum time between notifications for the same rule/device.
- `repeat_s`: optional re-notify while still firing (default off / 6 h for critical).
- **RESOLVED** notification when the condition clears (toggle per rule).
- Quiet hours (per channel) except for `critical`.
- Severity levels: `info`, `warning`, `critical`.
- Maintenance mode / snooze per device (e.g. "mute 2 h").

### Default rules (thresholds are *starting points* — owner to confirm, §15)

| Key | Condition | Default severity |
|---|---|---|
| `device_unreachable` | No successful poll for ≥ 3 consecutive attempts / 5 min | warning → critical after 30 min |
| `handle_temp_high` | `handle_temp_c` ≥ 55 °C (warn), ≥ 70 °C (crit), for 60 s | warning / critical |
| `pcba_temp_high` | `pcba_temp_c` ≥ 70 °C (warn), ≥ 85 °C (crit) | warning / critical |
| `mcu_temp_high` | `mcu_temp_c` ≥ 70 °C (warn), ≥ 85 °C (crit) | warning / critical |
| `thermal_foldback` | `lifetime.thermal_foldbacks` increased since last reading | warning |
| `device_alert_active` | `current_alerts` non-empty | warning (code-dependent) |
| `device_alert_count_up` | `lifetime.alert_count` increased | warning |
| `not_ready_reasons` | `evse_not_ready_reasons` non-empty while **vehicle connected** for > 2 min (UWC reports `[2,4,8]` routinely when unplugged — never alert on that) | warning |
| `grid_voltage_out_of_range` | `grid_v` (not per-phase `voltageX_v`, which read ≈ 0 when the contactor is open) outside nominal ± 5 % (warn) / ± 10 % (crit) — nominal 240 V (US split-phase), 208 V, 230 V or 400 V configurable | warning / critical |
| `grid_freq_out_of_range` | `grid_hz` outside 59.5–60.5 (60 Hz) or 49.5–50.5 (50 Hz) | warning |
| `phase_current_imbalance` | (3-phase only) max/min phase current deviation > 20 % while charging | info |
| `overcurrent` | `vehicle_current_a` > configured max current × 1.05 for 30 s | critical |
| `charging_stalled` | contactor closed & vehicle connected but current < 1 A for 10 min | info |
| `relay_voltage_abnormal` | while `contactor_closed`: `relay_k1_v`/`relay_k2_v` (UWC) or `relay_coil_v` (Gen 3) outside expected band, or K1 and K2 disagree significantly; while open: either relay > ~1 V (possible stuck relay). Band TBD from charging capture. | warning |
| `wifi_weak` | `wifi_rssi` < −75 dBm for 15 min | info |
| `wifi_no_internet` | `internet == false` for 30 min (affects firmware updates) | info |
| `unexpected_reboot` | uptime decreased | info |
| `firmware_changed` | firmware version changed | info |
| `grid_profile_changed` | any IEEE 1547 CRC in `/version` changed (grid-interconnection/trip settings altered, e.g. by a firmware update or remote config) | warning |
| `contactor_wear` | `contactor_cycles_loaded` crosses configurable milestones | info |

Rules are stored as data (`alert_rules`) with typed params; the UI provides a
form per rule type (no free-form expression language in v1 to avoid an
injection/complexity surface). A "Test rule against last 24 h" preview button
shows when it *would* have fired.

### Health of the app itself
- `self_notification_failure`: a channel failed N times → show banner in UI and
  try other channels.
- Daily/weekly optional **digest** (energy used, sessions, max temps, alerts).
- Optional **dead-man's switch**: ping an external URL (e.g. healthchecks.io /
  Uptime Kuma push) after every successful poll cycle so the owner learns if
  `wcmon` itself stops.

---

## 7. Notifications

Channel types (v1 candidates; owner picks which matter, §15):

- **ntfy** (self-hosted or ntfy.sh) — recommended default for TrueNAS users.
- **Email (SMTP)** — STARTTLS/implicit TLS required, TLS ≥ 1.2, auth.
- **Generic webhook** (JSON POST, optional HMAC-SHA256 signature header).
- **Home Assistant** (webhook trigger).
- **Gotify**, **Pushover**, **Discord**, **Slack**, **Telegram**, **Matrix**
  (add in later phases as needed).

Common features: per-channel minimum severity, quiet hours, message templates
(Go `text/template` with a restricted data struct), "Send test notification"
button, delivery queue persisted in SQLite with retry/backoff (1 m, 5 m, 15 m,
1 h; give up after 24 h), delivery log in UI. Outbound TLS verification always
on (custom CA bundle mountable for self-hosted endpoints).

---

## 8. Web UI (2026 web platform, dark mode)

**Principle:** server-rendered, progressively enhanced, framework-free; only use
web-platform features that are **Baseline "Widely available"** (or "Newly
available" with a graceful fallback) as of 2026.

### Pages
1. **Login** — single password field, show/hide toggle, `autocomplete="current-password"`.
2. **Dashboard** — per-device cards: state (idle / plugged in / charging /
   fault), live current & power, session energy & duration, grid V/Hz, the three
   temperatures as gauges, Wi-Fi strength, active alerts. Live via SSE.
3. **Device detail** — time-series charts (1 h / 24 h / 7 d / 30 d / 1 y),
   lifetime counters, firmware/serial, charging sessions table, raw latest JSON
   (collapsible), CSV export.
4. **Alerts** — active alerts, history, ack/snooze, rule editor, rule preview.
5. **Notifications** — channels CRUD, test-send, delivery log.
6. **Settings** — devices (see "Device management" below), poll intervals, retention,
   units (°C/°F), time zone, theme, change password, sign out all sessions,
   backup download, about/licence/source link (AGPL §13).
7. **Diagnostics** — poll latency/errors, unknown fields seen, DB size, version.

### Device management (Wall Connector address is set in the GUI)
The Wall Connector's IP/hostname is **configured only in the Web GUI** and stored
in the `devices` table — there is no env var or config file for it.

- **First-run onboarding:** after the initial password is set, a short wizard
  asks for the UWC's IP address or hostname (with a hint: "find it in your
  router's DHCP list or the Tesla One app; reserve it in your router so it
  doesn't change"). The dashboard shows an "Add your Wall Connector" empty
  state until one is saved.
- **Test connection** button (before saving and any time later): calls
  `/api/1/version` and `/api/1/vitals` with a 5 s timeout and shows the result —
  reachable / not reachable / not a Wall Connector (unexpected response), plus
  detected part number, firmware and a masked serial — so the owner can confirm
  it's the right device before saving.
- **Edit address** at any time (e.g. after a DHCP change). The device keeps its
  history because identity is tied to the device record and its serial number;
  if the serial reported at the new address differs from the stored one, warn
  ("this looks like a different Wall Connector") and ask to confirm.
- Per-device fields editable in the same form: display name, address, enabled,
  poll interval (and charging-time interval), nominal voltage/frequency,
  configured max current / breaker size (used by the voltage and overcurrent
  rules).
- `device_unreachable` alert text links straight to the edit form, since a
  changed IP is the most likely cause.
- All device changes are audit-logged and CSRF-protected like every other
  settings change.

### Platform features to use
- HTML: `<dialog>` for modals, **Popover API** for menus/toasts, `<details>`,
  `<search>`, `inert`, form validation attributes, `<template>`.
- CSS: `color-scheme: dark light`, **`light-dark()`** colour tokens, custom
  properties + `@property`, **CSS nesting**, **cascade layers (`@layer`)**,
  **container queries**, `:has()`, `:focus-visible`, logical properties,
  `clamp()`, subgrid, **View Transitions** (same-document, and cross-document
  `@view-transition` with fallback), `prefers-reduced-motion`,
  `prefers-contrast`, `forced-colors`.
- JS: native **ES modules** (ES2025), **import maps** (for vendored modules),
  `EventSource` (SSE), `fetch` with `AbortSignal.timeout()`, `Intl.*` for
  number/date/unit formatting, Web Components (custom elements, no shadow DOM
  required) for gauges/charts. **No inline scripts/styles** (CSP), **Trusted
  Types** enforced.
- PWA: Web App Manifest + minimal service worker (offline shell only; never
  cache API responses containing data after logout).

### Dark mode
- Default follows `prefers-color-scheme`, **dark styling designed first**.
- Toggle: System / Dark / Light, stored in a non-sensitive cookie (so SSR emits
  the right `data-theme` with no flash) and mirrored in `localStorage`.
- Colour tokens defined once with `light-dark()`; charts read tokens via
  `getComputedStyle` and re-render on theme change.
- Status colours always paired with icon + text (never colour alone).

### Accessibility & quality bars
- **WCAG 2.2 AA**: contrast ≥ 4.5:1 in both themes, focus visible, target size
  ≥ 24×24 px, full keyboard operation, `aria-live` for live values (throttled),
  reduced-motion respected.
- Responsive from 320 px phone width to wide desktop.
- Lighthouse ≥ 95 on performance/accessibility/best-practices; total JS < 60 KB
  gzipped (excluding charts library).

---

## 9. Authentication (single password)

### Bootstrap (first run)
Order of precedence:
1. `WCMON_PASSWORD_HASH` / `WCMON_PASSWORD_HASH_FILE` — pre-computed Argon2id
   PHC string (produced by `wcmon hash-password`).
2. `WCMON_PASSWORD_FILE` — plaintext in a Docker/TrueNAS secret file; hashed on
   start, plaintext never stored or logged.
3. Neither set → **setup mode**: a random one-time setup token is printed to the
   container log; the UI requires that token to set the initial password. Setup
   mode expires after 30 min (restart to regenerate).

Avoid plaintext `WCMON_PASSWORD` env vars (visible in `docker inspect`); accept
it only with a loud startup warning, or not at all (decide §15).

### Password policy (NIST SP 800-63B-4 aligned)
- Minimum 12 characters (configurable ≥ 8), maximum 128; allow all Unicode,
  NFKC-normalise; no composition rules; no forced rotation.
- Reject passwords found in a bundled list of common/breached passwords (top
  ~100k, embedded, offline). Optional k-anonymity HIBP check is **off** by
  default (no outbound calls without consent).

### Hashing
- **Argon2id**, defaults m = 64 MiB, t = 3, p = 1, 16-byte salt, 32-byte key
  (≥ OWASP minimum of m = 19 MiB, t = 2, p = 1); PHC string format so
  parameters can be upgraded and re-hashed transparently on next login.
- Constant-time comparison; a dummy hash is computed when no password is set to
  avoid timing differences.

### Sessions
- 256-bit random session ID; only its SHA-256 is stored server-side.
- Cookie: `__Host-wcmon_session`, `Secure`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`, no `Domain`. (When serving plain HTTP on a trusted LAN — strongly
  discouraged — fall back to a non-`__Host-` name with a UI warning banner.)
- Idle timeout 12 h, absolute lifetime 7 d ("remember me" optional, 30 d).
- Session ID rotated on login and password change; password change revokes all
  other sessions; "Sign out everywhere" button.

### Brute-force protection
- Per-IP and global login throttling (e.g. 5 attempts / 15 min / IP with
  exponential delay; global 50 / 15 min), uniform error messages, audit-logged.
- Respect `X-Forwarded-For` **only** from configured `WCMON_TRUSTED_PROXIES`.

### Recovery
- `docker exec <ctr> /wcmon reset-password` (prompts, or reads from stdin) —
  TrueNAS: "Shell" button on the app container.

---

## 10. Security baseline (2026)

Reference standards: **OWASP ASVS 5.0** (target Level 2), **OWASP Top 10:2025**,
**NIST SP 800-63B-4** (passwords), **CIS Docker Benchmark**, **OpenSSF
Scorecard**, **SLSA v1.x Build L3** (via GitHub-hosted reusable workflows).

### Transport
- Built-in HTTPS on by default, **TLS 1.3 only** (TLS 1.2 opt-in), modern
  curve preferences incl. the hybrid post-quantum `X25519MLKEM768` that Go
  enables by default.
- Certificate: user-supplied (`WCMON_TLS_CERT_FILE` / `_KEY_FILE`, e.g. from
  TrueNAS cert store mount) **or** auto-generated self-signed ECDSA P-256 cert
  persisted in `/data/tls/` with SANs from `WCMON_PUBLIC_HOSTNAMES`.
- `WCMON_TLS=off` for deployments behind a TLS-terminating reverse proxy
  (Traefik, Caddy, Nginx Proxy Manager, TrueNAS-hosted proxy); then require
  `WCMON_TRUSTED_PROXIES` and `X-Forwarded-Proto=https` to set Secure cookies.
- HSTS (`max-age=31536000`) only when serving TLS directly with a non-self-signed
  cert or when explicitly enabled.

### HTTP response headers (all responses)
```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self';
  worker-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none';
  require-trusted-types-for 'script'; trusted-types wcmon; upgrade-insecure-requests
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=(), interest-cohort=()
Cache-Control: no-store            (authenticated pages & API)
X-Frame-Options: DENY              (legacy belt-and-braces)
```
Static assets are content-hashed and served `immutable` with SRI hashes.

### Application
- **CSRF:** Go `http.CrossOriginProtection` (Sec-Fetch-Site / Origin checks) +
  `SameSite=Strict` + per-form synchronizer token for state-changing forms
  (defence in depth). All state changes are POST/PUT/DELETE.
- Strict JSON decoding (`DisallowUnknownFields` for client input), request body
  limits, input validation on every field, output encoding via `html/template`.
- **SSRF:** device URLs restricted to private ranges by default; notification
  webhooks restricted to `https://` unless explicitly allowed; no redirects to
  internal ranges; DNS-rebinding-safe dialer (validate resolved IP at connect).
- Audit log of logins, failed logins, settings/rule/channel changes.
- Errors: generic messages to client, details only in logs; logs never contain
  secrets, session IDs, or passwords (slog `LogValuer` redaction for secret types).
- Time-boxed server timeouts (`ReadHeaderTimeout`, `ReadTimeout`,
  `WriteTimeout` except SSE, `IdleTimeout`), max header bytes.

### Supply chain & CI
- Go modules pinned via `go.sum`; `GOFLAGS=-mod=readonly`; `GOTOOLCHAIN` pinned.
- **govulncheck**, **gosec**, **staticcheck**/**golangci-lint**, **CodeQL**,
  **OpenSSF Scorecard**, **Trivy** or **Grype** image scan (fail on
  High/Critical with fix available), **gitleaks** secret scan.
- **Renovate** (or Dependabot) for Go modules, GitHub Actions (pinned by SHA),
  base image digests, vendored JS.
- Reproducible build: `-trimpath`, `-buildvcs`, `CGO_ENABLED=0`,
  `SOURCE_DATE_EPOCH`.
- **SBOM** (SPDX + CycloneDX via Syft / BuildKit attestations), **SLSA
  provenance**, **cosign keyless signing** of images in GHCR; document
  verification (`cosign verify ...`).
- `SECURITY.md` with private vulnerability reporting enabled on GitHub.
- Branch protection, required reviews/checks, signed commits recommended.

### Threat model (summary — expand in `docs/THREAT_MODEL.md` in Phase 1)
| Threat | Mitigation |
|---|---|
| LAN attacker brute-forces password | Argon2id, throttling, lockout, audit |
| Attacker on LAN spoofs Wall Connector responses | Strict parsing, range checks, alerts can't execute anything |
| XSS via device-provided strings (SSID, alerts) | `html/template` escaping, CSP, Trusted Types |
| CSRF from other LAN apps on same host | Fetch-metadata checks, SameSite=Strict, tokens |
| Secrets leakage from backups/volumes | Encrypted channel creds, `0600` files, key separate from DB option |
| Malicious dependency/base image | Minimal deps, pinning, scanning, signed images, SBOM |
| Container breakout | Non-root, read-only rootfs, no caps, `no-new-privileges`, seccomp default |

---

## 11. Container and deployment

### Image
- Multi-stage `Dockerfile`: `golang:<ver>-alpine@sha256:…` builder →
  `gcr.io/distroless/static-debian12:nonroot@sha256:…` runtime.
- Binary at `/wcmon`, entrypoint `["/wcmon", "serve"]`.
- **Runs as UID/GID 568:568 by default** (TrueNAS `apps` user) — overridable
  with `user:`; image must work with any arbitrary UID that owns `/data`.
- Volumes: `/data` (DB, secret key, TLS) — the only writable path. `/tmp` via
  tmpfs if needed.
- Port: `8443` (HTTPS) or `8080` (HTTP when `WCMON_TLS=off`).
- `HEALTHCHECK` uses `/wcmon healthcheck` (no curl in image) hitting
  `/healthz` (unauthenticated, returns only `ok`) — `/readyz` checks DB.
- OCI labels: `org.opencontainers.image.source/licenses=AGPL-3.0-only/version/revision`.
- Platforms: `linux/amd64`, `linux/arm64`. Published to
  `ghcr.io/bhager42/teslachargingmonitor` with tags `X.Y.Z`, `X.Y`, `latest`,
  plus digest pinning documented.
- Target image size < 25 MB, idle RSS < 40 MB, idle CPU ≈ 0.

### Configuration (environment)
| Variable | Default | Notes |
|---|---|---|
| `WCMON_LISTEN` | `:8443` | |
| `WCMON_TLS` | `auto` | `auto` (self-signed) / `file` / `off` |
| `WCMON_TLS_CERT_FILE`, `WCMON_TLS_KEY_FILE` | — | |
| `WCMON_PUBLIC_HOSTNAMES` | — | SANs for self-signed cert, allowed `Host` values |
| `WCMON_PASSWORD_HASH_FILE` / `WCMON_PASSWORD_FILE` | — | §9 |
| `WCMON_SECRET_KEY_FILE` | `/data/secret.key` | |
| `WCMON_TRUSTED_PROXIES` | — | CIDRs |
| `WCMON_LOG_LEVEL` | `info` | |
| `TZ` | `UTC` | Display & quiet hours |

Every secret supports a `*_FILE` variant (Docker secrets / TrueNAS mounted files).

### Generic Docker Compose (`deploy/compose.yaml`)
```yaml
services:
  wcmon:
    image: ghcr.io/bhager42/teslachargingmonitor:1   # pin digest in production
    container_name: wcmon
    restart: unless-stopped
    user: "568:568"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m,mode=1777"]
    ports: ["8443:8443"]
    environment:
      TZ: America/Chicago
      WCMON_PUBLIC_HOSTNAMES: wcmon.lan,truenas.lan
      WCMON_PASSWORD_FILE: /run/secrets/wcmon_password
    secrets: [wcmon_password]
    volumes:
      - ./data:/data
    healthcheck:
      test: ["CMD", "/wcmon", "healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    deploy:
      resources:
        limits: { cpus: "0.50", memory: 128M }
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "3" }
secrets:
  wcmon_password:
    file: ./wcmon_password.txt
```

### TrueNAS SCALE 25.10+ (`deploy/truenas/`)
TrueNAS SCALE 24.10+ runs apps on Docker Compose; 25.10 supports
**Apps → Discover → ⋮ → Install via YAML** for custom apps.

Deliverables:
1. `deploy/truenas/custom-app.yaml` — Compose YAML ready to paste, using a host
   path such as `/mnt/<pool>/apps/wcmon/data` mounted at `/data`, `user: 568:568`.
2. `docs/INSTALL_TRUENAS.md` step-by-step:
   - Create dataset `<pool>/apps/wcmon` (preset *Apps*), owner `apps` (568).
   - Option A: Install via YAML (paste file, edit pool path & TZ).
   - Option B: Apps → Custom App form (image, port, env, host-path storage,
     run as 568, read-only rootfs toggle if available).
   - Using a TrueNAS-managed certificate (export to the dataset) or putting the
     app behind a reverse proxy app.
   - Retrieving the setup token from **Apps → wcmon → Logs**; password reset via
     **Shell**.
   - Updating (image tag bump), backups (snapshot the dataset; app also offers
     DB backup download), restore.
3. *(Stretch)* Submit an app to the **TrueNAS community apps catalog**
   (`truenas/apps` repo) with `app.yaml`, questions, and ix-volume defaults.

### Other targets (documented, smoke-tested in CI where feasible)
- `docker run` one-liner, Podman (rootless), Portainer stack, Unraid template
  (stretch), Kubernetes manifest/Helm (stretch).

---

## 12. Licensing (AGPL-3.0)

- `LICENSE` containing the full **GNU AGPL v3** text (verbatim from gnu.org).
- SPDX header in every source file:
  `// SPDX-License-Identifier: AGPL-3.0-only` (or `-or-later`, see §15) and a
  copyright line `// Copyright (C) 2026 <owner name>`.
- **AGPL §13 compliance:** because users interact over a network, the web UI
  footer and the About page show "Source code" linking to the exact
  version/commit (`/about` shows version, commit SHA, build date, and a link to
  `https://github.com/bhager42/teslachargingmonitor/tree/<sha>`). Forks must be
  able to change the source URL via build flag `-ldflags -X …SourceURL=`.
- `NOTICE`/`THIRD_PARTY_LICENSES` generated in CI with `go-licenses`; CI fails
  on licences incompatible with AGPL (e.g. proprietary, SSPL, some
  "non-commercial" licences). Vendored JS licences included.
- `CONTRIBUTING.md` with DCO sign-off (`Signed-off-by:`) — no CLA unless owner
  wants dual licensing (§15).
- Trademark note in README: "Tesla" and "Wall Connector" are trademarks of
  Tesla, Inc.; this project is not affiliated with or endorsed by Tesla. Do not
  use Tesla logos in the UI/icon.

---

## 13. Testing strategy

| Layer | Tooling | What |
|---|---|---|
| Unit | `go test`, table-driven, `-race` | decoder tolerance, rule state machine (debounce/hysteresis/cooldown), password hashing/verification, session logic, retention math, SSRF guards |
| Fuzz | Go native fuzzing | Wall Connector JSON decoder, template data, URL validator |
| Simulator | `cmd/wcsim` — fake Wall Connector serving `/api/1/*` with scenarios (idle, charging, overheating, offline, reboot, firmware change, malformed JSON, slow responses) | Used by integration + e2e + local dev |
| Integration | `go test` with real SQLite + simulator; `httptest` | full poll → store → alert → notify (mock ntfy/SMTP/webhook servers, e.g. MailHog-like in-process) |
| E2E | **Playwright** (Chromium, Firefox, WebKit) against the built container + simulator via Compose | login, dashboard live updates, rule editing, theme toggle (no flash), CSP violations = test failure |
| Accessibility | `@axe-core/playwright` in both themes | zero serious/critical violations |
| Security | ZAP baseline scan in CI against running container; header assertions; govulncheck/gosec/Trivy | |
| Container | `container-structure-test` or Go test | non-root, no shell, read-only works, healthcheck passes, image size budget |

Coverage target ≥ 80 % for `internal/alerts`, `internal/auth`,
`internal/wallconnector`; ≥ 70 % overall.

Golden fixtures: `testdata/fixtures/uwc/<firmware>/{vitals,lifetime,wifi_status,version}.json`
(plus `gen3/` if a contributor provides them)
captured from real hardware in Phase 0 (serials/MACs/SSIDs redacted).

---

## 14. Phased delivery plan

Each phase = one or more small PRs, CI green, docs updated. Do not start a phase
until the previous phase's acceptance criteria pass.

### Phase 0 — Discovery & repo bootstrap
- Capture real payloads from the owner's device(s) (script
  `scripts/capture.sh <ip>` that curls the four endpoints, redacts serial/MAC/SSID,
  writes fixtures). **Needs owner input.**
- Repo scaffolding: `LICENSE` (AGPL-3.0), `README.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.editorconfig`, `.gitignore`,
  `go.mod`, `Makefile`/`Taskfile`, `CLAUDE.md`, `docs/THREAT_MODEL.md` (draft),
  ADRs in `docs/adr/` (0001 language, 0002 SQLite, 0003 no-build frontend).
- CI skeleton: lint, test, govulncheck, CodeQL, Scorecard, licence check.

**Accept:** UWC fixtures (idle + charging) committed and the field list in §2
updated to match reality; CI green
on an empty `main` package; licence headers enforced by a CI check.

### Phase 1 — Wall Connector client + simulator
- `internal/wallconnector`: typed models, tolerant decoder, code tables,
  client with timeouts/size limits/no redirects.
- `cmd/wcsim` with scenario files.
- Fuzz tests on the decoder.

**Accept:** client parses all fixtures; fuzzers run 60 s clean in CI;
simulator scenarios selectable via flag/env.

### Phase 2 — Storage + poller
- SQLite store, migrations, retention + rollup jobs, backup (`VACUUM INTO`).
- Poller with jitter/backoff/active-cadence; reboot & firmware-change detection.
- `wcmon serve` runs headless and logs readings.

**Accept:** 24 h soak against simulator with no goroutine/memory growth; DB
size within estimate (document MB/day/device); retention verified by test.

### Phase 3 — Alert engine
- Rule types from §6, state machine, alert events, preview against history.

**Accept:** table tests for every rule incl. debounce, hysteresis, cooldown,
repeat, resolve, snooze, quiet hours; simulator "overheat" scenario fires and
resolves exactly once.

### Phase 4 — Notifications
- Delivery queue, retries, channel implementations (owner's chosen set first),
  templates, test-send, encrypted channel secrets.

**Accept:** integration tests with mock receivers; secrets never appear in
logs, API responses, or DB plaintext (test asserts).

### Phase 5 — Web server, auth, security middleware
- HTTPS (auto/file/off), security headers, CSRF, sessions, login throttling,
  setup-token flow, `reset-password`/`hash-password` CLI, audit log.

**Accept:** ZAP baseline clean (no Medium+); header test suite; ASVS L2
checklist for V2/V3/V4/V13/V14-equivalent sections (ASVS 5.0 numbering)
documented in `docs/security/asvs.md` with pass/N-A per item.

### Phase 6 — Web UI
- Layout, design tokens with `light-dark()`, theme toggle without flash,
  dashboard (SSE), device detail charts, alerts, notifications, settings,
  diagnostics, about/source page, PWA manifest.

**Accept:** Playwright suite green on 3 engines; axe clean in both themes;
Lighthouse ≥ 95; works at 320 px; zero CSP violations; JS budget met.

### Phase 7 — Container, release, TrueNAS
- Hardened Dockerfile, multi-arch build, SBOM, provenance, cosign signing,
  GHCR publish on tag, Trivy gate, image structure tests.
- `deploy/compose.yaml`, `deploy/truenas/custom-app.yaml`,
  `docs/INSTALL_TRUENAS.md`, `docs/INSTALL_DOCKER.md`, upgrade/backup docs.

**Accept:** fresh install on TrueNAS SCALE 25.10 via "Install via YAML"
following the doc verbatim succeeds (owner-verified); `docker compose up` on
plain Docker succeeds; `cosign verify` documented and works; image < 25 MB.

### Phase 8 — Hardening & polish (v1.0.0)
- Threat model finalised, ASVS checklist complete, fuzz corpus extended,
  digest/report emails, optional Prometheus `/metrics`, dead-man's-switch ping,
  i18n scaffolding (strings externalised), docs site (optional).

**Accept:** v1.0.0 tagged, release notes, signed images, CHANGELOG, all
open questions in §15 resolved or deferred explicitly.

### Later / stretch
TrueNAS community catalog submission; Home Assistant MQTT discovery; per-session
cost tracking with utility rates; multi-connector power-sharing view; passkey
(WebAuthn) as an *optional* second factor; Helm chart.

### Proposed repository layout
```
cmd/wcmon/            main entrypoint + CLI subcommands
cmd/wcsim/            Wall Connector simulator
internal/{config,wallconnector,poller,store,alerts,notify,auth,web,cli}/
internal/store/migrations/*.sql
web/templates/        html/template files
web/static/{css,js,img,vendor}/   embedded via go:embed, content-hashed
testdata/fixtures/
e2e/                  Playwright tests (Node only for tests, not runtime)
deploy/compose.yaml
deploy/truenas/custom-app.yaml
docs/{DEVELOPMENT_PLAN.md,INSTALL_TRUENAS.md,INSTALL_DOCKER.md,THREAT_MODEL.md,adr/,security/}
.github/workflows/{ci.yml,release.yml,codeql.yml,scorecard.yml}
Dockerfile  LICENSE  README.md  SECURITY.md  CONTRIBUTING.md  CLAUDE.md
```

---

## 15. Open questions / inputs needed from the owner

### 15.0 Resolved decisions
| # | Decision | Date | Effect on plan |
|---|---|---|---|
| D1 | Owner has **only a Universal Wall Connector** (UWC). | 2026-11-02 | UWC is the primary, tested target; Gen 3 is best-effort. Fixtures and simulator scenarios are UWC-first (§2, §13, Phase 0/1). |
| D2 | The Wall Connector **IP address is configured in the Web GUI** (not env vars/config files). | 2026-11-02 | First-run onboarding + Settings device form with Test connection (§8); `WCMON_DEVICES` env seed removed (§11); poller hot-reloads on address change (§6). |
| D3 | `/version` and `/lifetime` captured from the UWC (fw 26.26.10), serial redacted. | 2026-11-02 | §2 verification table; extra `/version` fields stored; new `grid_profile_changed` rule; counter rules baseline on first sighting. |
| D4 | Idle `/vitals` captured from the UWC. | 2026-11-02 | UWC uses `relay_k1_v`/`relay_k2_v` instead of `relay_coil_v`; relay rule reworked; not-ready rule gated on vehicle connected; grid rule uses `grid_v`; boot vs lifetime uptime clarified. |

### 15.1 Still open

**Hardware & network**
1. How many UWCs (just one?) and is it in a **power-sharing** group? *(Model
   answered: UWC — D1.)*
2. *(Answered — D2: entered in the Web GUI.)* Please still reserve the UWC's IP
   in your router's DHCP so it doesn't change.
3. Remaining sample JSON from your UWC: `/version`, `/lifetime` and idle
   `/vitals` are captured (D3, D4); still needed are **`/api/1/vitals` while a
   car is actively charging** (and ideally plugged-in-but-not-charging) and
   **`/api/1/wifi_status`**. For reference, the full list: run
   `curl http://<ip>/api/1/vitals`, `/lifetime`, `/wifi_status`, `/version`
   (ideally once idle and once while charging) and share them — redact serial,
   MAC and SSID if you like.
4. Electrical setup: country/region, nominal voltage (240 V split-phase, 208 V,
   230 V single-phase, 400 V three-phase), frequency, **breaker size and the
   max current configured during commissioning**.
5. Is TrueNAS on the same VLAN/subnet as the chargers, or will traffic cross a
   firewall?

**Alerting**
6. Which notification channels do you want in v1 (ntfy, email/SMTP, Pushover,
   Gotify, Discord, Slack, Telegram, Home Assistant, generic webhook)?
7. Confirm or adjust the default thresholds in §6 (especially temperatures and
   voltage band). Any rules to add/remove?
8. Quiet hours? Daily/weekly summary digest wanted?
9. Default poll interval OK at 30 s (15 s while charging)?
10. Do you want an external dead-man's-switch ping (healthchecks.io / Uptime Kuma)?

**Access & security**
11. How will you reach the UI: LAN only, via VPN (Tailscale/WireGuard), or via a
    reverse proxy? Which proxy, if any?
12. TLS: use a TrueNAS-managed certificate, let the app self-sign, or terminate
    TLS at a reverse proxy?
13. Password provisioning preference: first-run setup token (default), Docker
    secret file, or pre-hashed value? Should a plaintext env var be refused
    entirely?
14. Session lifetime preferences (default 12 h idle / 7 d absolute)?

**Data**
15. Retention preferences (defaults in §5)? Which dataset/pool path on TrueNAS?
16. Prometheus/Grafana or InfluxDB export wanted? Home Assistant/MQTT integration?
17. Units: °C or °F; time zone.

**Project / legal**
18. Project and image name (default `wcmon` / `ghcr.io/bhager42/teslachargingmonitor`).
19. **AGPL-3.0-only** or **AGPL-3.0-or-later**? Copyright holder name for headers.
20. Will the repo be public? (Affects GHCR visibility, Scorecard, private
    vulnerability reporting, and the AGPL source link.)
21. Contributions: DCO sign-off OK, or do you want a CLA (only needed if you may
    ever relicense)?
22. Language preference: is Go acceptable, or do you prefer Python or
    TypeScript for maintainability?
23. Should we target submission to the official TrueNAS community app catalog?

---

## 16. Working rules for Claude Code

- Read this plan and `CLAUDE.md` at the start of every session; keep both
  updated when decisions change (record decisions as ADRs in `docs/adr/`).
- Work **one phase at a time**, in small PRs with clear titles; each PR updates
  tests and docs, and passes `make lint test` locally before pushing.
- Never weaken a security control (header, CSP, cookie flag, rate limit,
  container hardening) to make a test pass; fix the code instead.
- Never commit real serial numbers, MACs, SSIDs, IPs from the owner, passwords,
  or keys. Fixtures must be redacted.
- Prefer the standard library; any new dependency needs a one-line
  justification in the PR and must pass licence + vulnerability checks.
- Pin everything (Go toolchain, actions by SHA, base images by digest, vendored
  JS by checksum).
- Every source file starts with the SPDX AGPL header.
- When the device API returns something unexpected, **don't guess** — add a
  fixture, make the decoder tolerant, surface it in Diagnostics.
