# Tesla Charger Monitoring — Development Plan

> **Audience:** Claude Code (and human contributors).
> **Status:** Draft v2 — 2026-11-02. Owner decisions so far are recorded in [§15.0](#150-resolved-decisions); remaining open questions follow it.
> **License:** AGPL-3.0-or-later (see §12).

A small, self-hosted, containerized web app that polls the local HTTP API of a
**Tesla Universal Wall Connector** (the owner's only hardware — the primary and
tested target) on a schedule, stores the readings, shows them in a dark-mode-first web
dashboard, and sends alerts when metrics look concerning. The Gen 3 Wall
Connector uses the same `/api/1/*` API family, so it should work too, but it is
**best-effort/untested** unless a contributor supplies fixtures. The data model
still supports multiple devices so a second unit can be added later. The primary deployment
target is **TrueNAS SCALE 25.10 ("Goldeye") or later**, but it must run on any
OCI/Docker host (Docker Engine, Podman, Compose, Portainer, Unraid, k8s).

Project name: **Tesla Charger Monitoring** (shown in the UI, README, OCI
labels). Short identifier used for the binary, env-var prefix, cookie names and
container name: **`tcmon`**. Repo/image: `bhager42/teslachargingmonitor` /
`ghcr.io/bhager42/teslachargingmonitor`. The repository is **public**.

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
| `/api/1/wifi_status` | ✅ verified | Field set identical to Gen 3. `wifi_ssid` is base64 (decode, then HTML-escape — it is attacker-controllable text). `wifi_infra_ip` reports the device's own IP: show it next to the configured address and warn if they differ. `wifi_mac` and SSID are treated as sensitive (masked in UI by default, never logged). |

Note: the device stores lifetime counters (e.g. `alert_count` was already 3 at
first capture). Counter-based rules must take a **baseline on first sighting**
and only fire on increases afterwards — never on initial import.

| Endpoint | Purpose | Suggested poll cadence |
|---|---|---|
| `GET /api/1/vitals` | Live electrical/thermal state, alerts, EVSE state | every poll |
| `GET /api/1/lifetime` | Lifetime counters (energy, contactor cycles, thermal foldbacks, alert count) | every poll |
| `GET /api/1/wifi_status` | RSSI, SNR, signal strength, connectivity | every poll |
| `GET /api/1/version` | Firmware version, part/serial number, IEEE 1547 CRCs | every poll |

A "poll" fetches all four endpoints sequentially. Default poll interval is
**60 minutes** (owner decision D6, configurable in the GUI — see §6).

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
- **wifi_status (verified on UWC):** `wifi_ssid` (base64), `wifi_signal_strength`, `wifi_rssi`,
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
                ┌──────────────────────────── tcmon container ────────────────────────────┐
                │                                                                          │
 Wall           │  ┌───────────┐   readings   ┌──────────────┐  events  ┌───────────────┐ │
 Connector(s) ◄─┼──│  Poller   │─────────────►│ Alert engine │─────────►│ Notifier queue│─┼─► ntfy / email /
 HTTP :80       │  │ (per dev) │              │ (rules, state│          │ (retry, dedupe)│ │   webhook / …
                │  └─────┬─────┘              │  machine)    │          └───────────────┘ │
                │        │                    └──────┬───────┘                            │
                │        ▼                           ▼                                    │
                │  ┌──────────────────────── SQLite (WAL) /data/tcmon.db ───────────────┐ │
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
| Metrics (optional, deferred — D21) | Prometheus text format at `/metrics`, bearer-token protected, off by default | For Grafana users; not in v1.0. |
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

**Retention is adjustable in the Web GUI (owner decision D15); default 2 years
for readings.** Settings → Data retention offers, per data class, presets
(30 d, 90 d, 6 months, 1 y, **2 y**, 5 y, Keep forever) or a custom number of
days; it shows the current DB size and an estimated size for the chosen
setting. Shortening retention shows a confirmation ("this permanently deletes
data older than …") and suggests downloading a backup first; pruning runs
nightly and on demand. At the default hourly cadence one device produces
~8,800 rows/year per table, so 2 years of raw readings is small and no
rollups are needed for that data.

**Measured storage (Phase 2 soak, 3,000 polls):** ≈ 1.9 KB per poll
including raw payloads, i.e. **≈ 16 MiB/year** at hourly polling and
**≈ 31 MiB/year** with ~2 h/day plugged in at the 5-min cadence — an upper
bound, since raw payloads (≈ 70 % of that) are pruned after 90 days.
Implementation: only **1-hour rollups** (`rollups_1h`) are kept; 5-minute
rollups were dropped because 5 min is already the finest sampling cadence.
Fields the decoder flags invalid are stored as SQL NULL and listed in each
row's `invalid_json`, so rollups and alerts never consume them. Rollups (5-min → 1-h) are generated only for data
sampled more often than hourly (e.g. if the owner shortens the interval or
enables faster polling while charging, which is on by default) and are kept
indefinitely. Raw payloads
90 d; alert events 2 y; audit log 1 y. Nightly
`VACUUM`/`PRAGMA optimize`; online backup via `VACUUM INTO` exposed as a
downloadable backup in Settings.

**Secrets at rest:** notification channel credentials are encrypted with
AES-256-GCM (or XChaCha20-Poly1305) using a key from `TCMON_SECRET_KEY_FILE`
(auto-generated into `/data/secret.key` with `0600` on first start if not
provided). Never return decrypted secrets to the browser — show "•••• set".

---

## 6. Polling and the alert engine

### Poller
- One goroutine per enabled device; schedule at `poll_interval`
  — **default 60 min**, configurable in the GUI (Settings → device) from
  **1 min to 24 h** with presets (5, 15, 30, 60 min, 6 h, custom). Small jitter
  (±2 % , max 60 s). Changing it takes effect immediately.
- An immediate poll on startup and after a device is added/edited, plus a
  **"Poll now"** button on the dashboard and device page (rate-limited to once
  per 10 s).
- **"Poll more often while a car is plugged in"** — **on by default** (owner
  decision D10): every **5 min** while `vehicle_connected || contactor_closed`,
  back to the normal interval once unplugged; both intervals and the toggle are
  editable in the GUI. This is what makes
  the instantaneous rules (temperature, current, voltage) useful during a
  session; the GUI explains the trade-off next to the setting.
- Per-request timeout 5 s; response body limit 64 KiB; reject non-JSON.
- **Failure handling:** a failed poll is retried after 30 s, 2 min and 5 min
  before it counts as failed (so one Wi-Fi blip doesn't alert). A failed poll
  emits `device_unreachable` to the alert engine.
- The UI always shows **"last updated N min ago"** and marks data stale after
  1.5 × interval.
- The device address comes **only from the Web GUI** (see §8 "Device
  management"); changes take effect immediately — the poller for that device is
  restarted without restarting the container.
- Device address validation: IPv4, IPv6 or hostname (optional `:port`),
  normalised to `http://<host>[:port]`; must resolve to a **private/LAN
  address** by default (SSRF guard; an "allow non-private address" checkbox
  exists for odd networks). No redirects followed. Resolved IP is re-checked at
  connect time (DNS-rebinding safe).
- Detect reboot (`vitals.uptime_s` < time since previous successful poll, which
  works even with hourly polling) and firmware change (version differs).

### What a 60-minute default means for alerting
Hourly polling sees **snapshots**, not continuous data. The plan handles this:

- **Cumulative counters catch everything between polls** — `thermal_foldbacks`,
  `alert_count`, `charge_starts`, `energy_wh`, `contactor_cycles*`,
  `charging_time_s` (from `/lifetime`). Rules built on their deltas are reliable
  at any interval, so they are the backbone of the default rule set.
- **Instantaneous rules** (temperatures, current, voltage, frequency,
  `current_alerts`) only see the moment of the poll. They stay enabled but the
  rule UI notes "checked once per poll". Because faster polling while plugged
  in is on by default, they are sampled every 5 min during charging — when
  they matter most.
- Rule durations ("for 60 s") are evaluated as "for at least this long **or**
  one sample, whichever is longer", so at hourly cadence a single breaching
  sample fires (except where noted below).
- Charging sessions are derived from counter deltas (`charge_starts`,
  `energy_wh`, `charging_time_s`) per interval, with start/end times
  approximate to the poll interval.

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
| `device_unreachable` | A poll failed after its retries (§6 Poller) | warning → critical after 3 consecutive failed polls |
| `identity_mismatch` | serial number at the configured address changed | warning |
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
| `overcurrent` | `vehicle_current_a` (or any phase current) > configured max current × 1.05 for 30 s — owner's setup: **> 50.4 A** (48 A × 1.05) | critical |
| `current_near_limit` | `vehicle_current_a` ≥ max current but ≤ 1.05 × max for 2 consecutive polls (owner: 48–50.4 A) — informational, confirms full-rate charging is at the ceiling | info (disabled by default) |
| `charging_stalled` | contactor closed & vehicle connected but current < 1 A on 2 consecutive polls | info |
| `relay_voltage_abnormal` | while `contactor_closed`: `relay_k1_v`/`relay_k2_v` (UWC) or `relay_coil_v` (Gen 3) outside expected band, or K1 and K2 disagree significantly; while open: either relay > ~1 V (possible stuck relay). Band TBD from charging capture. | warning |
| `wifi_weak` | `wifi_rssi` < −75 dBm on 2 consecutive polls | info |
| `wifi_no_internet` | `internet == false` on 2 consecutive polls (affects firmware updates) | info |
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
- Weekly optional **digest** (energy used, sessions, cost, max temps, alerts) — D19.
- Optional **dead-man's switch**: ping an external URL (e.g. healthchecks.io /
  Uptime Kuma push) after every successful poll cycle so the owner learns if
  `tcmon` itself stops — D20.

---

## 7. Notifications

**Email is the primary channel (owner decision D7)** and ships first. All
channels implement one small `Channel` interface so more can be added later
without touching the alert engine.

### Email (SMTP) — v1, required
- Settings: SMTP host, port, security mode (**STARTTLS** on 587 or **implicit
  TLS** on 465; plaintext SMTP refused), TLS ≥ 1.2 with certificate
  verification (custom CA mountable), username, password / app password
  (encrypted at rest, §5), From address + display name, **one or more To
  addresses**, subject prefix (default `[Tesla Charger Monitoring]`).
- **Gmail is the owner's provider (D11) and the default preset**:
  `smtp.gmail.com`, port **587 STARTTLS** (465 implicit TLS selectable),
  username = full Gmail address, password = a **Google app password**
  (requires 2-Step Verification; the regular account password will not work).
  The settings page links to Google's app-password page and explains this.
  The From address must be the Gmail address or a verified "Send mail as"
  alias, so default From = username. Gmail's sending limits are far above this
  app's volume; batching (below) keeps it that way. Errors such as
  `534 5.7.9 Application-specific password required` are translated into
  plain-English hints in the test-email result.
- Other presets: Google Workspace, iCloud (also app password), Outlook.com /
  Microsoft 365, Fastmail, Proton Mail Bridge, self-hosted/relay, custom.
  OAuth2 (XOAUTH2) for Gmail is a stretch goal; the app password is the v1
  method.
- Messages: `multipart/alternative` plain-text + simple HTML (inline CSS only,
  no remote images, no tracking), readable in dark-mode mail clients; correct
  `Date`, `Message-ID`, `Auto-Submitted: auto-generated` headers; link back to
  the alert in the UI if a public URL is configured.
- **Batching:** all alerts raised by the same poll go out in **one email**;
  resolved notices batched the same way. Optional daily/weekly digest email.
- Header-injection safe: addresses parsed with `net/mail`, CR/LF stripped from
  subject/name fields, templates fed only typed data.
- "Send test email" button with a clear error report (DNS, TLS, auth, rejected
  recipient).
- Library: `github.com/wneessen/go-mail` (MIT, actively maintained) or stdlib
  `net/smtp` — decide in Phase 4 after dependency review.

### Additional channels — later phases, in suggested order
- **ntfy** (self-hosted or ntfy.sh) — good push option for TrueNAS users.
- **Generic webhook** (JSON POST, optional HMAC-SHA256 signature header).
- **Home Assistant** (webhook trigger).
- **Gotify**, **Pushover**, **Discord**, **Slack**, **Telegram**, **Matrix**.

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
  breaker size and max charging current (used by the voltage and overcurrent
  rules). The form asks for the **breaker size** and pre-fills max current as
  **80 % of it** (NEC continuous-load rule), editable to match what was set at
  commissioning. Defaults: 240 V / 60 Hz split-phase. Owner's values (D17):
  60 A breaker → **48 A max**, i.e. ≈ 11.5 kW at 240 V; the dashboard shows
  live current as a fraction of 48 A.
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
  cache API responses containing data after logout). Optional: with the
  default self-signed cert, browsers won't register the service worker, so
  nothing may depend on it.

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
1. `TCMON_PASSWORD_HASH` / `TCMON_PASSWORD_HASH_FILE` — pre-computed Argon2id
   PHC string (produced by `tcmon hash-password`).
2. `TCMON_PASSWORD_FILE` — plaintext in a Docker/TrueNAS secret file; hashed on
   start, plaintext never stored or logged.
3. Neither set → **setup mode**: a random one-time setup token is printed to the
   container log; the UI requires that token to set the initial password. Setup
   mode expires after 30 min (restart to regenerate).

Avoid plaintext `TCMON_PASSWORD` env vars (visible in `docker inspect`); accept
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
- Cookie: `__Host-tcmon_session`, `Secure`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`, no `Domain`. (When serving plain HTTP on a trusted LAN — strongly
  discouraged — fall back to a non-`__Host-` name with a UI warning banner.)
- Idle timeout 12 h, absolute lifetime 7 d ("remember me" optional, 30 d).
- Session ID rotated on login and password change; password change revokes all
  other sessions; "Sign out everywhere" button.

### Brute-force protection
- Per-IP and global login throttling (e.g. 5 attempts / 15 min / IP with
  exponential delay; global 50 / 15 min), uniform error messages, audit-logged.
- Respect `X-Forwarded-For` **only** from configured `TCMON_TRUSTED_PROXIES`.

### Recovery
- `docker exec <ctr> /tcmon reset-password` (prompts, or reads from stdin) —
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
- **Default for this owner (D12): LAN only, no CA-validated certificate →
  `TCMON_TLS=auto`.** The app generates a **self-signed ECDSA P-256
  certificate** on first start, persisted in `/data/tls/` (0600), valid 825
  days, auto-regenerated 30 days before expiry, SANs from
  `TCMON_PUBLIC_HOSTNAMES` (e.g. the TrueNAS IP/hostname) plus `localhost`.
  - The browser shows a one-time "not secure / not private" warning that the
    owner accepts; traffic (including the password) is still encrypted.
  - The SHA-256 fingerprint is printed in the container log and on the About
    page so the owner can confirm it matches what the browser shows.
  - Settings offers **"Download certificate"** so it can optionally be trusted
    on the owner's devices to remove the warning.
  - Known limitation: browsers refuse **service workers** on pages with
    untrusted certificates, so PWA install/offline shell silently degrade
    (the app must work fully without them).
- Alternatives: user-supplied cert (`TCMON_TLS=file`, `TCMON_TLS_CERT_FILE` /
  `_KEY_FILE`, e.g. exported from the TrueNAS cert store) or `TCMON_TLS=off`.
- **Plain HTTP (`TCMON_TLS=off`) is not the default** even on the LAN: anyone
  on the network could capture the password and session cookie. It is allowed
  only behind a TLS-terminating proxy or with an explicit
  `TCMON_ALLOW_INSECURE_HTTP=true`, which shows a permanent warning banner and
  drops the `__Host-` cookie prefix.
- **LAN-only access control (D12):** by default the server only accepts
  client connections from loopback, RFC 1918 (10/8, 172.16/12, 192.168/16),
  link-local and IPv6 ULA (fc00::/7) addresses; anything else gets 403 before
  authentication. Configurable via `TCMON_ALLOWED_CLIENT_CIDRS` (e.g. narrow
  it to `192.168.1.0/24`). This is defence in depth — the README still tells
  the owner not to port-forward the app.
- With `TCMON_TLS=off` behind a TLS-terminating reverse proxy
  (Traefik, Caddy, Nginx Proxy Manager, TrueNAS-hosted proxy), require
  `TCMON_TRUSTED_PROXIES` and `X-Forwarded-Proto=https` to set Secure cookies.
- HSTS is **not** sent with the self-signed default (it would make the
  certificate warning un-bypassable in some browsers); only with a
  CA-validated cert or when explicitly enabled.
- Outbound TLS is unaffected by D12: the Gmail SMTP connection **always
  validates** Google's certificate. (The Wall Connector itself only speaks
  plain HTTP on the LAN; nothing to validate there.)

### HTTP response headers (all responses)
```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self';
  worker-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none';
  require-trusted-types-for 'script'; trusted-types tcmon; upgrade-insecure-requests
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
- The repo is **public**: enable GitHub secret scanning + push protection,
  Dependabot alerts, and OpenSSF Scorecard publishing; GHCR package visibility
  public; never commit owner identifiers (serial, MAC, SSID, IPs).
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
  `gcr.io/distroless/static-debian13:nonroot@sha256:…` runtime (ADR 0005).
- Binary at `/tcmon`, entrypoint `["/tcmon", "serve"]`.
- **Runs as UID/GID 568:568 by default** (TrueNAS `apps` user) — overridable
  with `user:`; image must work with any arbitrary UID that owns `/data`.
- Volumes: `/data` (DB, secret key, TLS) — the only writable path. `/tmp` via
  tmpfs if needed.
- Port: `8443` (HTTPS) or `8080` (HTTP when `TCMON_TLS=off`).
- `HEALTHCHECK` uses `/tcmon healthcheck` (no curl in image) hitting
  `/healthz` (unauthenticated, returns only `ok`) — `/readyz` checks DB.
- OCI labels: `org.opencontainers.image.source/licenses=AGPL-3.0-or-later/version/revision`.
- Platforms: `linux/amd64`, `linux/arm64`. Published to
  `ghcr.io/bhager42/teslachargingmonitor` with tags `X.Y.Z`, `X.Y`, `latest`,
  plus digest pinning documented.
- Target image size < 25 MB, idle RSS < 40 MB, idle CPU ≈ 0.

### Configuration (environment)
| Variable | Default | Notes |
|---|---|---|
| `TCMON_LISTEN` | `:8443` | |
| `TCMON_TLS` | `auto` | `auto` (self-signed) / `file` / `off` |
| `TCMON_TLS_CERT_FILE`, `TCMON_TLS_KEY_FILE` | — | |
| `TCMON_PUBLIC_HOSTNAMES` | — | SANs for self-signed cert, allowed `Host` values |
| `TCMON_PASSWORD_HASH_FILE` / `TCMON_PASSWORD_FILE` | — | §9 |
| `TCMON_SECRET_KEY_FILE` | `/data/secret.key` | |
| `TCMON_TRUSTED_PROXIES` | — | CIDRs |
| `TCMON_ALLOWED_CLIENT_CIDRS` | private + loopback ranges | LAN-only enforcement (§10) |
| `TCMON_ALLOW_INSECURE_HTTP` | `false` | Required to run `TCMON_TLS=off` without a proxy |
| `TCMON_LOG_LEVEL` | `info` | |
| `TZ` | `UTC` | Display & quiet hours |

Every secret supports a `*_FILE` variant (Docker secrets / TrueNAS mounted files).

### Generic Docker Compose (`deploy/compose.yaml`)
```yaml
services:
  tcmon:
    image: ghcr.io/bhager42/teslachargingmonitor:1   # pin digest in production
    container_name: tcmon
    restart: unless-stopped
    user: "568:568"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m,mode=1777"]
    ports: ["8443:8443"]
    environment:
      TZ: America/Chicago
      TCMON_TLS: auto                     # self-signed, LAN only (D12)
      TCMON_PUBLIC_HOSTNAMES: truenas.lan,192.168.1.10   # your TrueNAS name/IP
      TCMON_PASSWORD_FILE: /run/secrets/tcmon_password
    secrets: [tcmon_password]
    volumes:
      - ./data:/data
    healthcheck:
      test: ["CMD", "/tcmon", "healthcheck"]
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
  tcmon_password:
    file: ./tcmon_password.txt
```

### TrueNAS SCALE 25.10+ (`deploy/truenas/`)
TrueNAS SCALE 24.10+ runs apps on Docker Compose; 25.10 supports
**Apps → Discover → ⋮ → Install via YAML** for custom apps.

Deliverables:
1. `deploy/truenas/custom-app.yaml` — Compose YAML ready to paste, with
   `user: 568:568` and a named volume `tcmon-data` at `/data` that TrueNAS
   keeps on the apps pool, so no dataset or path is needed (only `TZ` is
   edited). Mounting your own dataset (e.g. `/mnt/<pool>/apps/tcmon`) is
   documented as an option for dataset snapshots.
2. `docs/INSTALL_TRUENAS.md` step-by-step:
   - Option A: Install via YAML (paste file, edit TZ); data in a named volume.
   - Optional: create dataset `<pool>/apps/tcmon` (preset *Apps*), owner
     `apps` (568), and mount it at `/data` instead.
   - Option B: Apps → Custom App form (image, port, env, host-path storage,
     run as 568, read-only rootfs toggle if available).
   - Using a TrueNAS-managed certificate (export to the dataset) or putting the
     app behind a reverse proxy app.
   - Retrieving the setup token from **Apps → tcmon → Logs**; password reset via
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
  `// SPDX-License-Identifier: AGPL-3.0-or-later` (owner decision D13) and a
  copyright line `// Copyright (C) 2026 Brad Hager and contributors`
  (owner decision D14). The README and About page use the
  standard "either version 3 of the License, or (at your option) any later
  version" wording.
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
- Trademark note in README, the About page and the login page footer:
  "Tesla" and "Wall Connector" are trademarks of Tesla, Inc.; Tesla Charger
  Monitoring is an independent project, not affiliated with or endorsed by
  Tesla. Use the word "Tesla" only descriptively; no Tesla logos, fonts or
  "T" mark in the UI, icon or social preview image.

---

## 13. Testing strategy

Every phase ships its own tests in the same PRs as the code — tests are part of
each phase's acceptance criteria, not a later phase. CI runs all of them on
every push and pull request.

| Phase | Tests that must exist when the phase is done |
|---|---|
| 0 | Unit (CLI, build info), fixture-redaction check, SPDX header check |
| 1 | Unit + **fuzz** (decoder, URL validation) against real UWC fixtures; simulator self-tests |
| 2 | Unit (store, migrations, retention) + **integration** (poller ⇄ simulator ⇄ SQLite) + 24 h soak |
| 3 | Table-driven unit tests per rule and state transition; **integration** with simulator scenarios |
| 4 | **Integration** with an in-process mock SMTP server (STARTTLS, implicit TLS, auth failure, Gmail error codes) |
| 5 | Unit (hashing, sessions, throttling) + **HTTP integration** (headers, CSRF, LAN-only allowlist) + ZAP baseline scan |
| 6 | **End-to-end** Playwright (Chromium, Firefox, WebKit) + axe accessibility in both themes + Lighthouse budget |
| 7 | Container structure tests (non-root, read-only, healthcheck, size) + compose smoke test |
| 8 | Full regression, extended fuzz corpus, ASVS checklist review |

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

> **Status (2026-11-02): implemented** on `claude/awesome-cori-yon2g6` — LICENSE,
> README, SECURITY, CONTRIBUTING (DCO), CODE_OF_CONDUCT, ADRs 0001–0004, draft
> threat model, `scripts/capture.sh` (redacting), `scripts/check-headers.sh`,
> Makefile, golangci-lint v2 config, Dependabot, CI/CodeQL/Scorecard workflows
> (actions pinned by SHA), `tcmon version` with tests, fixture-redaction test.
> Charging fixture deferred (D16, tracking issue). Owner to enable on GitHub:
> private vulnerability reporting, secret scanning + push protection, branch
> protection on `main` requiring CI.
- Capture real payloads from the owner's device(s) (script
  `scripts/capture.sh <ip>` that curls the four endpoints, redacts serial/MAC/SSID,
  writes fixtures). **Needs owner input.**
- Repo scaffolding: `LICENSE` (AGPL-3.0), `README.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.editorconfig`, `.gitignore`,
  `go.mod`, `Makefile`/`Taskfile`, `CLAUDE.md`, `docs/THREAT_MODEL.md` (draft),
  ADRs in `docs/adr/` (0001 language, 0002 SQLite, 0003 no-build frontend).
- CI skeleton: lint, test, govulncheck, CodeQL, Scorecard, licence check.

**Accept:** UWC idle fixtures committed and the field list in §2 updated to
match reality (done for version/lifetime/wifi_status/idle vitals). The
**charging `/vitals` capture is deferred** (owner's car unavailable — D16): do
not block on it. Open a tracking issue "Add UWC charging vitals fixture"; until
it lands, the simulator's charging scenario is synthesised from the Gen 3 field
semantics and labelled provisional, and `relay_voltage_abnormal` ships
**disabled by default** with a UI note "needs calibration from a charging
capture". (`overcurrent` does **not** need the capture — its threshold comes
from the configured 48 A max (D17) — so it ships enabled.) CI green
on an empty `main` package; licence headers enforced by a CI check.

### Phase 1 — Wall Connector client + simulator

> **Status (2026-11-02): implemented.** `internal/netguard` (LAN address
> rules + connect-time dial guard), `internal/wallconnector` (models with
> plausibility ranges, reflection-based tolerant decoder producing a
> `Report` of unknown/missing/invalid fields, firmware parsing, observed-only
> code tables, GUI address parsing, client: no proxy, no redirects, no
> keep-alive, 5 s timeout, 64 KiB cap, one request at a time, `Snapshot` and
> `Probe` for "Test connection"), `internal/wcsim` + `cmd/wcsim` (13
> scenarios — idle, charging*, overheat*, thermal-foldback*, device-alert,
> grid-low-voltage, overcurrent*, reboot, firmware-change, wifi-weak,
> offline, slow, malformed; *provisional until issue #1; selectable by flag,
> env or `POST /_sim/scenario`; `-speed` time acceleration). Three fuzz
> targets run 60 s each in CI; the address fuzzer found and fixed a
> trailing-dot / numeric-hostname bypass of the LAN check (regression seeds
> in `internal/wallconnector/testdata/fuzz`). Coverage: wallconnector 92 %,
> wcsim 94 %, netguard 100 %.
- `internal/wallconnector`: typed models, tolerant decoder, code tables,
  client with timeouts/size limits/no redirects.
- `cmd/wcsim` with scenarios (implemented in Go rather than data files so
  they can evolve with simulated time).
- Fuzz tests on the decoder.

**Accept:** client parses all fixtures; fuzzers run 60 s clean in CI;
simulator scenarios selectable via flag/env.

### Phase 2 — Storage + poller

> **Status (2026-11-02): implemented.** `internal/store` (SQLite via
> modernc.org/sqlite v1.60.1, WAL, incremental auto-vacuum, 0600 file,
> embedded consecutive migrations with downgrade refusal; devices with
> 80 %-of-breaker max current, readings/raw payloads/events/poll log,
> hourly rollups with watermark, batched retention pruning that never drops
> un-rolled data, `VACUUM INTO` backups, stats). `internal/poller`
> (worker per device, 60 min / 5 min plugged-in cadence with ±2 % jitter,
> retries at 30 s / 2 min / 5 min, poll-now with 10 s rate limit, hot
> reload via `Sync` every minute, reboot / firmware / grid-profile /
> identity-mismatch detection with first-sighting baselines, update
> fan-out for Phase 3). `tcmon serve` (JSON logs, nightly 03:17
> maintenance) plus an **interim admin CLI** `tcmon device add|update|list|
> remove|test`, `backup`, `migrate`. The CLI writes the same `devices`
> table the web UI will own; D2 (address configured in the GUI, never env
> vars) still holds — the CLI is an operator fallback, not configuration.
> Soak: 3,000 back-to-back polls, goroutines and heap flat (CI runs it on
> every build). Coverage: store 81 %, poller 93 %, cli 83 %.
- SQLite store, migrations, retention + rollup jobs, backup (`VACUUM INTO`).
- Poller with jitter/backoff/active-cadence; reboot & firmware-change detection.
- `tcmon serve` runs headless and logs readings.

**Accept:** 24 h soak against simulator with no goroutine/memory growth; DB
size within estimate (document MB/day/device); retention verified by test.

### Phase 3 — Alert engine

> **Status (2026-11-02): implemented.** `internal/alerts`: 22 built-in rules
> (all of §6 plus `identity_mismatch`), each with typed parameter specs
> (bounds used for validation and, later, the rule editor), defaults in code
> and owner overrides in `alert_rule_overrides` (all devices or one device).
> One pure `step` function drives the per-(rule, device) state machine:
> debounce (`for`, satisfied by a single sample when sampling is slower than
> `for`), minimum consecutive samples, hysteresis, escalation (sent
> immediately), silent de-escalation, cooldown (a held-back firing notice is
> sent once the cooldown ends if still firing), repeat **only while
> critical** (default 6 h on safety rules), optional resolved notices,
> per-device / per-rule snoozes (max 30 days). Event rules (counters, firmware,
> grid profile, reboot, identity) baseline on first sighting and re-baseline
> on counter decreases. Fields flagged invalid skip evaluation. State is
> persisted (no re-alerting after restart); every notice is recorded in
> `alert_events` with a `notified` flag (suppressed ones are kept for the
> history page) and can be acknowledged. `Preview` replays stored history
> through one rule with a candidate config (not possible for
> `device_unreachable`, as failed polls store no readings). Notices from one
> poll are published as one batch so Phase 4 sends one email per poll.
> `QuietHours` (non-critical muting, midnight-spanning windows) is
> implemented here for Phase 4's channels. `tcmon serve` runs the engine and
> logs alerts until email exists; `tcmon alerts rules|history` show config and
> history. Acceptance test: the simulator's overheat scenario produces
> exactly firing → escalated → resolved through the real poller and engine.
> Coverage: alerts 91 %, store 84 %.
- Rule types from §6, state machine, alert events, preview against history.

**Accept:** table tests for every rule incl. debounce, hysteresis, cooldown,
repeat, resolve, snooze, quiet hours; simulator "overheat" scenario fires and
resolves exactly once.

### Phase 4 — Notifications

> **Status (2026-11-02): implemented.** `internal/secrets` (AES-256-GCM
> with a 32-byte key in `secret.key` — `TCMON_SECRET_KEY_FILE`, created 0600
> on first start, warns if group/world-readable; `Secret` type redacted in
> fmt, slog and JSON). `internal/notify`: email via the Go standard library's
> `net/smtp` (no new dependency) with the Gmail preset (smtp.gmail.com:587
> STARTTLS, app password), implicit TLS on 465, TLS ≥ 1.2 with certificate
> verification always on (optional private CA via `TCMON_SMTP_CA_FILE`),
> **plaintext refused** if STARTTLS is not offered. Errors are classified
> permanent vs transient with plain-English hints (Gmail 534 5.7.9 →
> app-password instructions, 535, rejected recipient, certificate, DNS,
> timeout). Messages: one `multipart/alternative` email per poll batch per
> channel (text + escaped HTML templates, dark-mode friendly,
> `Auto-Submitted`, header-injection safe, trademark notice in the footer).
> Persistent queue `notify_deliveries` with backoff 1 m / 5 m / 15 m / 1 h
> (repeating) and give-up after 24 h; permanent errors fail immediately;
> per-channel minimum severity and quiet hours (non-critical notices during
> quiet hours are **dropped from email but kept in the alert history**, not
> deferred); channel health (last success, consecutive failures, last
> error) for the future UI banner. Interim CLI: `tcmon notify add-email|
> update|list|test|remove|log` (password only via `-password-stdin` or
> `-password-file`, never argv). `tcmon serve` delivers alerts by email.
> Tests: mock SMTP server (`internal/notify/smtpmock`) covering STARTTLS,
> implicit TLS, wrong password, Gmail app-password error, rejected
> recipient, plaintext refusal, untrusted certificate, transient 421 with
> retry; the password is checked absent from the DB file, WAL, logs and
> API structs; a simulator alert arrives as exactly one batched email, and
> `tcmon serve` emails an overcurrent alert end to end. Other channels
> (ntfy, webhook, …) remain future work behind the same queue.
- Delivery queue, retries, `Channel` interface, **email (SMTP) channel
  complete** (§7), templates, batching, test-send, encrypted channel secrets.
  Other channels are follow-up PRs.

**Accept:** integration tests against an in-process mock SMTP server covering
STARTTLS, implicit TLS, auth failure, rejected recipient and plaintext refusal;
an alert raised by the simulator arrives as one batched email; secrets never appear in
logs, API responses, or DB plaintext (test asserts).

### Phase 5 — Web server, auth, security middleware

> **Status (2026-11-02): implemented.** `internal/auth`: Argon2id
> (m=64 MiB, t=3, p=1, PHC strings, transparent rehash; `golang.org/x/crypto`
> v0.58.0), NFKC password policy (12–128 chars, 46k common passwords from the
> NCSC list via SecLists (MIT), context words), one-time setup token (log,
> 30 min, single use), `TCMON_PASSWORD_FILE` / `TCMON_PASSWORD_HASH(_FILE)`
> (env-managed password; **plaintext `TCMON_PASSWORD` is refused** —
> assumption for §15 Q13), sessions (256-bit IDs, SHA-256 at rest, 12 h idle
> / 7 d absolute / 30 d remember-me, rotation, revoke others), per-IP and
> global throttling, audit log (migration 0004, `AuditDays` retention 1 y).
> `internal/web`: TLS auto (self-signed ECDSA P-256, 0600, 825 d, renewed
> 30 d before expiry or when `TCMON_PUBLIC_HOSTNAMES` change, fingerprint in
> log and About page, downloadable cert) / file / off (proxy or explicit
> opt-in with banner), TLS 1.3 minimum, LAN-only client allowlist, Host
> check against DNS rebinding, all §10 headers, `http.CrossOriginProtection`
> + per-session CSRF tokens, 64 KiB bodies, server timeouts. Pages: setup,
> login, minimal dashboard (devices, recent alerts), Security (change
> password, sign out others, audit), About (version, AGPL source, cert
> fingerprint). Assets embedded from `web/` (package `webui`), content-hashed.
> CLI: `healthcheck`, `reset-password`, `hash-password`. ZAP baseline scan
> in CI; ASVS checklist in `docs/security/asvs.md`.
- HTTPS (auto/file/off), security headers, CSRF, sessions, login throttling,
  setup-token flow, `reset-password`/`hash-password` CLI, audit log.

**Accept:** ZAP baseline clean (no Medium+); header test suite; ASVS L2
checklist for V2/V3/V4/V13/V14-equivalent sections (ASVS 5.0 numbering)
documented in `docs/security/asvs.md` with pass/N-A per item.

### Phase 6 — Web UI

> **Status (2026-11-02): implemented.** Server-rendered pages (dashboard with
> live device cards, device detail with SVG charts for 24 h / 7 d / 30 d / 1 y,
> lifetime counters, masked identity, raw responses and CSV export; Alerts
> with active alerts, snoozes, history with acknowledgement and a rule editor
> with "test against the last 24 hours"; Notifications with the Gmail form,
> test email and delivery log; Settings with °C/°F and per-class retention
> presets/custom days (confirmation before data is deleted) and database
> backup download; **Settings → Wall Connectors**, where the device address
> is entered, tested ("Test connection") and edited (D2); Diagnostics with
> unknown/missing/invalid fields from the latest raw responses and the poll
> log). Live updates over Server-Sent Events (pre-formatted values, DOM
> updates via `textContent` only). Theme Auto/Dark/Light stored in a cookie
> and rendered server-side (no flash). One 7 KB ES module (3 KB gzipped,
> budget-tested, no `innerHTML`/`eval`), `light-dark()` tokens, container
> queries, `@layer`, view transitions, web app manifest; no service worker
> (it cannot register with the self-signed certificate). Playwright + axe
> suite (WCAG 2.2 AA in both themes on 13 pages + sign-in, zero CSP/Trusted
> Types violations, 320 px without horizontal scroll, live SSE update,
> theme without flash, charts, connection test) runs on Chromium, Firefox and
> WebKit in CI. The e2e suite found and fixed a real bug: devices saved from
> the web UI were never polled because poller workers inherited the HTTP
> request's context. **Deferred:** the Lighthouse ≥ 95 audit (needs a
> signed-in, self-signed-HTTPS Lighthouse CI setup) moves to Phase 8.
- Layout, design tokens with `light-dark()`, theme toggle without flash,
  dashboard (SSE), device detail charts, alerts, notifications, settings,
  diagnostics, about/source page, PWA manifest.

**Accept:** Playwright suite green on 3 engines; axe clean in both themes;
Lighthouse ≥ 95; works at 320 px; zero CSP violations; JS budget met.

### Phase 6b — Charging cost (owner request D18)

> **Status (2026-11-03): implemented.**
> - **Cost logic** (`internal/energy`, pure and table-tested): counter deltas
>   with reset handling, price history, a time-of-use split across window
>   boundaries, and day/week/month buckets in local time (DST-safe). Energy
>   is assigned by each interval's midpoint.
> - **Data:** migration 0005 adds `energy_rates`. Sessions and totals are
>   computed from stored readings on each page load, so no sessions table
>   was needed.
> - **Pages:**
>   - **Settings → Electricity price:** default $0.155; currency; "applies
>     from" date or all past data; optional off-peak price and window;
>     monthly fee; price history.
>   - **Costs:** totals for this month, last month, this year and all time;
>     server-rendered SVG bar charts by day, week or month, each with a data
>     table; the sessions table; daily and session CSV exports.
>   - **Dashboard card:** session cost and this month's cost.
> - **Assumptions** (Q10a unanswered): a flat price, energy only, US dollars.
> - **Acceptance:** a simulated charging session's kWh and cost match the
>   lifetime counters; axe and 320 px checks pass on the new pages.

Show what charging costs, using the owner's electricity price
(**$0.155 per kWh**, editable in the GUI).

**Where the energy numbers come from.** The Wall Connector's lifetime
`energy_wh` counter (verified on the owner's UWC) only ever goes up, so the
energy used between any two polls is the difference between them. That is
exact even with hourly polling — nothing is missed between polls. A
counter that goes down (device reset or replaced) starts a new baseline
instead of producing a negative value. This is the energy delivered by the
Wall Connector, which is what the utility bills; the car's own display may
show slightly less because of charging losses. The UI says so in one line.

**Price settings (Settings → Energy cost).**
- Price per kWh (default **0.155**), currency symbol (default **$**),
  decimals shown.
- Rates keep their history: each change has an "effective from" date, so
  changing the price updates future costs without rewriting past months
  (with an option to apply a new price to past data too).
- Optional extras, off by default: a second **off-peak price** with daily
  start/end times (time-of-use plans), and a flat **monthly fee** or
  percentage for taxes/delivery charges. Energy between two polls is
  costed at the price in effect at that time; when a poll interval crosses
  an off-peak boundary the energy is split in proportion to time.

**Charts and pages.**
- **Dashboard card:** "This session: 12.4 kWh · $1.92" and "This month:
  $18.40".
- **Cost page** (new nav item "Costs") with bar charts by **day** (last
  30 days), **week** (last 12 weeks) and **month** (last 12 months), each
  bar showing cost with kWh on hover/focus and in an accessible data table
  below the chart. Totals for this month, last month, this year and all
  time, plus average cost per session and per month.
- **Charging sessions table:** start, end, duration, kWh, cost and peak
  current. Sessions come from `charge_starts` increments and the plugged-in
  polling (5-minute resolution while a car is connected; start/end times
  are accurate to the polling interval).
- **CSV export** of daily energy and cost, and of sessions.
- Optional monthly cost line in the (Phase 8) summary email.

**Data model.** Migration `0005_energy.sql`: `energy_rates` (effective_from,
price_per_kwh, off-peak price and window, monthly fee); the currency symbol
is a setting. Sessions and day/week/month totals are computed from the stored
lifetime-counter and plug-state readings on each page load (small at this
data volume), so changing a price never leaves stale totals. Cost history
therefore follows the readings retention (2 years by default).

**Accept:**
- Unit tests: counter deltas including resets, rate-history boundaries, the
  time-of-use split across boundaries, and month and day boundaries in the
  container's time zone (including DST changes).
- Simulator test: a charging scenario produces session kWh and cost that
  match the counters to within one poll.
- Accessibility (axe) checks pass on the Costs page in both themes; the
  chart has a matching data table.

### Phase 7 — Container, release, TrueNAS

> **Status (2026-11-05): implemented and released (v0.7.0–v0.7.2); TrueNAS
> install owner-verified.** See ADR 0005.
> - **Image:** distroless static (debian13, the current stable) by digest,
>   cross-compiled reproducibly. It is 19 MB unpacked, about 8 MB to
>   download, runs as 568:568, and has no shell. It passes
>   `scripts/image-test.sh`.
> - **CI:** image tests, a `docker compose up --wait` smoke test with
>   `deploy/compose.yaml`, and a Grype gate (High/Critical with a fix).
> - **Release** (`release.yml`, on `vX.Y.Z` tags): amd64 and arm64 images on
>   GHCR with an SBOM and SLSA provenance, cosign keyless signing, a GitHub
>   attestation, and a GitHub release.
> - **Deploy:** `deploy/compose.yaml`, `deploy/truenas/custom-app.yaml`
>   (a TrueNAS-managed named volume by default, so no dataset or path is
>   needed; your own dataset is optional),
>   and `docs/INSTALL_TRUENAS.md` / `docs/INSTALL_DOCKER.md` (update, backup,
>   restore, password reset, verify).
> - **TrueNAS (owner-verified 2026-11-05, v0.7.2):** installed with
>   "Install via YAML" on TrueNAS SCALE and working. Found and fixed along
>   the way: Settings could not be saved with "Keep forever" retention (#11,
>   v0.7.1); the app page had no **Web UI** button, which made it easy to
>   open plain `http://` instead of `https://` (`x-portals`, #10, v0.7.1);
>   "Car plugged in but not ready" fired on every normal charge (#13,
>   v0.7.2).
> - **Still open:** `cosign verify` against a released image (documented in
>   `docs/INSTALL_DOCKER.md`, not yet run). `gh attestation verify` on
>   `:0.7.2` exited successfully.
- Hardened Dockerfile, multi-arch build, SBOM, provenance, cosign signing,
  GHCR publish on tag, vulnerability gate (Grype, ADR 0005), image structure tests.
- `deploy/compose.yaml`, `deploy/truenas/custom-app.yaml`,
  `docs/INSTALL_TRUENAS.md`, `docs/INSTALL_DOCKER.md`, upgrade/backup docs.

**Accept:** fresh install on TrueNAS SCALE 25.10 via "Install via YAML"
following the doc verbatim succeeds (owner-verified); `docker compose up` on
plain Docker succeeds; `cosign verify` documented and works; image < 25 MB.

### Phase 8 — Hardening & polish (v1.0.0)
- Threat model finalised, ASVS checklist complete, fuzz corpus extended,
  weekly digest email (D19), dead-man's-switch ping (D20),
  i18n scaffolding (strings externalised), docs site (optional).
  Prometheus `/metrics` is deferred (D21).

Delivered as small PRs, in this order:
1. Decisions D19–D21 and this breakdown.
2. Threat model finalised; ASVS 5.0 checklist cross-checked against the
   official requirement IDs, with every 🟡 closed or explicitly deferred.
3. Fuzz corpus extended: seeds for every target from the real fixtures, and
   new targets for untrusted parsing (form values, rule parameters, CSV).
4. Dead-man's-switch ping (D20): URL in Settings, stored encrypted, HTTPS
   only, sent after each successful poll, failures shown in Diagnostics.
5. Weekly digest email (D19): opt-in per email channel; content from
   `internal/energy` and the alert history; previewable and testable.
6. i18n scaffolding: user-facing strings moved to a message catalogue
   (English only), without changing any text.
7. Lighthouse ≥ 95 audit in CI (carried over from Phase 6).
8. CHANGELOG, §15 resolved or explicitly deferred, then v1.0.0.

**Accept:** v1.0.0 tagged, release notes, signed images, CHANGELOG, all
open questions in §15 resolved or deferred explicitly.

### Later / stretch
TrueNAS community catalog submission; Home Assistant MQTT discovery; importing
utility tariffs automatically (e.g. from OpenEI); multi-connector power-sharing view; passkey
(WebAuthn) as an *optional* second factor; Helm chart.

### Proposed repository layout
```
cmd/tcmon/            main entrypoint + CLI subcommands
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
| D2 | The Wall Connector **IP address is configured in the Web GUI** (not env vars/config files). | 2026-11-02 | First-run onboarding + Settings device form with Test connection (§8); `TCMON_DEVICES` env seed removed (§11); poller hot-reloads on address change (§6). |
| D3 | `/version` and `/lifetime` captured from the UWC (fw 26.26.10), serial redacted. | 2026-11-02 | §2 verification table; extra `/version` fields stored; new `grid_profile_changed` rule; counter rules baseline on first sighting. |
| D4 | Idle `/vitals` captured from the UWC. | 2026-11-02 | UWC uses `relay_k1_v`/`relay_k2_v` instead of `relay_coil_v`; relay rule reworked; not-ready rule gated on vehicle connected; grid rule uses `grid_v`; boot vs lifetime uptime clarified. |
| D5 | `/wifi_status` captured from the UWC (SSID, MAC, IP redacted in fixture). | 2026-11-02 | §2 marks it verified; `wifi_infra_ip` used to detect address drift; SSID/MAC masked. Only a charging `/vitals` capture remains. |
| D6 | Polling interval configurable in the GUI; **default 60 min**. | 2026-11-02 | §6 rewritten for hourly snapshots: counter-delta rules as backbone, retries before unreachable alert, poll-now button, optional faster polling while plugged in; retention simplified (§5). |
| D7 | **Email is the primary notification channel**; others may follow. | 2026-11-02 | §7 + Phase 4: full SMTP channel first, batching, provider presets; other channels later. |
| D8 | Project name **Tesla Charger Monitoring**; repo is **public**. | 2026-11-02 | Short id `tcmon` (binary, `TCMON_*` env vars, cookie); trademark disclaimer strengthened (§12); public-repo hardening (§10). |
| D9 | **Go** confirmed as the language. | 2026-11-02 | §4 stands. |
| D10 | Faster polling while a car is plugged in: **on by default** (5 min). The 16 s uptime in the idle `/vitals` capture was an intentional restart. | 2026-11-02 | §6 Poller; fixture README annotated. |
| D11 | Email provider is **Gmail**. | 2026-11-02 | §7: Gmail default preset, app-password guidance, Gmail error hints. |
| D12 | **LAN only**; no CA-validated HTTPS certificate. | 2026-11-02 | §10: self-signed cert by default with fingerprint + download; client-IP allowlist of private ranges; HSTS off; plain HTTP only by explicit opt-in. |
| D13 | License **AGPL-3.0-or-later**. | 2026-11-02 | §12 SPDX headers, OCI label, README wording. |
| D14 | Copyright holder: **Brad Hager**. | 2026-11-02 | §12 header line. |
| D15 | Data retention **adjustable in the Web GUI**, default **2 years**. | 2026-11-02 | §5 retention UI with presets, size estimate, confirmation before deleting. |
| D16 | Charging `/vitals` capture **deferred** (car not available). HTTPS with a self-signed cert and one-time browser warning **confirmed** (D12). | 2026-11-02 | Phase 0 no longer blocks on it; charging-dependent rules ship disabled until calibrated. |
| D17 | **60 A circuit → 48 A max charging current**; 240 V / 60 Hz split-phase (confirmed by idle capture: `grid_v` 240.1, `grid_hz` 59.8). | 2026-11-02 | §8 device form (breaker → 80 % max), `overcurrent` threshold 50.4 A and enabled by default, new optional `current_near_limit` rule. |
| D18 | Add a **charging cost** view; owner's electricity price **$0.155/kWh**. | 2026-11-03 | New Phase 6b: price settings with history (default 0.155, `$`), optional off-peak price and monthly fee, cost on the dashboard card, Costs page with day/week/month bar charts, sessions table, CSV export. |
| D19 | **Weekly digest email, optional** (off by default). | 2026-11-05 | Phase 8: one email a week (charging energy and cost, alerts, device health) to the email channels; no daily option. |
| D20 | **Dead-man's-switch ping, optional** (off until a URL is entered). | 2026-11-05 | Phase 8: HTTPS GET/POST to a user-entered URL (healthchecks.io, Uptime Kuma push) after each successful poll; the service's grace period must exceed the poll interval (60 min by default). |
| D21 | Prometheus `/metrics` **deferred** (not in v1.0). | 2026-11-05 | Phase 8 drops it; §4 row kept as a later option. InfluxDB, Home Assistant and MQTT stay in Later / stretch. |

### 15.1 Still open

Anything below that is not answered uses the documented default; Claude Code
records the assumption in the PR that relies on it.

**Hardware & network**
1. How many UWCs (just one?) and is it in a **power-sharing** group? *(Model
   answered: UWC — D1.)*
2. *(Answered — D2: entered in the Web GUI.)* Please still reserve the UWC's IP
   in your router's DHCP so it doesn't change.
3. **Deferred (D16):** `/api/1/vitals` while a car is actively charging (and
   ideally plugged-in-but-not-charging) — send it when the car is back. For reference, the full list: run
   `curl http://<ip>/api/1/vitals`, `/lifetime`, `/wifi_status`, `/version`
   (ideally once idle and once while charging) and share them — redact serial,
   MAC and SSID if you like. *(The restart that produced 16 s uptime was
   intentional — D10.)*
4. *(Answered — D17: 60 A breaker, 48 A max, 240 V / 60 Hz.)*
5. Is TrueNAS on the same VLAN/subnet as the chargers, or will traffic cross a
   firewall?

**Alerting**
6. *(Answered — D7/D11: email via Gmail.)* Which second channel, if any,
   would you want next (ntfy, Pushover, Home Assistant, …)?
7. Confirm or adjust the default thresholds in §6 (especially temperatures and
   voltage band). Any rules to add/remove?
8. *(Answered — D19: weekly digest, optional.)* Quiet hours exist (per channel, Phase 4).
9. *(Answered — D6/D10: 60 min default, 5 min while plugged in.)*
10. *(Answered — D20: optional dead-man's-switch ping URL.)*
10a. *(D18: $0.155/kWh.)* Is that a single flat price, or do you have a
    time-of-use plan (cheaper overnight)? Should taxes or fixed monthly
    charges be included in the cost, or energy only? Currency is assumed
    to be US dollars ($).

**Access & security**
11. *(Answered — D12: LAN only.)*
12. *(Answered — D12/D16: self-signed HTTPS, one-time browser warning.)*
13. *(Default applied in Phase 5: all three supported — setup token,
    `TCMON_PASSWORD_FILE`, `TCMON_PASSWORD_HASH`; plaintext `TCMON_PASSWORD`
    is refused.)* Tell us if you want a different default.
14. Session lifetime preferences (default 12 h idle / 7 d absolute)?

**Data**
15. *(Answered — D15: adjustable in GUI, 2-year default.)* Which dataset/pool
    path on TrueNAS? (Default in docs: `/mnt/<pool>/apps/tcmon/data`.)
16. *(Answered — D21: Prometheus `/metrics` deferred.)* InfluxDB or Home
    Assistant/MQTT integration wanted later?
17. Units: °C or °F; time zone.

**Project / legal**
18. *(Answered — D8: Tesla Charger Monitoring, short id `tcmon`.)*
19. *(Answered — D13/D14: AGPL-3.0-or-later, © Brad Hager.)*
20. *(Answered — D8: public.)*
21. Contributions: DCO sign-off OK, or do you want a CLA (only needed if you may
    ever relicense)?
22. *(Answered — D9: Go.)*
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
