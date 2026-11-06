<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# Security controls and policies

The documented policies that the OWASP ASVS 5.0 checklist
([`asvs.md`](asvs.md)) refers to. Values are the defaults in the code at the
time of writing; the code is authoritative if they ever disagree.

Context: one owner, one password, LAN only (D12), one Universal Wall
Connector, email via Gmail. There are no user accounts, roles or tenants.

## Input validation rules (V2.1)

All validation happens in Go on the server; HTML attributes such as `min`,
`max` and `required` are for convenience only.

| Input | Rule | Where |
|---|---|---|
| Wall Connector address | IPv4/IPv6 literal or hostname; `http`/`https` only; no credentials, path, query, fragment or IPv6 zone; port 1–65535; numeric/hex IPv4 spellings refused; LAN ranges only unless "allow non-LAN" is set; checked again at dial time | `wallconnector.ParseAddress`, `netguard.DialControl` |
| Device name | 1–64 characters | `store.Device.Normalize` |
| Poll intervals | Whole seconds between `store.MinInterval` and `store.MaxInterval` | same |
| Nominal voltage / frequency | One of 120, 208, 220, 230, 240, 277, 400, 480 V; 50 or 60 Hz | same |
| Breaker / max current | 0–200 A / 0–100 A; max current ≤ 80 % of the breaker (continuous load) | same |
| Alert rule parameters | Each parameter has a declared minimum and maximum; "for" ≤ 24 h, cooldown and repeat ≤ 7 days (repeat ≥ 15 min), min samples 1–100 | `alerts.Definition.Validate` |
| Retention | 0 (keep forever) or 1–36 500 days per data class | `store.Retention.Validate` |
| Email channel | Addresses parsed with `net/mail`; host, port 1–65535, STARTTLS or implicit TLS (plaintext refused); quiet hours `HH:MM-HH:MM` | `notify` |
| Electricity price | 0–100 per kWh, monthly fee 0–100 000, off-peak times within the day (minute 0–1439) | `store` (`ErrBadRate`) |
| Password | 12–128 characters after NFKC normalisation; not a common/breached password; not a context word | `auth.CheckPolicy` |
| Device responses | Untrusted: ≤ 64 KiB, 5 s timeout, no redirects, strict JSON decoding into typed structs, per-field plausible ranges; out-of-range fields are kept but flagged invalid and never drive alerts | `wallconnector.Decode*`, `Report` |
| Request bodies / headers | Forms ≤ 64 KiB; headers ≤ 16 KiB; read 15 s, write 30 s, idle 2 min | `limitBody`, `http.Server` |

Combined-field rules (V2.1.2, V2.2.3): max current against breaker size;
alert repeat at least 15 minutes when set; a shorter retention requires an
explicit confirmation because it deletes data.

## Business-logic limits and anti-automation (V2.1.3, V2.4.1, V6.1.1)

| Function | Limit |
|---|---|
| Login and setup | 5 failed attempts per client IP and 50 globally per 15 minutes; then `429` with `Retry-After`. In memory (a restart clears it). Every attempt is audited. |
| Setup token | One-time, 160-bit random, expires after 30 minutes, constant-time compare. |
| Poll now | At most once per 10 seconds per Wall Connector. |
| Polling | Minimum interval per device; one request in flight per device; retries at 30 s, 2 min and 5 min before "unreachable". |
| Alert email | Batched per poll; per-rule cooldown and repeat limits; quiet hours per channel. |
| Test email / Test connection | Not rate limited. They need a signed-in session and a CSRF token, so only the owner can trigger them (accepted, see `asvs.md`). |

## Authentication pathways (V6.1.3, V6.3.4)

All pathways set or check the same single password, with the same policy and
Argon2id hashing:

1. **First run:** the one-time setup token from the container log, then a
   new password (`/setup`).
2. **Pre-seeded:** `TCMON_PASSWORD_FILE`, `TCMON_PASSWORD_HASH` or
   `TCMON_PASSWORD_HASH_FILE`. A plaintext `TCMON_PASSWORD` is refused.
3. **Sign-in:** `/login` with the password.
4. **Recovery:** `tcmon reset-password`, which requires a shell in the
   container (host administrator).

There is no other way in. MFA is not offered (owner requirement: a single
password; passkeys are listed under Later / stretch).

## Context-specific words (V6.1.2, V6.2.11)

A password is refused when, after NFKC normalisation and lower-casing, it
contains one of these words and fewer than 12 characters remain without it:
`tcmon`, `tesla`, `wallconnector`, `wall connector`, `charger`, `password`,
`passw0rd` (`auth.contextWords`). This is in addition to the embedded list
of about 46 000 common/breached passwords.

## Sessions (V7.1)

- Reference tokens: 256-bit random; only a SHA-256 hash is stored.
- Inactivity timeout 12 hours; absolute lifetime 7 days, or 30 days with
  "keep me signed in". This is longer than NIST SP 800-63B's AAL1 guidance
  would suggest for shared devices; it is justified by LAN-only access, a
  single owner, `SameSite=Strict` cookies and CSRF tokens (§15 question 14
  keeps the defaults open for the owner).
- Concurrent sessions: not limited. The Security page shows how many are
  active and can sign out all of them; a password change signs out all
  others.
- No federation or SSO.

## Authorization (V8.1)

One role. Every route except `/login`, `/setup`, `/healthz`, `/readyz` and
`/static/*` requires a valid session (`authed`); every state-changing request
also requires the session's CSRF token and passes Fetch Metadata
cross-origin protection. There is no field-level or per-object access
control because all data belongs to the one owner.

## Cryptographic inventory and key lifecycle (V11.1)

| Use | Algorithm | Key / material | Lifecycle |
|---|---|---|---|
| Password storage | Argon2id, m = 64 MiB, t = 3, p = 1, 16-byte salt | — | Parameters are stored in each hash; rehashed transparently when they change |
| Channel credentials at rest (Gmail app password, dead-man's-switch URL) | AES-256-GCM, random 96-bit nonce, versioned format, bound to its purpose (fixed AAD) | `secret.key` (32 random bytes, mode 0600) in the data directory, or `TCMON_SECRET_KEY_FILE` | Created on first run; kept separately from the database in backups; rotation means re-entering credentials with a new key |
| Session and CSRF tokens | `crypto/rand`, 256 bits; SHA-256 for the stored session hash | — | Expire as above; revoked on sign-out or password change |
| Setup token | `crypto/rand`, 160 bits | — | Single use, 30 minutes |
| HTTPS (default) | Self-signed ECDSA P-256 certificate; TLS 1.3 minimum (1.2 opt-in via `TCMON_TLS_MIN_VERSION`); Go's default suites incl. X25519MLKEM768 | Key in `tls/` in the data directory | 825-day validity, renewed automatically 30 days before expiry or when host names change; fingerprint shown in the log and on About |
| HTTPS (own certificate) | As provided | `TCMON_TLS_CERT_FILE` / `TCMON_TLS_KEY_FILE` | Owner-managed |
| SMTP | TLS 1.2+, certificate always verified (system roots or `TCMON_SMTP_CA_FILE`) | — | — |
| Dead-man's-switch ping | TLS 1.2+, certificate always verified (system roots, plus `TCMON_SMTP_CA_FILE` if set, for a LAN monitor with a private CA) | — | — |
| Release images | cosign keyless signatures, SLSA provenance, SBOM | GitHub OIDC (no long-lived keys) | Per release |

Only Go's standard library and `golang.org/x/crypto` implement these.
`math/rand` is used only for poll-timing jitter.

## Communication inventory (V13.1.1, V13.2.4)

| Direction | Peer | Protocol | Notes |
|---|---|---|---|
| Inbound | Owner's browser | HTTPS (self-signed by default) | LAN client allowlist, Host header allowlist |
| Outbound | Wall Connector | HTTP (the device offers nothing else) | LAN addresses only, checked when parsing and at dial time; no proxy; no redirects |
| Outbound | Gmail (or another SMTP server) | SMTP with STARTTLS or implicit TLS | Host entered by the owner; plaintext refused |
| Outbound | Dead-man's-switch service (optional) | HTTPS GET, TLS ≥ 1.2, certificate validated | URL entered by the owner; off until set; at most one ping a minute, after successful polls; redirects only to HTTPS (at most 3); response discarded; 10 s timeout |

Nothing else is contacted: no telemetry, update checks, fonts or CDNs.

## Sensitive data classification (V14.1)

| Class | Data | Protection |
|---|---|---|
| Secret | Password (hash only), Gmail app password, dead-man's-switch URL, `secret.key`, TLS private key, session/setup tokens | Never logged or shown; credentials encrypted at rest; files mode 0600; `secrets.Secret` type redacts itself |
| Personal | Wall Connector serial, Wi-Fi SSID/MAC, LAN IPs, email addresses | Serial masked in the UI and alerts; SSID/MAC never logged; never committed (redacted fixtures, `fixturecheck`) |
| Private | Readings and charging history (reveals when someone is home) | Stored only in the local database; retention configurable (D15); backups only by the signed-in owner. The optional weekly digest (D19) emails a summary (energy, cost, alert counts, highest temperatures) only to channels the owner opted in |
| Internal | Configuration, alert rules, audit log | Signed-in owner only |

No sensitive data travels in URLs or query strings, and every non-static
response is `Cache-Control: no-store`.

## Dependencies and remediation (V15.1.1, V15.1.2)

- Dependabot checks Go modules, GitHub Actions, the e2e npm packages and
  the container base image weekly; govulncheck, dependency review, CodeQL, Grype and Scorecard run in
  CI. Releases publish an SBOM.
- Targets: a vulnerability that affects tcmon and has a fix — critical or
  high within 7 days, medium within 30 days, low with the next release.
  Other dependency updates are reviewed within a month. Reports follow
  `SECURITY.md` (acknowledge within 7 days, fix or plan within 30 days).

## Resource-intensive functions (V15.1.3, V15.2.2)

| Function | Safeguard |
|---|---|
| Polling | Per-device interval, single in-flight request, timeouts, backoff |
| Charts and series API | Allow-listed metrics and ranges; hourly roll-ups beyond the readings retention |
| CSV export, costs | Bounded by the selected range and the retention period |
| Database backup | Signed-in owner only; streamed from a temporary copy |
| Password hashing | Argon2id at 64 MiB per attempt, bounded by the login throttle |
| Live updates (SSE) | One stream per signed-in page; ends when the session expires or is revoked |

## Logging inventory (V16.1.1)

| Log | Content | Format and storage | Access |
|---|---|---|---|
| Application log | Startup, polls, alerts, email delivery, HTTP requests (method, path, status, duration, client IP; ≥ 400 at info, others at debug), panics | JSON (`log/slog`) on stdout, timestamps with UTC offset; kept by Docker/TrueNAS | Host administrator |
| Audit log | Sign-in success and failure, throttling, setup, password change, session revocation, settings changes, backups | `audit_log` table; retention 365 days by default | Owner (Security page), host administrator |
| Poll and delivery log | Each poll and email delivery result | Database; retention 90 days by default | Owner (Diagnostics) |

Request-controlled text is stripped of line breaks and truncated before it
is logged (`logSafe`). Passwords, tokens and credentials are never logged.
Shipping logs to a separate system is left to the host (Docker or TrueNAS
log drivers).
