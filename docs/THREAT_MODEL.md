<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# Threat Model

Scope: Tesla Charger Monitoring (`tcmon`) running as a container on a home
LAN (TrueNAS SCALE or Docker), polling one Tesla Universal Wall Connector and
sending email via Gmail.

Status: finalised in Phase 8 (2026-11-05), drafted in Phase 0. The ASVS 5.0
Level 2 checklist is [`security/asvs.md`](security/asvs.md), and the
documented policies it relies on are in
[`security/controls.md`](security/controls.md). Review this file whenever a
new external connection, input or stored secret is added.

## Attackers considered
| Attacker | Capability |
|---|---|
| Another device on the LAN | Can reach the app's port and the Wall Connector; can sniff or spoof plain HTTP |
| A malicious website in the owner's browser | Can send cross-site requests to LAN addresses and try DNS rebinding |
| Someone reading the public repository | Sees code, fixtures and CI configuration |
| A compromised dependency or CI action | Can try to change what ends up in the image |

Out of scope: an attacker with administrator access to the host (they can
read `/data` and the container log), and physical access to the Wall
Connector.

## Assets
| Asset | Why it matters |
|---|---|
| Web UI password / session cookies | Full control of the app's settings |
| Gmail app password | Can send email as the owner |
| Readings history | Reveals when the owner is home/charging (privacy) |
| `secret.key`, TLS private key | Decrypt stored credentials; impersonate the app |
| Alert pipeline integrity | Missed alerts could hide an electrical/thermal fault |
| Device identifiers (serial, MAC, SSID) | Personal data; must not leak via repo or logs |

## Trust boundaries
1. Browser ⇄ tcmon (HTTPS, self-signed by default; LAN-only allowlist).
2. tcmon ⇄ Wall Connector (plain, unauthenticated HTTP on the LAN —
   responses are untrusted input).
3. tcmon ⇄ Gmail SMTP (TLS, certificate always validated).
3a. tcmon ⇄ dead-man's-switch service (HTTPS to an owner-entered URL;
   planned for Phase 8, D20).
4. Container ⇄ host (`/data` volume, non-root UID 568).
5. CI/CD ⇄ GHCR ⇄ user (supply chain).

## Threats and mitigations (STRIDE)
| # | Threat | Mitigation (plan §) |
|---|---|---|
| S1 | Password guessing from the LAN | Argon2id, per-IP + global throttling, audit log (§9) |
| S2 | Session theft via sniffing | HTTPS by default, `__Host-` Secure HttpOnly SameSite=Strict cookie (§9, §10) |
| S3 | DNS rebinding from a malicious website to the LAN app | Host header allowlist (IP literals, localhost, `TCMON_PUBLIC_HOSTNAMES`) → 421 (Phase 5) |
| S4 | Setup hijack before the owner sets a password | Setup needs a one-time token visible only in the container log; expires after 30 min (Phase 5) |
| S5 | Cookie tossing from another host or plain-HTTP origin | Every cookie uses the `__Host-` prefix over HTTPS, `SameSite=Strict`; the theme cookie gained it in Phase 8 |
| T1 | LAN attacker spoofs Wall Connector responses | Strict decoding, size/time limits, range checks; data can't trigger code execution (§2, §6) |
| T2 | Tampered container image | Signed images, SBOM, provenance, digest pinning (§10, §11) |
| T4 | Malicious dependency or CI action | Actions pinned by SHA, base image by digest; Dependabot, dependency review, govulncheck, Grype, CodeQL, Scorecard; minimal dependencies |
| T5 | Forged log entries via request text | JSON logs; request-controlled text stripped of line breaks and truncated (`logSafe`) |
| R1 | Settings changed without trace | Audit log of auth and settings changes (§10) |
| I1 | XSS via device strings (SSID, codes) | `html/template` escaping, strict CSP, Trusted Types (§8, §10) |
| I2 | Secrets in DB/backups | Channel credentials encrypted (AES-256-GCM) with a separate `secret.key` (0600); `Secret` type redacted in logs/JSON; passwords never on the command line (Phase 4) |
| I4 | Alerts or credentials sent in clear over SMTP | STARTTLS required (plaintext refused) or implicit TLS; certificate verification always on (Phase 4) |
| T3 | Header injection via device/rule text into email | Addresses parsed with `net/mail`, subject flattened and RFC 2047-encoded, HTML template auto-escaping (Phase 4) |
| I3 | Identifiers committed to the public repo | Redacting capture script + fixture test (Phase 0) |
| I5 | Charging history reveals when someone is home | Stored only locally; retention configurable (D15); backups and CSV only for the signed-in owner; no telemetry |
| I6 | Internal details exposed by errors or listings | Generic error pages (`auth.UserMessage`, panic recovery); no directory listings (fixed in Phase 8); `/healthz` returns only `ok` |
| D1 | Poll storms overload the device | Min interval, single in-flight request, backoff (§6) |
| D2 | Email flood | Batching per poll, cooldowns, repeat limits (§6, §7) |
| D3 | Slow or oversized requests exhaust the server | 64 KiB bodies, 16 KiB headers, read/write/idle timeouts; Argon2id work bounded by the login throttle |
| E1 | Container breakout / privilege escalation | Non-root, read-only rootfs, no capabilities, no-new-privileges (§11) |
| E2 | SSRF via the device address or the dead-man's-switch URL | Device addresses limited to LAN ranges when parsed and again at dial time (DNS-rebinding-safe), no redirects; the planned dead-man URL will be HTTPS only (D20) |
| E3 | CSRF from another LAN web app | Fetch-metadata checks + tokens + SameSite=Strict (§10) |

## Accepted risks
- The Wall Connector API itself is unauthenticated HTTP; anyone on the LAN can
  read it regardless of this app, and a LAN attacker could spoof its
  responses. tcmon treats them as untrusted input, so the worst case is false
  or missed alerts.
- Self-signed certificate: first-visit trust relies on the owner comparing the
  fingerprint shown in logs/About page.
- One password, no MFA (owner requirement). Brute force is limited by the
  throttle, Argon2id and LAN-only access.
- Secrets live in files in `/data`, not a vault; the host administrator is
  trusted.
- Logs stay on the host unless the owner forwards them.
- Remaining ASVS deviations and deferred items are listed in
  [`security/asvs.md`](security/asvs.md#summary).
