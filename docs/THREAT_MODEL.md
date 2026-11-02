# Threat Model (draft — Phase 0)

Scope: Tesla Charger Monitoring (`tcmon`) running as a container on a home
LAN (TrueNAS SCALE or Docker), polling one Tesla Universal Wall Connector and
sending email via Gmail. Finalised in Phase 8.

## Assets
| Asset | Why it matters |
|---|---|
| Web UI password / session cookies | Full control of the app's settings |
| Gmail app password | Can send email as the owner |
| Readings history | Reveals when the owner is home/charging (privacy) |
| Alert pipeline integrity | Missed alerts could hide an electrical/thermal fault |
| Device identifiers (serial, MAC, SSID) | Personal data; must not leak via repo or logs |

## Trust boundaries
1. Browser ⇄ tcmon (HTTPS, self-signed by default; LAN-only allowlist).
2. tcmon ⇄ Wall Connector (plain, unauthenticated HTTP on the LAN —
   responses are untrusted input).
3. tcmon ⇄ Gmail SMTP (TLS, certificate always validated).
4. Container ⇄ host (`/data` volume, non-root UID 568).
5. CI/CD ⇄ GHCR ⇄ user (supply chain).

## Threats and mitigations (STRIDE)
| # | Threat | Mitigation (plan §) |
|---|---|---|
| S1 | Password guessing from the LAN | Argon2id, per-IP + global throttling, audit log (§9) |
| S2 | Session theft via sniffing | HTTPS by default, `__Host-` Secure HttpOnly SameSite=Strict cookie (§9, §10) |
| T1 | LAN attacker spoofs Wall Connector responses | Strict decoding, size/time limits, range checks; data can't trigger code execution (§2, §6) |
| T2 | Tampered container image | Signed images, SBOM, provenance, digest pinning (§10, §11) |
| R1 | Settings changed without trace | Audit log of auth and settings changes (§10) |
| I1 | XSS via device strings (SSID, codes) | `html/template` escaping, strict CSP, Trusted Types (§8, §10) |
| I2 | Secrets in DB/backups | Channel credentials encrypted with a separate key file, 0600 (§5) |
| I3 | Identifiers committed to the public repo | Redacting capture script + fixture test (Phase 0) |
| D1 | Poll storms overload the device | Min interval, single in-flight request, backoff (§6) |
| D2 | Email flood | Batching per poll, cooldowns, repeat limits (§6, §7) |
| E1 | Container breakout / privilege escalation | Non-root, read-only rootfs, no capabilities, no-new-privileges (§11) |
| E2 | SSRF via device URL or webhook settings | Private-range allowlist for devices, https-only webhooks, DNS-rebinding-safe dialer (§6, §10) |
| E3 | CSRF from another LAN web app | Fetch-metadata checks + tokens + SameSite=Strict (§10) |

## Accepted risks
- The Wall Connector API itself is unauthenticated HTTP; anyone on the LAN can
  read it regardless of this app.
- Self-signed certificate: first-visit trust relies on the owner comparing the
  fingerprint shown in logs/About page.
