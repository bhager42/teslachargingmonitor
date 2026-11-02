# OWASP ASVS 5.0 — Level 2 checklist (Phase 5 snapshot)

Status of Tesla Charger Monitoring against the OWASP Application Security
Verification Standard 5.0, Level 2, grouped by chapter. Requirements are
paraphrased; **exact requirement IDs will be cross-checked against the
official ASVS 5.0.0 text in Phase 8** (plan §14). Legend: ✅ pass ·
🟡 partial / planned (phase noted) · N/A not applicable.

Scope: single-user, LAN-only web app (owner decisions D12), one password,
no user accounts, no API for third parties.

## V1 Encoding and sanitization
| Requirement (paraphrased) | Status | Evidence |
|---|---|---|
| Context-aware output encoding for HTML | ✅ | `html/template` everywhere; device strings (SSID, codes) only rendered through it |
| No injection into SQL | ✅ | Parameterized queries only; identifier concatenation limited to constant lists (`store/maintenance.go`, gosec G202 justified inline) |
| Email header injection prevented | ✅ | `net/mail` parsing, subject flattened + RFC 2047 encoded (`notify/email.go`, tested) |

## V2 Validation and business logic
| Requirement | Status | Evidence |
|---|---|---|
| Server-side validation of all input | ✅ | Device address, intervals, rule params, email settings, retention, passwords validated in Go |
| Limits on request sizes | ✅ | 64 KiB form bodies, 16 KiB headers, device responses 64 KiB |
| Anti-automation on authentication | ✅ | Per-IP (5/15 min) and global (50/15 min) throttling with `Retry-After` |

## V3 Web frontend security
| Requirement | Status | Evidence |
|---|---|---|
| Strict CSP without `unsafe-*`, `frame-ancestors 'none'` | ✅ | `web/middleware.go`, asserted on every route in `TestSecurityHeadersEverywhere` |
| Trusted Types enforced | ✅ | `require-trusted-types-for 'script'` (no JS yet; Phase 6 must comply) |
| `X-Content-Type-Options`, `Referrer-Policy`, COOP/COEP/CORP, `Permissions-Policy` | ✅ | Same middleware/test |
| Cookies: `__Host-` prefix, Secure, HttpOnly, SameSite=Strict | ✅ | `TestSetupFlow` |
| CSRF defense | ✅ | `http.CrossOriginProtection` (Fetch Metadata) + per-session synchronizer token on authenticated POSTs |
| Host header validation (DNS rebinding) | ✅ | `hostCheck`: IP literals, localhost, `TCMON_PUBLIC_HOSTNAMES` only (421 otherwise) |
| HSTS | 🟡 | Off with the self-signed default by design (D12); on with `TCMON_HSTS=true` |

## V4 API and web service
N/A in Phase 5 (no JSON API yet). 🟡 Phase 6 adds same-origin JSON/SSE endpoints behind the same session + CSRF controls.

## V5 File handling
| Requirement | Status | Evidence |
|---|---|---|
| No user file uploads | N/A | — |
| Downloads served with correct type/disposition | ✅ | Certificate download (`application/x-pem-file`, attachment); backups via CLI only |

## V6 Authentication
| Requirement | Status | Evidence |
|---|---|---|
| Passwords ≥ 12 chars allowed up to 128+, no composition rules, Unicode allowed | ✅ | `auth.CheckPolicy` (min 12, max 128, NFKC) |
| Breached/common password check | ✅ | Embedded list (46k entries ≥ 8 chars from the NCSC 100k list) + context words |
| No password hints/security questions | ✅ | — |
| Password change requires the current password | ✅ | `ChangePassword`, tested |
| Generic error messages | ✅ | "Incorrect password." only |
| Initial secret delivered securely | ✅ | One-time setup token in the container log, 30-min expiry, constant-time compare, single use |
| Recovery | ✅ | `tcmon reset-password` requires container shell access |
| Passwords not in env vars visible to `docker inspect` | ✅ | `TCMON_PASSWORD` refused; `_FILE` / hash variants only |
| MFA | 🟡 | Out of scope for v1 (single password by owner requirement); passkeys listed as stretch |

## V7 Session management
| Requirement | Status | Evidence |
|---|---|---|
| ≥ 128-bit random session IDs, only hashes stored | ✅ | 256-bit, SHA-256 at rest |
| Idle and absolute timeouts | ✅ | 12 h idle, 7 d absolute (30 d with "keep me signed in"), `TestSessionsExpire` |
| Session rotation on login and password change | ✅ | New ID each login; password change revokes all, issues new |
| Logout invalidates server-side | ✅ | `TestLoginLogoutAndThrottle` |
| "Sign out everywhere" | ✅ | Security page |

## V8 Authorization
Single role; every route except `/login`, `/setup`, `/healthz`, `/readyz`, `/static/*` requires a session (`authed`). ✅

## V9 / V10 Self-contained tokens, OAuth
N/A (no JWT/OAuth).

## V11 Cryptography
| Requirement | Status | Evidence |
|---|---|---|
| Approved password hashing with tunable cost | ✅ | Argon2id m=64 MiB, t=3, p=1 (above OWASP minimum); transparent rehash |
| Authenticated encryption for secrets at rest | ✅ | AES-256-GCM, random nonces, versioned format, separate 0600 key file |
| CSPRNG for all secrets | ✅ | `crypto/rand` only |

## V12 Secure communication
| Requirement | Status | Evidence |
|---|---|---|
| TLS for all traffic | ✅ | HTTPS by default (self-signed auto cert); plain HTTP only behind a trusted proxy or explicit opt-in with a banner |
| TLS 1.3 minimum (1.2 opt-in), PQ hybrid key exchange | ✅ | Go defaults incl. X25519MLKEM768; `TestTLSVersionsAndServe` |
| Outbound TLS verified | ✅ | SMTP always verifies certificates; plaintext SMTP refused |
| Certificate identity verifiable by the user | ✅ | SHA-256 fingerprint in log + About page; downloadable cert |

## V13 Configuration
| Requirement | Status | Evidence |
|---|---|---|
| Least-privilege, hardened runtime | 🟡 | Phase 7: non-root UID 568, read-only rootfs, no capabilities |
| Dependencies pinned, scanned | ✅ | `go.sum`, govulncheck, Dependabot, dependency review, CodeQL, Scorecard |
| No debug endpoints | ✅ | `/healthz` returns only `ok` |
| LAN-only exposure | ✅ | Client allowlist (RFC 1918, ULA, loopback, link-local), `TestLANOnlyAndHostCheck` |

## V14 Data protection
| Requirement | Status | Evidence |
|---|---|---|
| Sensitive pages not cached | ✅ | `Cache-Control: no-store` on every non-static response |
| Device identifiers protected | ✅ | Serial masked in UI/alerts, fixtures redacted, SSID/MAC never logged |
| Data retention configurable | ✅ | D15 |

## V15 Secure coding and architecture
✅ Threat model (`docs/THREAT_MODEL.md`), memory-safe language, minimal dependencies (sqlite, x/crypto, x/text), fuzzing of parsers.

## V16 Security logging and error handling
| Requirement | Status | Evidence |
|---|---|---|
| Security events logged (logins, failures, throttling, password changes, session revocation, setup) | ✅ | `audit_log` table + JSON logs; shown on the Security page |
| No secrets in logs | ✅ | `Secret` type redaction; tests scan logs for passwords |
| Generic errors to users, details in logs | ✅ | `auth.UserMessage` filters what reaches the UI |
| Panics handled without leaking details | ✅ | Recovery middleware returns a generic 500 |

## V17 WebRTC
N/A.

## Automated checks
- `TestSecurityHeadersEverywhere`, `TestLANOnlyAndHostCheck`, `TestSetupFlow`,
  `TestLoginLogoutAndThrottle`, `TestSessionsExpire`, `TestChangePasswordAndRevoke`,
  `TestEnvManagedPassword`, `TestCertificate`, `TestTLSVersionsAndServe` (`internal/web`).
- ZAP baseline scan in CI against the running server (`.github/workflows/ci.yml`, job "ZAP baseline scan").
