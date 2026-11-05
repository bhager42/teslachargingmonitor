<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# OWASP ASVS 5.0.0 — Level 2 checklist

Tesla Charger Monitoring assessed against every Level 1 and Level 2
requirement of the [OWASP Application Security Verification Standard
5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0), by official
requirement ID. Requirement wording is paraphrased; see the standard for the
exact text. Policies that ASVS asks to be documented are in
[`controls.md`](controls.md); threats and accepted risks are in the
[threat model](../THREAT_MODEL.md).

Scope: single owner, one password, LAN only (D12), no user accounts, no API
for third parties. Assessed 2026-11-05 (Phase 8).

Legend: ✅ meets the requirement · ⚠️ deliberate deviation, accepted with a
reason · 🟡 partly met, remaining work deferred · N/A not applicable.

## Summary

| Status | Requirements |
|---|---|
| ✅ Meets | 152 |
| ⚠️ Accepted deviation | 6 |
| 🟡 Partly met (deferred) | 3 |
| N/A Not applicable | 92 |
| **Total (Level 1 + 2)** | **253** |

Accepted deviations: V3.4.1 (HSTS), V6.3.3 (MFA), V12.2.2 (publicly trusted
certificate), V12.3.1 (the Wall Connector's plain HTTP), V13.3.1 (secrets
vault), V16.4.3 (remote log shipping). Deferred: V2.4.1 (rate limit for test
email/connection), V7.5.2 (per-session list), V16.3.2 (logging of
unauthenticated requests).

## V1 Encoding and Sanitization

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V1.1.1 | Decode input once, before validation | 2 | ✅ | Go's `net/http`/`url` decode once; values are validated after decoding; no double decoding anywhere |
| V1.1.2 | Encode at the final step / by the interpreter | 2 | ✅ | `html/template` contextual auto-escaping at render time; `encoding/json`, `encoding/csv`, `net/mail` encode their own output |
| V1.2.1 | Context-aware output encoding (HTML, attributes, headers) | 1 | ✅ | `html/template` everywhere, no `template.HTML`/`JS`/`URL` conversions; headers set only from constants or validated values |
| V1.2.2 | Encode untrusted data in URLs; safe schemes only | 1 | ✅ | Links are built from integer IDs and constants; device address restricted to `http`/`https` (`wallconnector.ParseAddress`) |
| V1.2.3 | Encode when building JavaScript/JSON | 1 | ✅ | JSON only via `encoding/json`; no inline scripts (CSP); browser JS sets `textContent` only |
| V1.2.4 | Parameterised database queries | 1 | ✅ | SQLite with `?` placeholders only; identifier concatenation limited to constant lists (`store/maintenance.go`, gosec G202 justified inline) |
| V1.2.5 | No OS command injection | 1 | ✅ | No `os/exec` anywhere in the application |
| V1.2.6 | LDAP injection | 2 | N/A | No LDAP |
| V1.2.7 | XPath injection | 2 | N/A | No XML/XPath |
| V1.2.8 | LaTeX injection | 2 | N/A | No LaTeX |
| V1.2.9 | Escape regular-expression metacharacters | 2 | ✅ | All regular expressions are compile-time constants; no user input is compiled |
| V1.3.1 | Sanitise WYSIWYG/HTML input | 1 | N/A | No rich-text input |
| V1.3.2 | No eval / dynamic code execution | 1 | ✅ | No `eval`/`new Function`/`innerHTML` (`TestJavaScriptBudget`); CSP `script-src 'self'` with Trusted Types |
| V1.3.3 | Sanitise data for dangerous contexts | 2 | ✅ | Log text stripped of line breaks and truncated (`logSafe`); email subjects flattened and RFC 2047-encoded |
| V1.3.4 | Sanitise user-supplied SVG | 2 | N/A | No SVG upload; charts are drawn by the app from numbers |
| V1.3.5 | Sanitise user-supplied template/Markdown/CSS | 2 | N/A | No user-supplied markup |
| V1.3.6 | SSRF protection with allowlists | 2 | ✅ | Wall Connector: LAN-only address check when parsing and again at dial time (`netguard.DialControl`), no redirects, no proxy; SMTP host entered by the signed-in owner, TLS required |
| V1.3.7 | No templates built from untrusted input | 2 | ✅ | Templates are embedded files parsed at start-up (`webui.Templates`, `notify/templates`) |
| V1.3.8 | JNDI injection | 2 | N/A | Not Java |
| V1.3.9 | Memcache injection | 2 | N/A | No memcache |
| V1.3.10 | Format-string safety | 2 | ✅ | Format strings are constants (`go vet` printf check in `make check`) |
| V1.3.11 | SMTP/IMAP injection | 2 | ✅ | Addresses parsed with `net/mail`; subject flattened and encoded; bodies from templates (`notify`, tested) |
| V1.4.1 | Memory-safe strings and buffers | 2 | ✅ | Go, built with `CGO_ENABLED=0`; no `unsafe` package; SQLite is the pure-Go `modernc.org/sqlite` |
| V1.4.2 | Prevent integer overflow | 2 | ✅ | Device numbers range-checked on decode (`wc:"range"` tags); form numbers bounded before use; Go integers do not wrap into memory errors |
| V1.4.3 | Release memory; no dangling pointers | 2 | ✅ | Garbage-collected; `make soak` checks the poller for goroutine and heap growth |
| V1.5.1 | Safe XML parser configuration (XXE) | 1 | N/A | No XML parsing |
| V1.5.2 | Safe deserialisation | 2 | ✅ | Only `encoding/json` into typed structs; no `gob`, YAML or polymorphic types |

## V2 Validation and Business Logic

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V2.1.1 | Documented input validation rules | 1 | ✅ | [controls](controls.md) § Input validation rules |
| V2.1.2 | Documented combined-field consistency rules | 2 | ✅ | [controls](controls.md) § Input validation rules |
| V2.1.3 | Documented business-logic limits | 2 | ✅ | [controls](controls.md) § Business-logic limits |
| V2.2.1 | Positive validation of all input | 1 | ✅ | Allowlists and ranges for every form field and device value ([controls](controls.md)) |
| V2.2.2 | Validation at a trusted server layer | 1 | ✅ | All checks in Go; HTML attributes are convenience only |
| V2.2.3 | Combined data items are reasonable | 2 | ✅ | Max current ≤ 80 % of the breaker; repeat ≥ 15 min; retention reductions need confirmation |
| V2.3.1 | Flows run in the expected order | 1 | ✅ | Setup requires a valid, unexpired one-time token before a password can be set; setup is refused once a password exists |
| V2.3.2 | Business-logic limits enforced | 2 | ✅ | Limits in [controls](controls.md) enforced in code (throttle, poll-now gap, alert cooldowns) |
| V2.3.3 | Transactions for multi-step operations | 2 | ✅ | `store.withTx` for snapshots, alert state, rates, retention pruning, notifications, auth changes |
| V2.3.4 | Locking for limited resources | 2 | N/A | No limited-quantity resources |
| V2.4.1 | Anti-automation for costly functions | 2 | 🟡 | Login, setup, poll-now and alert email are limited; **Send test email** and **Test connection** are not (signed-in owner only, CSRF-protected): accepted low risk |

## V3 Web Frontend Security

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V3.2.1 | Prevent rendering in the wrong context | 1 | ✅ | Correct `Content-Type` everywhere, `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`, CSV/backup/certificate as attachments |
| V3.2.2 | Text rendered with safe functions | 1 | ✅ | Browser JS uses `textContent` only; live data is pre-formatted by Go (`DeviceCard`) |
| V3.3.1 | Cookies Secure with `__Host-`/`__Secure-` prefix | 1 | ✅ | Session, form and (from this version) theme cookies use `__Host-` over HTTPS (`TestSetupFlow`, `TestThemeCookie`) |
| V3.3.2 | SameSite set per purpose | 2 | ✅ | All cookies `SameSite=Strict` |
| V3.3.3 | `__Host-` prefix unless shared | 2 | ✅ | All cookies use `__Host-` over HTTPS |
| V3.3.4 | HttpOnly for tokens; tokens only via Set-Cookie | 2 | ✅ | Session and form cookies `HttpOnly`; tokens never in URLs or page scripts (the CSRF token is a hidden form field) |
| V3.4.1 | HSTS ≥ 1 year (subdomains at L2) | 1 | ⚠️ | Off by default because the default certificate is self-signed on a LAN (D12); `TCMON_HSTS=true` sends `max-age=31536000` without `includeSubDomains`, since the app is reached by IP or a single LAN host name |
| V3.4.2 | CORS origin fixed or allow-listed | 1 | ✅ | No CORS headers are sent; cross-origin reads are blocked by default |
| V3.4.3 | CSP with `object-src 'none'` and `base-uri 'none'` | 2 | ✅ | `default-src 'none'` (covers `object-src`), `base-uri 'none'`, no `unsafe-*`, Trusted Types (`TestSecurityHeadersEverywhere`) |
| V3.4.4 | `X-Content-Type-Options: nosniff` | 2 | ✅ | Every response (`securityHeaders`) |
| V3.4.5 | Referrer policy | 2 | ✅ | `Referrer-Policy: no-referrer` |
| V3.4.6 | CSP `frame-ancestors` | 2 | ✅ | `frame-ancestors 'none'` on every response, plus `X-Frame-Options: DENY` |
| V3.5.1 | Anti-forgery for cross-origin requests | 1 | ✅ | `http.CrossOriginProtection` (Fetch Metadata) and a per-session CSRF token on every state-changing request |
| V3.5.2 | CORS-preflight reliance | 1 | N/A | The app does not rely on preflight (see V3.5.1) |
| V3.5.3 | State changes only with unsafe methods | 1 | ✅ | All state changes are `POST` routes; `GET` routes only read |
| V3.5.4 | Separate apps on separate hostnames | 2 | ✅ | tcmon is served alone on its own host and port |
| V3.5.5 | Validate postMessage origins | 2 | N/A | No `postMessage` |
| V3.7.1 | Only supported client technologies | 2 | ✅ | Plain HTML, CSS and ES modules; no plugins |
| V3.7.2 | Redirects only to allow-listed hosts | 2 | ✅ | All redirects are to fixed internal paths |

## V4 API and Web Service

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V4.1.1 | Correct Content-Type with charset | 1 | ✅ | HTML, text, CSV and JS declare `charset=utf-8`; JSON and SSE are UTF-8 by definition |
| V4.1.2 | Only user-facing endpoints redirect HTTP→HTTPS | 2 | ✅ | No HTTP listener, so nothing redirects; plain HTTP only by explicit opt-in |
| V4.1.3 | Intermediary headers cannot be overridden | 2 | ✅ | `X-Forwarded-For` honoured only from `TCMON_TRUSTED_PROXIES`, right-most untrusted address (`TestLANOnlyAndHostCheck`) |
| V4.2.1 | Correct HTTP message boundaries (smuggling) | 2 | ✅ | Go `net/http` server; no proxying by the app |
| V4.3.1 | GraphQL query limits | 2 | N/A | No GraphQL |
| V4.3.2 | GraphQL introspection off | 2 | N/A | No GraphQL |
| V4.4.1 | WebSockets over TLS | 1 | N/A | No WebSockets (live updates use SSE over the same HTTPS session) |
| V4.4.2 | WebSocket Origin check | 2 | N/A | No WebSockets |
| V4.4.3 | Dedicated WebSocket tokens | 2 | N/A | No WebSockets |
| V4.4.4 | WebSocket tokens from the HTTPS session | 2 | N/A | No WebSockets |

## V5 File Handling

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V5.1.1 | Documented upload rules | 2 | N/A | No file uploads |
| V5.2.1 | Upload size limits | 1 | N/A | No file uploads (request bodies are capped at 64 KiB) |
| V5.2.2 | Upload type/magic-byte checks | 1 | N/A | No file uploads |
| V5.2.3 | Archive bomb checks | 2 | N/A | No archives accepted |
| V5.3.1 | Uploaded files never executed | 1 | N/A | No file uploads; static files are embedded in the binary |
| V5.3.2 | No user-controlled file paths | 1 | ✅ | File paths are internal (data directory, temporary backup directory); `/static/` serves only embedded files |
| V5.4.1 | Ignore user file names; set Content-Disposition | 2 | ✅ | Downloads use fixed or generated names (`tcmon-backup-YYYYMMDD-HHMM.db`, CSV, certificate) |
| V5.4.2 | Encode served file names | 2 | ✅ | File names are generated from digits and fixed text only |
| V5.4.3 | Antivirus scan of untrusted files | 2 | N/A | No files from untrusted sources are served |

## V6 Authentication

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V6.1.1 | Documented brute-force defences | 1 | ✅ | [controls](controls.md) § Business-logic limits |
| V6.1.2 | Documented context-specific words | 2 | ✅ | [controls](controls.md) § Context-specific words |
| V6.1.3 | Documented authentication pathways | 2 | ✅ | [controls](controls.md) § Authentication pathways |
| V6.2.1 | Minimum length ≥ 8 (15 recommended) | 1 | ✅ | Minimum 12 characters (`auth.MinPasswordLength`), chosen with the owner; long passphrases encouraged in the UI |
| V6.2.2 | Users can change their password | 1 | ✅ | Security page (`TestChangePasswordAndRevoke`) |
| V6.2.3 | Change requires current and new password | 1 | ✅ | `ChangePassword` verifies the current password |
| V6.2.4 | Check against the top 3000 passwords | 1 | ✅ | Embedded list of about 46 000 common passwords (≥ 8 characters, NCSC 100k list) |
| V6.2.5 | No composition rules | 1 | ✅ | Length and blocklists only (`auth.CheckPolicy`) |
| V6.2.6 | `type=password` fields | 1 | ✅ | All password inputs |
| V6.2.7 | Paste and password managers allowed | 1 | ✅ | No paste blocking; password fields use `autocomplete` hints |
| V6.2.8 | Password verified exactly as entered | 1 | ✅ | No truncation or case change; NFKC Unicode normalisation is applied identically when setting and verifying, as NIST SP 800-63B recommends |
| V6.2.9 | At least 64 characters allowed | 2 | ✅ | Up to 128 characters |
| V6.2.10 | No forced periodic rotation | 2 | ✅ | Passwords never expire |
| V6.2.11 | Context words enforced | 2 | ✅ | `auth.contextWords` ([controls](controls.md)) |
| V6.2.12 | Breached-password check | 2 | ✅ | Embedded breached-password list (offline; no external lookups by design) |
| V6.3.1 | Brute-force controls as documented | 1 | ✅ | Per-IP 5 and global 50 failures per 15 min (`TestLoginLogoutAndThrottle`) |
| V6.3.2 | No default accounts | 1 | ✅ | No accounts at all; the password is set at first run via a one-time token |
| V6.3.3 | MFA or combined factors | 2 | ⚠️ | Single password by owner requirement on a LAN-only app; passkeys are under Later / stretch |
| V6.3.4 | No undocumented authentication pathways | 2 | ✅ | [controls](controls.md) § Authentication pathways lists all four |
| V6.4.1 | Initial secrets random, short-lived, single use | 1 | ✅ | Setup token: 160-bit `crypto/rand`, 30 minutes, single use |
| V6.4.2 | No password hints or secret questions | 1 | ✅ | None |
| V6.4.3 | Secure password reset | 2 | ✅ | `tcmon reset-password` requires shell access to the container; no MFA to bypass |
| V6.4.4 | Identity proofing when an MFA factor is lost | 2 | N/A | No MFA |
| V6.5.1 | OTPs usable once | 2 | N/A | No OTP/lookup secrets |
| V6.5.2 | Hash low-entropy lookup secrets | 2 | N/A | No lookup secrets |
| V6.5.3 | CSPRNG for OTP seeds | 2 | N/A | No OTP |
| V6.5.4 | Minimum OTP entropy | 2 | N/A | No OTP |
| V6.5.5 | OTP lifetimes | 2 | N/A | No OTP |
| V6.6.1 | PSTN/SMS OTP restrictions | 2 | N/A | No SMS/phone authentication |
| V6.6.2 | Out-of-band codes bound to the request | 2 | N/A | No out-of-band authentication |
| V6.6.3 | Rate-limit out-of-band codes | 2 | N/A | No out-of-band authentication |
| V6.8.1 | No identity spoofing across IdPs | 2 | N/A | No identity providers |
| V6.8.2 | Validate assertion signatures | 2 | N/A | No JWT/SAML |
| V6.8.3 | SAML replay protection | 2 | N/A | No SAML |
| V6.8.4 | Check IdP authentication strength | 2 | N/A | No identity providers |

## V7 Session Management

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V7.1.1 | Documented timeouts with justification | 2 | ✅ | [controls](controls.md) § Sessions |
| V7.1.2 | Documented concurrent-session policy | 2 | ✅ | [controls](controls.md) § Sessions (not limited; visible and revocable) |
| V7.1.3 | Documented federated session management | 2 | N/A | No SSO/federation |
| V7.2.1 | Session verification on the backend | 1 | ✅ | Server-side session table; the cookie is a reference token |
| V7.2.2 | Dynamically generated session tokens | 1 | ✅ | Random token per sign-in; no static keys |
| V7.2.3 | Reference tokens ≥ 128 bits from a CSPRNG | 1 | ✅ | 256-bit `crypto/rand`; SHA-256 stored |
| V7.2.4 | New token on authentication | 1 | ✅ | New session at every sign-in; password change revokes all and issues a new one |
| V7.3.1 | Inactivity timeout | 2 | ✅ | 12 hours (`TestSessionsExpire`) |
| V7.3.2 | Absolute session lifetime | 2 | ✅ | 7 days (30 with "keep me signed in") |
| V7.4.1 | Terminated sessions unusable | 1 | ✅ | Deleted server-side on sign-out and expiry; SSE streams end on revocation (`TestLoginLogoutAndThrottle`) |
| V7.4.2 | Sessions end when the account is disabled | 1 | N/A | Single owner; no accounts to disable (a password reset revokes all sessions) |
| V7.4.3 | Option to end other sessions after a credential change | 2 | ✅ | A password change signs out all other sessions automatically |
| V7.4.4 | Visible sign-out on every authenticated page | 2 | ✅ | **Sign out** in the header of the layout |
| V7.4.5 | Administrators can end sessions | 2 | ✅ | **Sign out everywhere** on the Security page |
| V7.5.1 | Re-authentication before changing auth attributes | 2 | ✅ | The only such attribute is the password, which needs the current password |
| V7.5.2 | View and end individual sessions after re-authentication | 2 | 🟡 | The Security page shows how many sessions are active and can end all of them, without a per-session list or re-authentication: deferred (single owner) |
| V7.6.1 | RP/IdP session coordination | 2 | N/A | No identity provider |
| V7.6.2 | Sessions need explicit user action | 2 | ✅ | Sessions are created only by signing in or completing setup |

## V8 Authorization

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V8.1.1 | Documented function/data access rules | 1 | ✅ | [controls](controls.md) § Authorization |
| V8.1.2 | Documented field-level rules | 2 | N/A | Single owner; no field-level restrictions exist |
| V8.2.1 | Function-level access control | 1 | ✅ | `authed` on every route except sign-in, setup, health and static files (route table in `internal/web/server.go`) |
| V8.2.2 | Object-level access control (IDOR) | 1 | N/A | All objects belong to the one owner |
| V8.2.3 | Field-level access control | 2 | N/A | Single owner |
| V8.3.1 | Authorization enforced on the server | 1 | ✅ | Session and CSRF checks in Go; nothing relies on client code |
| V8.4.1 | Cross-tenant controls | 2 | N/A | Not multi-tenant |

## V9 Self-contained Tokens

N/A — all 7 Level 1–2 requirements. No self-contained tokens (JWT, PASETO); sessions use server-side reference tokens.


## V10 OAuth and OIDC

N/A — all 29 Level 1–2 requirements. No OAuth or OpenID Connect, as client, resource server or provider.


## V11 Cryptography

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V11.1.1 | Key management policy and lifecycle | 2 | ✅ | [controls](controls.md) § Cryptographic inventory and key lifecycle |
| V11.1.2 | Cryptographic inventory | 2 | ✅ | [controls](controls.md) § Cryptographic inventory and key lifecycle |
| V11.2.1 | Industry-validated implementations | 2 | ✅ | Go standard library and `golang.org/x/crypto` only |
| V11.2.2 | Crypto agility | 2 | ✅ | Versioned secret format (`formatV1`); Argon2id parameters stored per hash with transparent rehash; TLS settings from Go defaults |
| V11.2.3 | ≥ 128-bit security | 2 | ✅ | AES-256-GCM, ECDSA P-256, SHA-256, 256-bit tokens |
| V11.3.1 | No ECB or weak padding | 1 | ✅ | Only AES-GCM |
| V11.3.2 | Approved ciphers and modes only | 1 | ✅ | AES-256-GCM |
| V11.3.3 | Authenticated encryption | 2 | ✅ | AES-GCM with associated data |
| V11.4.1 | Approved hash functions only | 1 | ✅ | SHA-256; no MD5 or SHA-1 |
| V11.4.2 | Password hashing KDF with current parameters | 2 | ✅ | Argon2id m = 64 MiB, t = 3, p = 1 (above OWASP's minimum) |
| V11.4.3 | Collision-resistant hashes ≥ 256 bits | 2 | ✅ | SHA-256 |
| V11.4.4 | KDF with stretching for password-derived keys | 2 | N/A | No keys are derived from passwords; `secret.key` is random |
| V11.5.1 | CSPRNG, ≥ 128 bits, for unguessable values | 2 | ✅ | `crypto/rand` for every token, key and nonce; `math/rand` only for poll-timing jitter |
| V11.6.1 | Approved key generation and signatures | 2 | ✅ | ECDSA P-256 via `crypto/ecdsa` for the self-signed certificate |

## V12 Secure Communication

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V12.1.1 | Only current TLS versions | 1 | ✅ | TLS 1.3 minimum; 1.2 by opt-in (`TestTLSVersionsAndServe`) |
| V12.1.2 | Recommended cipher suites | 2 | ✅ | Go defaults (forward-secret AEAD suites), hybrid post-quantum key exchange X25519MLKEM768 |
| V12.1.3 | Validate mTLS client certificates | 2 | N/A | No client certificates |
| V12.2.1 | TLS for external HTTP services | 1 | ✅ | HTTPS by default; SMTP always over TLS |
| V12.2.2 | Publicly trusted certificates externally | 1 | ⚠️ | LAN-only app with a self-signed certificate by owner decision D12; own certificates supported via `TCMON_TLS=file` |
| V12.3.1 | Encrypted protocols for all connections | 2 | ⚠️ | The Wall Connector only offers plain HTTP on the LAN; its responses are treated as untrusted input (accepted risk in the threat model). Everything else uses TLS |
| V12.3.2 | TLS clients validate certificates | 2 | ✅ | SMTP always verifies; HTTPS Wall Connector addresses are verified too |
| V12.3.3 | TLS between internal services | 2 | N/A | Single process; no internal HTTP services |
| V12.3.4 | Trusted certificates between internal services | 2 | N/A | No internal services |

## V13 Configuration

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V13.1.1 | Documented communication needs | 2 | ✅ | [controls](controls.md) § Communication inventory |
| V13.2.1 | Authenticated backend connections | 2 | N/A | Embedded SQLite in the same process; no backend services |
| V13.2.2 | Least privilege between components | 2 | ✅ | Runs as UID 568 with no capabilities, read-only root file system, no-new-privileges; only `/data` is writable |
| V13.2.3 | No default service credentials | 2 | ✅ | None exist; the Gmail app password is entered by the owner |
| V13.2.4 | Allowlist for outbound communication | 2 | ✅ | Wall Connector limited to LAN addresses at dial time; SMTP and the optional dead-man's-switch ping to owner-configured hosts only |
| V13.2.5 | Server allowlist for loaded resources | 2 | ✅ | Static files are embedded; nothing is loaded from elsewhere |
| V13.3.1 | Secrets management solution | 2 | ⚠️ | No vault on a home NAS: credentials are encrypted with a separate key file (mode 0600, or `TCMON_SECRET_KEY_FILE` from a secrets mount); passwords are refused as environment variables |
| V13.3.2 | Least-privilege access to secrets | 2 | ✅ | Key and certificate files mode 0600, owned by the app user |
| V13.4.1 | No source-control metadata deployed | 1 | ✅ | Distroless image contains only the binary |
| V13.4.2 | Debug modes off | 2 | ✅ | No debug endpoints or profiler; debug logging only with `TCMON_LOG_LEVEL=debug` |
| V13.4.3 | No directory listings | 2 | ✅ | Fixed in this version: `/static/` serves files only (`TestSecurityHeadersEverywhere`) |
| V13.4.4 | HTTP TRACE not supported | 2 | ✅ | Routes are method-specific; anything else gets 404/405 |
| V13.4.5 | Docs and monitoring endpoints not exposed | 2 | ✅ | Only `/healthz` and `/readyz`, which return `ok`/`ready` |

## V14 Data Protection

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V14.1.1 | Sensitive data classified | 2 | ✅ | [controls](controls.md) § Sensitive data classification |
| V14.1.2 | Protection requirements per class | 2 | ✅ | [controls](controls.md) § Sensitive data classification |
| V14.2.1 | No sensitive data in URLs | 1 | ✅ | Tokens and passwords only in bodies and cookies |
| V14.2.2 | Not cached in server components | 2 | ✅ | `Cache-Control: no-store` on every non-static response |
| V14.2.3 | Not sent to untrusted parties | 2 | ✅ | No trackers, analytics or third-party resources |
| V14.2.4 | Controls implemented per class | 2 | ✅ | Encryption, masking, retention and logging as in [controls](controls.md) |
| V14.3.1 | Client data cleared after sign-out | 1 | ✅ | Pages are `no-store`; the browser keeps only the theme preference |
| V14.3.2 | Anti-caching headers | 2 | ✅ | `Cache-Control: no-store, no-cache, must-revalidate` |
| V14.3.3 | No sensitive data in browser storage | 2 | ✅ | Only the theme preference (cookie and `localStorage`) |

## V15 Secure Coding and Architecture

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V15.1.1 | Documented remediation time frames | 1 | ✅ | [controls](controls.md) § Dependencies and remediation |
| V15.1.2 | SBOM of third-party components | 2 | ✅ | SBOM published with every release; dependencies in `go.sum`/`package-lock.json` |
| V15.1.3 | Documented resource-intensive functions | 2 | ✅ | [controls](controls.md) § Resource-intensive functions |
| V15.2.1 | Components within remediation time frames | 1 | ✅ | govulncheck, Grype and dependency review fail CI on known vulnerabilities; Dependabot weekly |
| V15.2.2 | Availability defences for costly functions | 2 | ✅ | As documented (timeouts, intervals, throttles, bounded ranges) |
| V15.2.3 | No test or sample code in production | 2 | ✅ | The image holds one binary; the simulator and mocks are separate binaries/packages not shipped |
| V15.3.1 | Return only required fields | 1 | ✅ | Pages and JSON are built from view models (`DeviceCard`, series points); the device serial is masked |
| V15.3.2 | Do not follow redirects from external calls | 2 | ✅ | Wall Connector client refuses redirects (`ErrRedirect`) |
| V15.3.3 | Mass-assignment protection | 2 | ✅ | Handlers read named form fields into explicit structs; no generic binding |
| V15.3.4 | Correct client IP from trusted proxies only | 2 | ✅ | `clientIP`: `X-Forwarded-For` only from `TCMON_TRUSTED_PROXIES` |
| V15.3.5 | Strict types and comparisons | 2 | ✅ | Go's static typing; constant-time comparison for tokens |
| V15.3.6 | No JavaScript prototype pollution | 2 | ✅ | Browser JS never merges untrusted objects; data comes pre-formatted from the server |
| V15.3.7 | HTTP parameter pollution | 2 | ✅ | State-changing handlers read the body only (`PostFormValue`) |

## V16 Security Logging and Error Handling

| ID | Requirement (paraphrased) | L | Status | Evidence |
|---|---|---|---|---|
| V16.1.1 | Logging inventory | 2 | ✅ | [controls](controls.md) § Logging inventory |
| V16.2.1 | Log metadata: when, where, who, what | 2 | ✅ | JSON logs with time, event, path, status and client IP; audit entries with time, action and IP |
| V16.2.2 | Synchronised time; UTC or explicit offset | 2 | ✅ | Container clock from the host; timestamps include the UTC offset |
| V16.2.3 | Logs only where documented | 2 | ✅ | stdout and the database, as in the inventory |
| V16.2.4 | Common, machine-readable log format | 2 | ✅ | JSON via `log/slog` |
| V16.2.5 | Sensitive data handled per protection level | 2 | ✅ | `secrets.Secret` redacts itself; tests scan logs for passwords; serial/SSID/MAC never logged |
| V16.3.1 | All authentication operations logged | 2 | ✅ | Sign-in success/failure/throttling, setup, password changes and resets, sign-outs, session revocation (`audit_log`) |
| V16.3.2 | Failed authorization logged | 2 | 🟡 | CSRF and cross-origin rejections (403) are logged at info; unauthenticated requests redirected to sign-in are logged only at debug: deferred |
| V16.3.3 | Security events and bypass attempts logged | 2 | ✅ | Audit log plus HTTP log for every 4xx/5xx (throttling, CSRF, host and LAN rejections) |
| V16.3.4 | Unexpected errors and TLS failures logged | 2 | ✅ | Poll, SMTP (including TLS) and render errors logged at error/warn; panics logged |
| V16.4.1 | Encode data against log injection | 2 | ✅ | Structured JSON; request-controlled text passed through `logSafe` |
| V16.4.2 | Logs protected from unauthorized access | 2 | ✅ | Only the host administrator can read container logs; the audit log is behind sign-in |
| V16.4.3 | Logs sent to a separate system | 2 | ⚠️ | Left to the host: Docker/TrueNAS log drivers can forward stdout; a home NAS usually has no SIEM |
| V16.5.1 | Generic error messages | 2 | ✅ | `auth.UserMessage`; generic 500 on panics; details only in logs |
| V16.5.2 | Secure operation when external resources fail | 2 | ✅ | Unreachable device → retries and an alert; failed email → retries and an in-app banner; nothing fails open |
| V16.5.3 | Fail securely; no fail-open | 2 | ✅ | Validation errors stop the action; invalid device fields never drive alerts; missing session → sign-in |

## V17 WebRTC

N/A — all 7 Level 1–2 requirements. No WebRTC.


## Automated checks

- `internal/web`: `TestSecurityHeadersEverywhere`, `TestLANOnlyAndHostCheck`,
  `TestSetupFlow`, `TestLoginLogoutAndThrottle`, `TestSessionsExpire`,
  `TestChangePasswordAndRevoke`, `TestEnvManagedPassword`, `TestCertificate`,
  `TestTLSVersionsAndServe`, `TestThemeCookie`, `TestJavaScriptBudget`.
- `e2e`: every page under the strict CSP with no violations, in Chromium,
  Firefox and WebKit.
- CI: ZAP baseline scan against the running server; CodeQL; govulncheck;
  Grype; dependency review; Scorecard; 10 fuzz targets (device data,
  alert rules, email composition, charging costs, form validation).
