<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# 0007 — Backup Gateway access and fixture capture

- **Status:** Accepted (2026-11-16)

## Context

Phase 9 (D27) reads a Powerwall 2 / Powerwall+ system through its Backup
Gateway 2 on the LAN. Unlike the Wall Connector, the Gateway's API needs a
login (the `customer` user and a password printed inside the Gateway door),
serves HTTPS with a self-signed certificate, is undocumented, and is
reported to lock out repeated failed logins. Its responses carry more
personal data than the Wall Connector's: the DIN (which contains the
serial number), battery and inverter serials, and the account's name and
email in the login response.

A probe on the owner's Gateway (firmware 26.34.2, 2026-11-16) confirmed
that the local login and the core endpoints still work, although the
Gateway's own web page now only refers to the Tesla app.

Step 9.0 needs real, redacted payloads before any client code is written,
in the same way Phase 0 captured the Wall Connector.

## Decision

These rules apply to the capture tool now and to `internal/gateway` (step
9.1) later.

- **One login, never an automatic retry.** A rejected login ends the
  capture run. The poller later backs off exponentially (5 min to 6 h) and
  raises `gateway_auth_failed`.
- **The password never appears on a command line or in the environment.**
  The capture tool reads it from standard input, hidden when stdin is a
  terminal. The app stores it via `secrets.Box`. The token and the login
  response's personal fields are never printed, logged or written.
- **Certificates are pinned (trust on first use).** The SHA-256 fingerprint
  of the Gateway's leaf certificate is shown and confirmed once, then every
  connection must present that certificate. Chain verification is replaced
  by the pin check, never simply turned off.
- **LAN only.** Connections go through `netguard.DialControl`, as for Wall
  Connectors.
- **Read only.** The only request that isn't a GET is the login.
- **Redaction is code, not sed.** `internal/gateway/redact` redacts by key
  (serial, DIN, email, names, tokens, addresses, locations, and anything
  nested under them) and by value (IPv4 outside the documentation ranges,
  MAC and email addresses, and identifiers learned from sensitive keys
  wherever they reappear). The tool refuses to write anything that fails
  `redact.Check`, and `internal/fixturecheck` runs the same check on every
  committed Gateway fixture. When in doubt, a value is redacted.
- **The capture tool is a development command** (`cmd/gwcapture`, run
  through `scripts/capture-gateway.sh`). It is not built into the
  container image.

## Consequences

- Each capture costs one login. A wrong password is visible at once and
  never escalates into a lockout.
- The redaction rules may over-redact fields that later turn out to be
  useful. Fixtures are re-captured rather than the rules loosened without
  review.
- A Gateway certificate change (for example after a factory reset) needs
  the owner to confirm the new fingerprint. In the app this becomes the
  `gateway_cert_changed` alert.
