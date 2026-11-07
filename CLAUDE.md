# CLAUDE.md

This repository will contain **Tesla Charger Monitoring** (`tcmon`), a self-hosted, containerized monitor and
alerting web app for the Tesla **Universal Wall Connector** (primary target;
Gen 3 Wall Connector best-effort), licensed under AGPL-3.0-or-later.

- The authoritative plan is [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md).
  Read it before starting work and follow its phase order and working rules (§16).
- Unresolved owner decisions are listed in §15 of the plan; do not invent answers
  for them — use the documented defaults and note the assumption in the PR.
- Owner decisions already made are in §15.0 (e.g. UWC-only hardware; the Wall
  Connector address is configured in the Web GUI, never via env vars; 60-min
  default polling, 5 min while plugged in; email via Gmail is the primary alert
  channel; LAN only with a self-signed HTTPS cert; Go; public repo).

## Commands

- `make check` — SPDX headers, golangci-lint, `go test -race` (run before every push)
- `make build` — builds `bin/tcmon`; `make vuln`, `make licenses` for dependency checks
- `scripts/capture.sh <ip> [label]` — capture redacted Wall Connector fixtures
- `make sim SCENARIO=<name> SPEED=<x>` — run the Wall Connector simulator (`internal/wcsim`)
- `make soak SOAK_POLLS=3000` — leak/soak test of the poller against the simulator
- `go run ./cmd/tcmon serve -data-dir ./data` with `tcmon device add -data-dir ./data -address 127.0.0.1:8099` (after `make sim`) for a local end-to-end run
- `make e2e` — Playwright + axe browser tests (WCAG 2.2 AA both themes, CSP, 320 px, live SSE) and the
  Lighthouse budget (Chromium; performance ≥ 95, accessibility and best practices 100) against the real binaries
- `make image` / `sudo make image-test` — build the container image and run
  `scripts/image-test.sh` (size < 25 MB, UID 568, no shell, hardened run)
- `make fuzz FUZZTIME=60s` — run all fuzz targets; commit any failing input under `testdata/fuzz` as a regression seed

## Conventions

- Every source file starts with the `SPDX-License-Identifier: AGPL-3.0-or-later`
  header and `Copyright (C) 2026 Brad Hager and contributors`.
- GitHub Actions are pinned by commit SHA (tag in a trailing comment).
- Fixtures must stay redacted; `internal/fixturecheck` enforces it.
- Record significant decisions as ADRs in `docs/adr/`.
- Device data is untrusted: decode with `wallconnector.Decode*` and honour the
  `Report` (fields in `Report.Invalid` must not drive alerts as if valid).
- Alert rules live in `internal/alerts/rules.go`; state transitions only in `step()`
  (engine.go) — keep it pure so table tests and `Preview` stay valid.
- Credentials: store only via `secrets.Box` (AES-GCM) and pass them around as
  `secrets.Secret`; never accept passwords as CLI arguments or log/return them.
- Never send email without TLS (STARTTLS required or implicit TLS); tests use
  `internal/notify/smtpmock`.
- Web: every page must work under the strict CSP (no inline script/style,
  Trusted Types); state-changing routes go through `authed` (session + CSRF);
  show only `auth.UserMessage` text to users. Templates live in `web/templates`.
- User-facing text lives in `internal/i18n/locales/en.json` (ADR 0006): templates
  (web pages and emails) use `{{t "key"}}`, `{{th "key_html"}}` (markup) and
  `{{tn "key" n}}` (plurals); Go code uses a package-level `tr` (`tr.T`, `tr.N`,
  `tr.Err` for validation errors);
  `TestCatalogCoverage` fails on unknown or unused keys. Never change wording
  as part of moving it.
- Browser JS lives in `web/static/js/app.mjs`: DOM APIs only (no innerHTML/eval —
  `TestJavaScriptBudget` enforces it and the 60 KB gzip budget). Live data is sent
  pre-formatted from Go (`DeviceCard`) so JS only sets `textContent`.
- Charging cost math lives in `internal/energy` (pure): costs come from lifetime
  `energy_wh` counter deltas, never from the device's session counter.
- Long-lived work started from a request (e.g. `poller.Reload`) must not inherit
  the request context.
- Schema changes go in a new `internal/store/migrations/NNNN_*.sql` file (numbered
  consecutively); never edit an applied migration.
- Only add status-code meanings to `internal/wallconnector/codes.go` that were
  observed on hardware; never guess.
