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

## Conventions

- Every source file starts with the `SPDX-License-Identifier: AGPL-3.0-or-later`
  header and `Copyright (C) 2026 Brad Hager and contributors`.
- GitHub Actions are pinned by commit SHA (tag in a trailing comment).
- Fixtures must stay redacted; `internal/fixturecheck` enforces it.
- Record significant decisions as ADRs in `docs/adr/`.
