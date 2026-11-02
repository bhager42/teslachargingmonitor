# CLAUDE.md

This repository will contain **wcmon**, a self-hosted, containerized monitor and
alerting web app for the Tesla **Universal Wall Connector** (primary target;
Gen 3 Wall Connector best-effort), licensed under AGPL-3.0.

- The authoritative plan is [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md).
  Read it before starting work and follow its phase order and working rules (§16).
- Unresolved owner decisions are listed in §15 of the plan; do not invent answers
  for them — use the documented defaults and note the assumption in the PR.
- Owner decisions already made are in §15.0 (e.g. UWC-only hardware; the Wall
  Connector address is configured in the Web GUI, never via env vars).
