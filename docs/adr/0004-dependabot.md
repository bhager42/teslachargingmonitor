# 0004 — Dependabot for dependency updates

- **Status:** Accepted (2026-11-02)

## Context
The plan allows Renovate or Dependabot. Renovate needs a GitHub App install;
Dependabot is built into GitHub.

## Decision
Use Dependabot (`.github/dependabot.yml`) for Go modules and GitHub Actions,
grouped weekly. Docker base-image digests are added in Phase 7. GitHub Actions
are pinned by commit SHA with the tag in a comment.

## Consequences
No extra app to install. If grouping or digest pinning proves insufficient,
switch to Renovate in a new ADR.
