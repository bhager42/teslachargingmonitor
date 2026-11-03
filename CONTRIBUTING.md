# Contributing

Thanks for your interest! This project follows the phased roadmap in
[docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md); please read it (in
particular §16, "Working rules") before opening a pull request.

## Ground rules

- **License:** contributions are accepted under AGPL-3.0-or-later.
- **DCO sign-off:** every commit must carry a `Signed-off-by:` line
  (`git commit -s`), certifying the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/).
  No CLA is required.
- **SPDX header:** every source file starts with
  ```
  // SPDX-License-Identifier: AGPL-3.0-or-later
  // Copyright (C) 2026 Brad Hager and contributors
  ```
  (use the comment syntax of the file type). `make headers` checks this.
- **No personal identifiers:** never commit real serial numbers, MAC
  addresses, SSIDs, IP addresses, passwords or keys. Use
  `scripts/capture.sh`, which redacts fixtures; `make test` verifies it.
- **Dependencies:** prefer the Go standard library. A new dependency needs a
  one-line justification in the PR and must pass `make licenses` and
  `make vuln`.
- **Security controls are not negotiable:** never weaken a header, cookie flag,
  rate limit or container hardening setting to make a test pass.

## Workflow

Install golangci-lint with the project toolchain (a binary built with an older
Go refuses to lint this module):

```bash
GOTOOLCHAIN=go1.27.3 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

1. Create a branch, make focused changes with tests and docs.
2. Run `make check` (and `make vuln` when dependencies change).
3. Open a pull request using the template; CI must be green.

## Releasing

Releases are built only by `.github/workflows/release.yml`. Either:

- **Actions** → **Release** → **Run workflow** on `main`, and enter the
  version without the `v` (for example `0.7.0`). The workflow builds, tests,
  scans, publishes, signs, and then creates the tag `v0.7.0` and the GitHub
  release on the commit it built. Or:
- push an annotated tag `vX.Y.Z` on `main`.

A version with a suffix (`1.0.0-rc.1`) is a pre-release and does not move
the `latest` image tag.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
