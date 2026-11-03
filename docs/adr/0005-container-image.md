<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# 0005 — Container image and release pipeline

- **Status:** Accepted (2026-11-03)

## Context

Phase 7 ships tcmon as a container for TrueNAS SCALE 25.10+ and plain Docker
(plan §11). The image must be small, run as a non-root user (TrueNAS `apps`,
568), work read-only, and be verifiable by users.

## Decision

- **Runtime base:** `gcr.io/distroless/static-debian13:nonroot`, pinned by
  digest. The binary is static (`CGO_ENABLED=0`, pure-Go SQLite), so no libc
  is needed. Distroless provides CA certificates (Gmail TLS) and tzdata (`TZ`),
  and has no shell or package manager. Debian 13 replaces the plan's
  debian12 because it is the current stable base.
- **Builder:** `golang:<toolchain>-alpine` pinned by digest, cross-compiling
  on the build host (`--platform=$BUILDPLATFORM`), so arm64 builds need no
  emulation. The build is reproducible: `-trimpath`, `-buildid=`, no VCS
  stamping, and the build date comes from `SOURCE_DATE_EPOCH` (the commit time).
- **Data:** a single writable `/data` (owned 568:568 in the image so a named
  volume inherits it). On TrueNAS the YAML uses a named volume (`tcmon-data`)
  that TrueNAS keeps on its apps pool, so the user enters no path and sets no
  permissions. Mounting a dataset of the user's own is documented as an
  option for dataset snapshots.
- **Vulnerability gate:** Grype (`anchore/scan-action`), failing on High or
  Critical findings that have a fix. The plan allowed Trivy or Grype; Grype
  runs from a single pinned action and can be swapped later without
  changing the image.
- **Release:** on a `vX.Y.Z` tag, build `linux/amd64` and `linux/arm64`,
  test and scan, push to GHCR with BuildKit SBOM and SLSA provenance
  (`mode=max`), sign the digest with cosign (keyless, GitHub OIDC), add a
  GitHub build-provenance attestation, and create a GitHub release that
  names the digest. Tags: `X.Y.Z`, `X.Y`, and `latest` (not for
  pre-releases).
- **Tests:** `scripts/image-test.sh` checks size, user, entrypoint,
  healthcheck, labels, the absence of a shell, tzdata, CA certificates, a
  hardened read-only run, HTTPS `/healthz` with the pinned certificate, the
  setup token in the log, and an arbitrary UID owning `/data`. CI also runs
  `docker compose up --wait` with `deploy/compose.yaml`.

## Consequences

- Users cannot open a shell in the container (TrueNAS's app **Shell** button
  does nothing useful); maintenance commands run as
  `docker exec tcmon /tcmon …`.
- The image size target (< 25 MB) is measured on the unpacked filesystem;
  the binary is about 16 MB, the base about 6 MB.
- Base-image digests are updated by Dependabot (`docker` ecosystem).
