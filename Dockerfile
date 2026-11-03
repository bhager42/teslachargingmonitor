# syntax=docker/dockerfile:1
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Brad Hager and contributors
#
# Tesla Charger Monitoring (tcmon) container image.
#   docker build -t tcmon .
# Multi-arch (see .github/workflows/release.yml):
#   docker buildx build --platform linux/amd64,linux/arm64 .
# Base images are pinned by digest; Dependabot keeps them current.

# ---- build: cross-compiles on the build host's architecture ---------------
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=
# Set SOURCE_DATE_EPOCH (e.g. the commit time) for a reproducible build.
ARG SOURCE_DATE_EPOCH=0

ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
	DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)" && \
	GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -buildvcs=false \
		-ldflags "-s -w -buildid= \
		-X github.com/bhager42/teslachargingmonitor/internal/buildinfo.Version=${VERSION} \
		-X github.com/bhager42/teslachargingmonitor/internal/buildinfo.Commit=${COMMIT} \
		-X github.com/bhager42/teslachargingmonitor/internal/buildinfo.Date=${DATE}" \
		-o /out/tcmon ./cmd/tcmon && \
	mkdir -p /out/data

# ---- runtime: distroless static, no shell, no package manager -------------
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

ARG VERSION=dev
ARG COMMIT=
LABEL org.opencontainers.image.title="Tesla Charger Monitoring" \
	org.opencontainers.image.description="Self-hosted monitor and email alerts for the Tesla Universal Wall Connector" \
	org.opencontainers.image.source="https://github.com/bhager42/teslachargingmonitor" \
	org.opencontainers.image.url="https://github.com/bhager42/teslachargingmonitor" \
	org.opencontainers.image.documentation="https://github.com/bhager42/teslachargingmonitor/tree/main/docs" \
	org.opencontainers.image.licenses="AGPL-3.0-or-later" \
	org.opencontainers.image.vendor="Brad Hager and contributors" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${COMMIT}"

COPY --from=build /out/tcmon /tcmon
# /data is the only writable path: database, secret key and TLS certificate.
# 568:568 is the TrueNAS "apps" user; any UID works if it owns the mount.
COPY --from=build --chown=568:568 --chmod=0700 /out/data /data

ENV TCMON_DATA_DIR=/data \
	TCMON_LISTEN=:8443 \
	TZ=UTC

USER 568:568
VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
	CMD ["/tcmon", "healthcheck"]

ENTRYPOINT ["/tcmon"]
CMD ["serve"]
