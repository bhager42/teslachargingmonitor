# 0001 — Go single static binary

- **Status:** Accepted (owner decision D9, 2026-11-02)

## Context
The app is a small LAN service that must run as a non-root, read-only
container on TrueNAS SCALE and other Docker hosts, with a minimal attack
surface and dependency footprint.

## Decision
Write the server in Go (toolchain pinned in `go.mod`), built with
`CGO_ENABLED=0 -trimpath` into one static binary that embeds templates,
static assets and SQL migrations. Prefer the standard library (`net/http`
routing, `html/template`, `log/slog`, `http.CrossOriginProtection`).

## Consequences
- Distroless/scratch runtime image, tiny size, no shell.
- Memory-safe language with first-class fuzzing and race detection.
- Contributors need Go; frontend stays plain HTML/CSS/JS (ADR 0003).
