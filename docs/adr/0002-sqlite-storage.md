# 0002 — SQLite (pure Go) for storage

- **Status:** Accepted (2026-11-02)

## Context
One device polled hourly (5 min while plugged in) yields only thousands of
rows per year. Users must not need to run a separate database.

## Decision
Use SQLite in WAL mode via `modernc.org/sqlite` (pure Go, no cgo), stored at
`/data/tcmon.db` on a host-path volume, with embedded forward-only migrations.

## Consequences
- Zero operational overhead; backup is a dataset snapshot or `VACUUM INTO`.
- Single writer; fine at this scale.
- `modernc.org/sqlite` is BSD-3-Clause, compatible with AGPL-3.0-or-later.
