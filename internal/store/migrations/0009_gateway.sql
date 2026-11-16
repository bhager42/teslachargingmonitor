-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 9 step 2: Tesla Backup Gateway (Powerwall 2 / Powerwall+) storage.
-- All timestamps are UTC Unix milliseconds. The Gateway's DIN and battery
-- serial numbers are never stored outside raw payloads.

-- address: host[:port] on the LAN. pin_sha256: the owner-confirmed
-- certificate fingerprint (hex). pending_pin_sha256: a different
-- certificate seen since; polling stops until the owner accepts it.
-- password_enc: the customer password sealed with secrets.Box.
-- backoff_*: the login back-off (ADR 0007), kept across restarts. Writes to
-- pending_pin and backoff_* do not touch updated_at, which restarts the
-- poller's worker.
CREATE TABLE gateways (
    id                  INTEGER PRIMARY KEY,
    name                TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    address             TEXT    NOT NULL,
    allow_non_lan       INTEGER NOT NULL DEFAULT 0 CHECK (allow_non_lan IN (0, 1)),
    enabled             INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    pin_sha256          TEXT    NOT NULL CHECK (length(pin_sha256) = 64),
    pending_pin_sha256  TEXT    NOT NULL DEFAULT '',
    password_enc        BLOB    NOT NULL,
    poll_interval_s     INTEGER NOT NULL DEFAULT 900 CHECK (poll_interval_s BETWEEN 60 AND 86400),
    charging_interval_s INTEGER NOT NULL DEFAULT 300 CHECK (charging_interval_s BETWEEN 60 AND 86400),
    backoff_failures    INTEGER NOT NULL DEFAULT 0,
    backoff_until       INTEGER NOT NULL DEFAULT 0,
    backoff_cause       TEXT    NOT NULL DEFAULT '',
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

-- What the Gateway reports about itself, updated on every successful poll.
-- first_full_pack_wh is the baseline for battery_capacity_drop.
CREATE TABLE gateway_info (
    gateway_id         INTEGER PRIMARY KEY REFERENCES gateways (id) ON DELETE CASCADE,
    firmware_version   TEXT    NOT NULL DEFAULT '',
    git_hash           TEXT    NOT NULL DEFAULT '',
    firmware_since_at  INTEGER NOT NULL,
    uptime_s           INTEGER,
    battery_count      INTEGER NOT NULL DEFAULT 0,
    full_pack_wh       REAL,
    first_full_pack_wh REAL,
    nominal_energy_kwh REAL,
    solar_rating_w     REAL,
    timezone           TEXT    NOT NULL DEFAULT '',
    real_mode          TEXT    NOT NULL DEFAULT '',
    backup_reserve_pct REAL,
    sitemaster_running INTEGER NOT NULL DEFAULT 0,
    connected_to_tesla INTEGER NOT NULL DEFAULT 0,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL
);

-- One row per successful poll. Power in W with the Gateway's signs (site < 0
-- exports, battery < 0 charges); energy columns are the lifetime counters in
-- Wh; soe_pct is the raw battery percentage (the app's is derived).
-- invalid_json lists fields the decoder flagged; they are stored as NULL.
CREATE TABLE readings_site (
    id                  INTEGER PRIMARY KEY,
    gateway_id          INTEGER NOT NULL REFERENCES gateways (id) ON DELETE CASCADE,
    ts                  INTEGER NOT NULL,
    solar_w             REAL,
    load_w              REAL,
    site_w              REAL,
    battery_w           REAL,
    solar_exported_wh   REAL,
    load_imported_wh    REAL,
    site_imported_wh    REAL,
    site_exported_wh    REAL,
    battery_imported_wh REAL,
    battery_exported_wh REAL,
    soe_pct             REAL,
    remaining_wh        REAL,
    full_pack_wh        REAL,
    grid_status         TEXT    NOT NULL DEFAULT '',
    invalid_json        TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX readings_site_gateway_ts ON readings_site (gateway_id, ts);
CREATE INDEX readings_site_ts ON readings_site (ts);

CREATE TABLE gateway_raw_payloads (
    id         INTEGER PRIMARY KEY,
    gateway_id INTEGER NOT NULL REFERENCES gateways (id) ON DELETE CASCADE,
    ts         INTEGER NOT NULL,
    endpoint   TEXT    NOT NULL,
    body       BLOB    NOT NULL
);
CREATE INDEX gateway_raw_payloads_ts ON gateway_raw_payloads (ts);
CREATE INDEX gateway_raw_payloads_gateway_ts ON gateway_raw_payloads (gateway_id, ts);

-- Gateway-reported changes detected by the poller (reboot, firmware change,
-- grid status change, certificate change). Consumed by the alert engine.
CREATE TABLE gateway_events (
    id           INTEGER PRIMARY KEY,
    gateway_id   INTEGER NOT NULL REFERENCES gateways (id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    kind         TEXT    NOT NULL,
    details_json TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX gateway_events_gateway_ts ON gateway_events (gateway_id, ts);
CREATE INDEX gateway_events_ts ON gateway_events (ts);

CREATE TABLE gateway_poll_log (
    id          INTEGER PRIMARY KEY,
    gateway_id  INTEGER NOT NULL REFERENCES gateways (id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    ok          INTEGER NOT NULL CHECK (ok IN (0, 1)),
    attempt     INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    error       TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX gateway_poll_log_gateway_ts ON gateway_poll_log (gateway_id, ts);
CREATE INDEX gateway_poll_log_ts ON gateway_poll_log (ts);

CREATE TABLE rollups_site_1h (
    gateway_id INTEGER NOT NULL REFERENCES gateways (id) ON DELETE CASCADE,
    bucket_ts  INTEGER NOT NULL,
    metric     TEXT    NOT NULL,
    min        REAL    NOT NULL,
    max        REAL    NOT NULL,
    avg        REAL    NOT NULL,
    count      INTEGER NOT NULL,
    PRIMARY KEY (gateway_id, bucket_ts, metric)
) WITHOUT ROWID;
CREATE INDEX rollups_site_1h_bucket ON rollups_site_1h (bucket_ts);
