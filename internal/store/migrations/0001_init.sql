-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 2 schema: devices, readings, raw payloads, rollups, device events,
-- poll log and settings. All timestamps are UTC Unix milliseconds.

CREATE TABLE devices (
    id                 INTEGER PRIMARY KEY,
    name               TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    address            TEXT    NOT NULL,
    allow_non_lan      INTEGER NOT NULL DEFAULT 0 CHECK (allow_non_lan IN (0, 1)),
    enabled            INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    poll_interval_s    INTEGER NOT NULL DEFAULT 3600 CHECK (poll_interval_s BETWEEN 60 AND 86400),
    plugged_interval_s INTEGER NOT NULL DEFAULT 300  CHECK (plugged_interval_s BETWEEN 60 AND 86400),
    fast_when_plugged  INTEGER NOT NULL DEFAULT 1 CHECK (fast_when_plugged IN (0, 1)),
    nominal_voltage_v  REAL    NOT NULL DEFAULT 240,
    nominal_hz         REAL    NOT NULL DEFAULT 60,
    breaker_a          REAL,
    max_current_a      REAL,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

CREATE TABLE device_info (
    device_id             INTEGER PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    firmware_version      TEXT    NOT NULL DEFAULT '',
    git_branch            TEXT    NOT NULL DEFAULT '',
    part_number           TEXT    NOT NULL DEFAULT '',
    serial_number         TEXT    NOT NULL DEFAULT '',
    web_service           TEXT    NOT NULL DEFAULT '',
    ieee1547_vf_trips_crc TEXT    NOT NULL DEFAULT '',
    ieee1547_ride_thru_crc TEXT   NOT NULL DEFAULT '',
    ieee1547_combined_crc TEXT    NOT NULL DEFAULT '',
    first_seen_at         INTEGER NOT NULL,
    last_seen_at          INTEGER NOT NULL
);

-- invalid_json: JSON array of field names the decoder flagged as invalid;
-- those columns must not be trusted (e.g. excluded from rollups and alerts).
CREATE TABLE readings_vitals (
    id                  INTEGER PRIMARY KEY,
    device_id           INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts                  INTEGER NOT NULL,
    contactor_closed    INTEGER NOT NULL,
    vehicle_connected   INTEGER NOT NULL,
    session_s           INTEGER,
    grid_v              REAL,
    grid_hz             REAL,
    vehicle_current_a   REAL,
    current_a_a         REAL,
    current_b_a         REAL,
    current_c_a         REAL,
    current_n_a         REAL,
    voltage_a_v         REAL,
    voltage_b_v         REAL,
    voltage_c_v         REAL,
    relay_k1_v          REAL,
    relay_k2_v          REAL,
    relay_coil_v        REAL,
    pcba_temp_c         REAL,
    handle_temp_c       REAL,
    mcu_temp_c          REAL,
    uptime_s            INTEGER,
    input_thermopile_uv INTEGER,
    prox_v              REAL,
    pilot_high_v        REAL,
    pilot_low_v         REAL,
    session_energy_wh   REAL,
    config_status       INTEGER,
    evse_state          INTEGER,
    alerts_json         TEXT    NOT NULL DEFAULT '[]',
    not_ready_json      TEXT    NOT NULL DEFAULT '[]',
    invalid_json        TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX readings_vitals_device_ts ON readings_vitals (device_id, ts);
CREATE INDEX readings_vitals_ts ON readings_vitals (ts);

CREATE TABLE readings_lifetime (
    id                      INTEGER PRIMARY KEY,
    device_id               INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts                      INTEGER NOT NULL,
    contactor_cycles        INTEGER,
    contactor_cycles_loaded INTEGER,
    alert_count             INTEGER,
    thermal_foldbacks       INTEGER,
    avg_startup_temp        REAL,
    charge_starts           INTEGER,
    energy_wh               INTEGER,
    connector_cycles        INTEGER,
    uptime_s                INTEGER,
    charging_time_s         INTEGER,
    invalid_json            TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX readings_lifetime_device_ts ON readings_lifetime (device_id, ts);
CREATE INDEX readings_lifetime_ts ON readings_lifetime (ts);

CREATE TABLE readings_wifi (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts              INTEGER NOT NULL,
    rssi            INTEGER,
    snr             INTEGER,
    signal_strength INTEGER,
    connected       INTEGER NOT NULL,
    internet        INTEGER NOT NULL,
    infra_ip        TEXT    NOT NULL DEFAULT '',
    invalid_json    TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX readings_wifi_device_ts ON readings_wifi (device_id, ts);
CREATE INDEX readings_wifi_ts ON readings_wifi (ts);

CREATE TABLE raw_payloads (
    id        INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts        INTEGER NOT NULL,
    endpoint  TEXT    NOT NULL,
    body      BLOB    NOT NULL
);
CREATE INDEX raw_payloads_ts ON raw_payloads (ts);
CREATE INDEX raw_payloads_device_ts ON raw_payloads (device_id, ts);

CREATE TABLE rollups_1h (
    device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    bucket_ts INTEGER NOT NULL,
    metric    TEXT    NOT NULL,
    min       REAL    NOT NULL,
    max       REAL    NOT NULL,
    avg       REAL    NOT NULL,
    count     INTEGER NOT NULL,
    PRIMARY KEY (device_id, bucket_ts, metric)
) WITHOUT ROWID;
CREATE INDEX rollups_1h_bucket ON rollups_1h (bucket_ts);

-- Device-reported changes detected by the poller (reboot, firmware change,
-- grid profile change, identity mismatch). Consumed by the alert engine.
CREATE TABLE device_events (
    id           INTEGER PRIMARY KEY,
    device_id    INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    kind         TEXT    NOT NULL,
    details_json TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX device_events_device_ts ON device_events (device_id, ts);
CREATE INDEX device_events_ts ON device_events (ts);

CREATE TABLE poll_log (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    ok          INTEGER NOT NULL CHECK (ok IN (0, 1)),
    attempt     INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    error       TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX poll_log_device_ts ON poll_log (device_id, ts);
CREATE INDEX poll_log_ts ON poll_log (ts);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
