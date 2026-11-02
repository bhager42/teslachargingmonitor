-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 3: alert engine. Rule defaults live in code; this table only holds
-- the owner's overrides. device_id 0 means "all devices".

CREATE TABLE alert_rule_overrides (
    rule_key        TEXT    NOT NULL,
    device_id       INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    params_json     TEXT    NOT NULL DEFAULT '{}',
    for_s           INTEGER NOT NULL CHECK (for_s >= 0),
    cooldown_s      INTEGER NOT NULL CHECK (cooldown_s >= 0),
    repeat_s        INTEGER NOT NULL CHECK (repeat_s >= 0),
    min_samples     INTEGER NOT NULL CHECK (min_samples BETWEEN 1 AND 100),
    notify_resolved INTEGER NOT NULL CHECK (notify_resolved IN (0, 1)),
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (rule_key, device_id)
) WITHOUT ROWID;

-- Per (rule, device) state machine, persisted so restarts don't re-alert.
CREATE TABLE alert_state (
    rule_key   TEXT    NOT NULL,
    device_id  INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    state_json TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (rule_key, device_id)
) WITHOUT ROWID;

-- kind: firing | escalated | repeat | resolved | event
-- notified: 0 when suppressed (cooldown, snooze)
CREATE TABLE alert_events (
    id        INTEGER PRIMARY KEY,
    rule_key  TEXT    NOT NULL,
    device_id INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    ts        INTEGER NOT NULL,
    kind      TEXT    NOT NULL,
    severity  TEXT    NOT NULL,
    message   TEXT    NOT NULL,
    value     REAL,
    notified  INTEGER NOT NULL CHECK (notified IN (0, 1)),
    acked_at  INTEGER
);
CREATE INDEX alert_events_device_ts ON alert_events (device_id, ts);
CREATE INDEX alert_events_ts ON alert_events (ts);

-- Snoozes / maintenance mode. rule_key '' means every rule of the device.
CREATE TABLE alert_snoozes (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    rule_key   TEXT    NOT NULL DEFAULT '',
    until_ts   INTEGER NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX alert_snoozes_device ON alert_snoozes (device_id, until_ts);
