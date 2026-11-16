-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 9 step 4: alerts about a Backup Gateway. Alert state, history and
-- snoozes gain a gateway_id next to device_id; exactly one of the two is
-- set (non-zero). The tables are rebuilt because SQLite cannot drop the
-- device foreign key in place; triggers keep the cascade on delete for both
-- Wall Connectors and Gateways. Existing rows are copied unchanged.

CREATE TABLE alert_state_new (
    rule_key   TEXT    NOT NULL,
    device_id  INTEGER NOT NULL DEFAULT 0,
    gateway_id INTEGER NOT NULL DEFAULT 0,
    state_json TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (rule_key, device_id, gateway_id),
    CHECK ((device_id = 0) != (gateway_id = 0))
) WITHOUT ROWID;
INSERT INTO alert_state_new (rule_key, device_id, state_json, updated_at)
    SELECT rule_key, device_id, state_json, updated_at FROM alert_state;
DROP TABLE alert_state;
ALTER TABLE alert_state_new RENAME TO alert_state;

CREATE TABLE alert_events_new (
    id         INTEGER PRIMARY KEY,
    rule_key   TEXT    NOT NULL,
    device_id  INTEGER NOT NULL DEFAULT 0,
    gateway_id INTEGER NOT NULL DEFAULT 0,
    ts         INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    value      REAL,
    notified   INTEGER NOT NULL CHECK (notified IN (0, 1)),
    acked_at   INTEGER,
    CHECK ((device_id = 0) != (gateway_id = 0))
);
INSERT INTO alert_events_new (id, rule_key, device_id, ts, kind, severity, message, value, notified, acked_at)
    SELECT id, rule_key, device_id, ts, kind, severity, message, value, notified, acked_at FROM alert_events;
DROP TABLE alert_events;
ALTER TABLE alert_events_new RENAME TO alert_events;
CREATE INDEX alert_events_device_ts ON alert_events (device_id, ts);
CREATE INDEX alert_events_gateway_ts ON alert_events (gateway_id, ts);
CREATE INDEX alert_events_ts ON alert_events (ts);

CREATE TABLE alert_snoozes_new (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL DEFAULT 0,
    gateway_id INTEGER NOT NULL DEFAULT 0,
    rule_key   TEXT    NOT NULL DEFAULT '',
    until_ts   INTEGER NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    CHECK ((device_id = 0) != (gateway_id = 0))
);
INSERT INTO alert_snoozes_new (id, device_id, rule_key, until_ts, reason, created_at)
    SELECT id, device_id, rule_key, until_ts, reason, created_at FROM alert_snoozes;
DROP TABLE alert_snoozes;
ALTER TABLE alert_snoozes_new RENAME TO alert_snoozes;
CREATE INDEX alert_snoozes_device ON alert_snoozes (device_id, until_ts);
CREATE INDEX alert_snoozes_gateway ON alert_snoozes (gateway_id, until_ts);

CREATE TRIGGER devices_delete_alerts AFTER DELETE ON devices BEGIN
    DELETE FROM alert_state WHERE device_id = OLD.id;
    DELETE FROM alert_events WHERE device_id = OLD.id;
    DELETE FROM alert_snoozes WHERE device_id = OLD.id;
END;

CREATE TRIGGER gateways_delete_alerts AFTER DELETE ON gateways BEGIN
    DELETE FROM alert_state WHERE gateway_id = OLD.id;
    DELETE FROM alert_events WHERE gateway_id = OLD.id;
    DELETE FROM alert_snoozes WHERE gateway_id = OLD.id;
END;
