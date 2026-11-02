-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 4: notification channels and a persistent delivery queue.
-- Credentials live only in secret_enc (AES-256-GCM, key file outside the DB).

CREATE TABLE notify_channels (
    id                   INTEGER PRIMARY KEY,
    type                 TEXT    NOT NULL CHECK (type IN ('email')),
    name                 TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    enabled              INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    min_severity         TEXT    NOT NULL DEFAULT 'info',
    quiet_hours          TEXT    NOT NULL DEFAULT '',
    config_json          TEXT    NOT NULL,
    secret_enc           BLOB,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    last_success_at      INTEGER,
    last_error           TEXT    NOT NULL DEFAULT '',
    last_error_at        INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE notify_deliveries (
    id              INTEGER PRIMARY KEY,
    channel_id      INTEGER NOT NULL REFERENCES notify_channels (id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    next_attempt_at INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    last_error      TEXT    NOT NULL DEFAULT '',
    sent_at         INTEGER,
    subject         TEXT    NOT NULL,
    message_json    TEXT    NOT NULL,
    alert_event_ids TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX notify_deliveries_due ON notify_deliveries (status, next_attempt_at);
CREATE INDEX notify_deliveries_channel ON notify_deliveries (channel_id, created_at);
CREATE INDEX notify_deliveries_created ON notify_deliveries (created_at);
