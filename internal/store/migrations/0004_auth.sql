-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 5: single-password authentication, sessions and the audit log.

CREATE TABLE auth (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash       TEXT    NOT NULL,
    password_changed_at INTEGER NOT NULL
);

-- Only a SHA-256 of the session ID is stored.
CREATE TABLE web_sessions (
    id_hash      BLOB    PRIMARY KEY,
    csrf_token   TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    ip           TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT ''
) WITHOUT ROWID;
CREATE INDEX web_sessions_expires ON web_sessions (expires_at);

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    ip           TEXT    NOT NULL DEFAULT '',
    action       TEXT    NOT NULL,
    details_json TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_ts ON audit_log (ts);
