// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// PasswordHash returns the stored password hash (PHC string).
func (s *Store) PasswordHash(ctx context.Context) (string, time.Time, error) {
	var h string
	var changed int64
	err := s.db.QueryRowContext(ctx, "SELECT password_hash, password_changed_at FROM auth WHERE id = 1").Scan(&h, &changed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, ErrNotFound
	}
	return h, fromMS(changed), err
}

// SetPasswordHash stores the password hash and revokes every session.
func (s *Store) SetPasswordHash(ctx context.Context, hash string, now time.Time) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth (id, password_hash, password_changed_at) VALUES (1, ?, ?)
			ON CONFLICT (id) DO UPDATE SET password_hash = excluded.password_hash,
			password_changed_at = excluded.password_changed_at`, hash, ms(now)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM web_sessions")
		return err
	})
}

// UpdatePasswordHash replaces the hash without touching sessions (used for
// transparent re-hashing with stronger parameters after a login).
func (s *Store) UpdatePasswordHash(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE auth SET password_hash = ? WHERE id = 1", hash)
	return err
}

// WebSession is a signed-in browser session.
type WebSession struct {
	IDHash    []byte
	CSRFToken string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

// CreateSession stores a new session.
func (s *Store) CreateSession(ctx context.Context, ws WebSession) error {
	if r := []rune(ws.UserAgent); len(r) > 200 {
		ws.UserAgent = string(r[:200])
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions (id_hash, csrf_token, created_at, last_seen_at, expires_at,
		ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`, ws.IDHash, ws.CSRFToken, ms(ws.CreatedAt), ms(ws.LastSeen),
		ms(ws.ExpiresAt), ws.IP, ws.UserAgent)
	return err
}

// Session returns a session by ID hash.
func (s *Store) Session(ctx context.Context, idHash []byte) (WebSession, error) {
	var ws WebSession
	var c, l, e int64
	err := s.db.QueryRowContext(ctx, `SELECT id_hash, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent
		FROM web_sessions WHERE id_hash = ?`, idHash).Scan(&ws.IDHash, &ws.CSRFToken, &c, &l, &e, &ws.IP, &ws.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return ws, ErrNotFound
	}
	ws.CreatedAt, ws.LastSeen, ws.ExpiresAt = fromMS(c), fromMS(l), fromMS(e)
	return ws, err
}

// TouchSession records activity.
func (s *Store) TouchSession(ctx context.Context, idHash []byte, now time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE web_sessions SET last_seen_at = ? WHERE id_hash = ?", ms(now), idHash)
	return err
}

// DeleteSession signs one session out.
func (s *Store) DeleteSession(ctx context.Context, idHash []byte) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM web_sessions WHERE id_hash = ?", idHash)
	return err
}

// DeleteOtherSessions signs out every session except keep (nil = all).
func (s *Store) DeleteOtherSessions(ctx context.Context, keep []byte) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM web_sessions WHERE id_hash != ?", keep)
	if keep == nil {
		res, err = s.db.ExecContext(ctx, "DELETE FROM web_sessions")
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountSessions returns the number of active sessions.
func (s *Store) CountSessions(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM web_sessions WHERE expires_at > ?", ms(now)).Scan(&n)
	return n, err
}

// DeleteExpiredSessions removes expired sessions.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM web_sessions WHERE expires_at <= ?", ms(now))
	return err
}

// AuditEntry is one security-relevant action.
type AuditEntry struct {
	ID      int64
	TS      time.Time
	IP      string
	Action  string
	Details map[string]string
}

// Audit records an action.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if e.Details == nil {
		e.Details = map[string]string{}
	}
	b, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO audit_log (ts, ip, action, details_json) VALUES (?, ?, ?, ?)",
		ms(e.TS), e.IP, e.Action, string(b))
	return err
}

// AuditLog returns recent entries, newest first.
func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, ts, ip, action, details_json FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		var d string
		if err := rows.Scan(&e.ID, &ts, &e.IP, &e.Action, &d); err != nil {
			return nil, err
		}
		e.TS = fromMS(ts)
		if err := json.Unmarshal([]byte(d), &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
