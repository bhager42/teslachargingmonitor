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
	"fmt"
	"time"
)

// NotifyChannel is a configured notification channel. Config holds the
// channel type's non-secret JSON; SecretEnc its encrypted credentials.
type NotifyChannel struct {
	ID                  int64
	Type                string
	Name                string
	Enabled             bool
	MinSeverity         string
	QuietHours          string // "HH:MM-HH:MM" or ""
	Digest              bool   // receives the weekly digest (D19)
	Config              []byte
	SecretEnc           []byte
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastSuccess         *time.Time
	LastError           string
	LastErrorAt         *time.Time
	ConsecutiveFailures int
}

const channelCols = `id, type, name, enabled, min_severity, quiet_hours, config_json, secret_enc, created_at,
	updated_at, last_success_at, last_error, last_error_at, consecutive_failures, digest`

func optTime(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := fromMS(n.Int64)
	return &t
}

func scanChannel(sc interface{ Scan(...any) error }) (NotifyChannel, error) {
	var c NotifyChannel
	var cfg string
	var created, updated int64
	var lastOK, lastErrAt sql.NullInt64
	err := sc.Scan(&c.ID, &c.Type, &c.Name, &c.Enabled, &c.MinSeverity, &c.QuietHours, &cfg, &c.SecretEnc,
		&created, &updated, &lastOK, &c.LastError, &lastErrAt, &c.ConsecutiveFailures, &c.Digest)
	c.Config = []byte(cfg)
	c.CreatedAt, c.UpdatedAt = fromMS(created), fromMS(updated)
	c.LastSuccess, c.LastErrorAt = optTime(lastOK), optTime(lastErrAt)
	return c, err
}

// CreateNotifyChannel inserts a channel (validated by the caller).
func (s *Store) CreateNotifyChannel(ctx context.Context, c NotifyChannel, now time.Time) (NotifyChannel, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO notify_channels (type, name, enabled, min_severity, quiet_hours,
		config_json, secret_enc, created_at, updated_at, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Type, c.Name, b2i(c.Enabled), c.MinSeverity, c.QuietHours, string(c.Config), c.SecretEnc, ms(now), ms(now),
		b2i(c.Digest))
	if err != nil {
		return NotifyChannel{}, fmt.Errorf("store: creating channel: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return NotifyChannel{}, err
	}
	return s.NotifyChannel(ctx, id)
}

// UpdateNotifyChannel saves a channel's settings (matched by ID).
func (s *Store) UpdateNotifyChannel(ctx context.Context, c NotifyChannel, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE notify_channels SET name = ?, enabled = ?, min_severity = ?,
		quiet_hours = ?, config_json = ?, secret_enc = ?, updated_at = ?, digest = ? WHERE id = ?`,
		c.Name, b2i(c.Enabled), c.MinSeverity, c.QuietHours, string(c.Config), c.SecretEnc, ms(now), b2i(c.Digest), c.ID)
	if err != nil {
		return fmt.Errorf("store: updating channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNotifyChannel removes a channel and its delivery log.
func (s *Store) DeleteNotifyChannel(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM notify_channels WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// NotifyChannel returns one channel.
func (s *Store) NotifyChannel(ctx context.Context, id int64) (NotifyChannel, error) {
	c, err := scanChannel(s.db.QueryRowContext(ctx, "SELECT "+channelCols+" FROM notify_channels WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return NotifyChannel{}, ErrNotFound
	}
	return c, err
}

// NotifyChannels returns all channels ordered by ID.
func (s *Store) NotifyChannels(ctx context.Context) ([]NotifyChannel, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+channelCols+" FROM notify_channels ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []NotifyChannel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecordChannelResult updates a channel's health after a delivery attempt.
func (s *Store) RecordChannelResult(ctx context.Context, id int64, ok bool, errText string, now time.Time) error {
	var err error
	if ok {
		_, err = s.db.ExecContext(ctx, `UPDATE notify_channels SET last_success_at = ?, consecutive_failures = 0
			WHERE id = ?`, ms(now), id)
	} else {
		_, err = s.db.ExecContext(ctx, `UPDATE notify_channels SET last_error = ?, last_error_at = ?,
			consecutive_failures = consecutive_failures + 1 WHERE id = ?`, truncateText(errText), ms(now), id)
	}
	return err
}

// Delivery statuses.
const (
	DeliveryPending = "pending"
	DeliverySent    = "sent"
	DeliveryFailed  = "failed"
)

// Delivery is one queued message for one channel.
type Delivery struct {
	ID          int64
	ChannelID   int64
	CreatedAt   time.Time
	NextAttempt time.Time
	Attempts    int
	Status      string
	LastError   string
	SentAt      *time.Time
	Subject     string
	MessageJSON []byte
	EventIDs    []int64
}

func truncateText(s string) string {
	if r := []rune(s); len(r) > maxPollErrorLen {
		return string(r[:maxPollErrorLen]) + "…"
	}
	return s
}

// EnqueueDeliveries adds pending deliveries, filling in their IDs.
func (s *Store) EnqueueDeliveries(ctx context.Context, ds []Delivery) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for i := range ds {
			d := &ds[i]
			ids, err := json.Marshal(d.EventIDs)
			if err != nil {
				return err
			}
			if d.EventIDs == nil {
				ids = []byte("[]")
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO notify_deliveries (channel_id, created_at, next_attempt_at,
				status, subject, message_json, alert_event_ids) VALUES (?, ?, ?, 'pending', ?, ?, ?)`,
				d.ChannelID, ms(d.CreatedAt), ms(d.NextAttempt), d.Subject, string(d.MessageJSON), string(ids))
			if err != nil {
				return fmt.Errorf("store: enqueueing delivery: %w", err)
			}
			d.ID, _ = res.LastInsertId()
			d.Status = DeliveryPending
		}
		return nil
	})
}

const deliveryCols = `id, channel_id, created_at, next_attempt_at, attempts, status, last_error, sent_at, subject,
	message_json, alert_event_ids`

func scanDeliveries(rows *sql.Rows) ([]Delivery, error) {
	defer func() { _ = rows.Close() }()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var created, next int64
		var sent sql.NullInt64
		var msg, ids string
		if err := rows.Scan(&d.ID, &d.ChannelID, &created, &next, &d.Attempts, &d.Status, &d.LastError, &sent,
			&d.Subject, &msg, &ids); err != nil {
			return nil, err
		}
		d.CreatedAt, d.NextAttempt, d.SentAt = fromMS(created), fromMS(next), optTime(sent)
		d.MessageJSON = []byte(msg)
		if err := json.Unmarshal([]byte(ids), &d.EventIDs); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DueDeliveries returns pending deliveries whose next attempt is due.
func (s *Store) DueDeliveries(ctx context.Context, now time.Time, limit int) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+deliveryCols+` FROM notify_deliveries
		WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?`, ms(now), limit)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// NextDeliveryAt returns when the earliest pending delivery is due.
func (s *Store) NextDeliveryAt(ctx context.Context) (time.Time, bool, error) {
	var next sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT MIN(next_attempt_at) FROM notify_deliveries WHERE status = 'pending'").Scan(&next)
	if err != nil || !next.Valid {
		return time.Time{}, false, err
	}
	return fromMS(next.Int64), true, nil
}

// Deliveries returns the delivery log, newest first (channelID 0 = all).
func (s *Store) Deliveries(ctx context.Context, channelID int64, limit int) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+deliveryCols+` FROM notify_deliveries
		WHERE (? = 0 OR channel_id = ?) ORDER BY created_at DESC, id DESC LIMIT ?`, channelID, channelID, limit)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// MarkDeliverySent records a successful delivery.
func (s *Store) MarkDeliverySent(ctx context.Context, id int64, attempts int, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notify_deliveries SET status = 'sent', attempts = ?, sent_at = ?,
		last_error = '' WHERE id = ?`, attempts, ms(now), id)
	return err
}

// MarkDeliveryRetry schedules another attempt.
func (s *Store) MarkDeliveryRetry(ctx context.Context, id int64, attempts int, next time.Time, errText string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notify_deliveries SET attempts = ?, next_attempt_at = ?, last_error = ?
		WHERE id = ?`, attempts, ms(next), truncateText(errText), id)
	return err
}

// MarkDeliveryFailed gives up on a delivery.
func (s *Store) MarkDeliveryFailed(ctx context.Context, id int64, attempts int, errText string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notify_deliveries SET status = 'failed', attempts = ?, last_error = ?
		WHERE id = ?`, attempts, truncateText(errText), id)
	return err
}
