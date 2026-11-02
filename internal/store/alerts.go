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
	"fmt"
	"time"
)

// RuleOverride is the owner's change to an alert rule's defaults.
// DeviceID 0 applies to all devices.
type RuleOverride struct {
	RuleKey        string
	DeviceID       int64
	Enabled        bool
	Params         map[string]float64
	For            time.Duration
	Cooldown       time.Duration
	Repeat         time.Duration
	MinSamples     int
	NotifyResolved bool
	UpdatedAt      time.Time
}

// RuleOverrides returns all stored overrides.
func (s *Store) RuleOverrides(ctx context.Context) ([]RuleOverride, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rule_key, device_id, enabled, params_json, for_s, cooldown_s,
		repeat_s, min_samples, notify_resolved, updated_at FROM alert_rule_overrides ORDER BY rule_key, device_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RuleOverride
	for rows.Next() {
		var o RuleOverride
		var params string
		var forS, cool, rep, upd int64
		if err := rows.Scan(&o.RuleKey, &o.DeviceID, &o.Enabled, &params, &forS, &cool, &rep, &o.MinSamples,
			&o.NotifyResolved, &upd); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(params), &o.Params); err != nil {
			return nil, fmt.Errorf("store: rule %s params: %w", o.RuleKey, err)
		}
		o.For, o.Cooldown, o.Repeat = time.Duration(forS)*time.Second, time.Duration(cool)*time.Second, time.Duration(rep)*time.Second
		o.UpdatedAt = fromMS(upd)
		out = append(out, o)
	}
	return out, rows.Err()
}

// SaveRuleOverride inserts or replaces an override (validated by the caller).
func (s *Store) SaveRuleOverride(ctx context.Context, o RuleOverride, now time.Time) error {
	params := o.Params
	if params == nil {
		params = map[string]float64{}
	}
	b, err := json.Marshal(params)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR REPLACE INTO alert_rule_overrides (rule_key, device_id, enabled,
		params_json, for_s, cooldown_s, repeat_s, min_samples, notify_resolved, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.RuleKey, o.DeviceID, b2i(o.Enabled), string(b), int64(o.For/time.Second), int64(o.Cooldown/time.Second),
		int64(o.Repeat/time.Second), o.MinSamples, b2i(o.NotifyResolved), ms(now))
	return err
}

// DeleteRuleOverride restores a rule's defaults.
func (s *Store) DeleteRuleOverride(ctx context.Context, ruleKey string, deviceID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM alert_rule_overrides WHERE rule_key = ? AND device_id = ?", ruleKey, deviceID)
	return err
}

// AlertStateRow is the opaque persisted state of one (rule, device) pair.
type AlertStateRow struct {
	RuleKey  string
	DeviceID int64
	JSON     []byte
}

// AlertStates loads every persisted rule state.
func (s *Store) AlertStates(ctx context.Context) ([]AlertStateRow, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT rule_key, device_id, state_json FROM alert_state")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AlertStateRow
	for rows.Next() {
		var r AlertStateRow
		var js string
		if err := rows.Scan(&r.RuleKey, &r.DeviceID, &js); err != nil {
			return nil, err
		}
		r.JSON = []byte(js)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AlertEvent is one entry in the alert history.
type AlertEvent struct {
	ID       int64
	RuleKey  string
	DeviceID int64
	TS       time.Time
	Kind     string
	Severity string
	Message  string
	Value    *float64
	Notified bool
	AckedAt  *time.Time
}

// SaveAlertResult persists updated rule states and new alert events in one
// transaction, filling in the events' IDs.
func (s *Store) SaveAlertResult(ctx context.Context, states []AlertStateRow, events []AlertEvent, now time.Time) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for _, st := range states {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO alert_state (rule_key, device_id, state_json, updated_at)
				VALUES (?, ?, ?, ?)`, st.RuleKey, st.DeviceID, string(st.JSON), ms(now)); err != nil {
				return fmt.Errorf("store: saving alert state: %w", err)
			}
		}
		for i := range events {
			e := &events[i]
			var v any
			if e.Value != nil {
				v = *e.Value
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO alert_events (rule_key, device_id, ts, kind, severity, message,
				value, notified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				e.RuleKey, e.DeviceID, ms(e.TS), e.Kind, e.Severity, e.Message, v, b2i(e.Notified))
			if err != nil {
				return fmt.Errorf("store: saving alert event: %w", err)
			}
			if e.ID, err = res.LastInsertId(); err != nil {
				return err
			}
		}
		return nil
	})
}

// AlertEventFilter selects alert history.
type AlertEventFilter struct {
	DeviceID    int64 // 0 = all
	Since       time.Time
	UnackedOnly bool
	Limit       int // default 100
}

// AlertEvents returns alert history, newest first.
func (s *Store) AlertEvents(ctx context.Context, f AlertEventFilter) ([]AlertEvent, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	q := `SELECT id, rule_key, device_id, ts, kind, severity, message, value, notified, acked_at
		FROM alert_events WHERE ts >= ? AND (? = 0 OR device_id = ?) AND (? = 0 OR acked_at IS NULL)
		ORDER BY ts DESC, id DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, ms(f.Since), f.DeviceID, f.DeviceID, b2i(f.UnackedOnly), f.Limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AlertEvent
	for rows.Next() {
		var e AlertEvent
		var ts int64
		var v sql.NullFloat64
		var acked sql.NullInt64
		if err := rows.Scan(&e.ID, &e.RuleKey, &e.DeviceID, &ts, &e.Kind, &e.Severity, &e.Message, &v, &e.Notified, &acked); err != nil {
			return nil, err
		}
		e.TS = fromMS(ts)
		if v.Valid {
			e.Value = &v.Float64
		}
		if acked.Valid {
			t := fromMS(acked.Int64)
			e.AckedAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AckAlertEvent marks an alert event as acknowledged.
func (s *Store) AckAlertEvent(ctx context.Context, id int64, now time.Time) error {
	res, err := s.db.ExecContext(ctx, "UPDATE alert_events SET acked_at = ? WHERE id = ? AND acked_at IS NULL", ms(now), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Snooze mutes notifications for a device (RuleKey "") or one of its rules.
type Snooze struct {
	ID        int64
	DeviceID  int64
	RuleKey   string
	Until     time.Time
	Reason    string
	CreatedAt time.Time
}

// MaxSnooze bounds how long alerts can be muted.
const MaxSnooze = 30 * 24 * time.Hour

// AddSnooze stores a snooze ending at s.Until.
func (s *Store) AddSnooze(ctx context.Context, sn Snooze, now time.Time) (Snooze, error) {
	if !sn.Until.After(now) || sn.Until.Sub(now) > MaxSnooze {
		return Snooze{}, fmt.Errorf("store: snooze must end within %v", MaxSnooze)
	}
	if r := []rune(sn.Reason); len(r) > 200 {
		sn.Reason = string(r[:200])
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO alert_snoozes (device_id, rule_key, until_ts, reason, created_at)
		VALUES (?, ?, ?, ?, ?)`, sn.DeviceID, sn.RuleKey, ms(sn.Until), sn.Reason, ms(now))
	if err != nil {
		return Snooze{}, fmt.Errorf("store: adding snooze: %w", err)
	}
	sn.ID, _ = res.LastInsertId()
	sn.CreatedAt = now
	return sn, nil
}

// ActiveSnoozes returns snoozes for a device that have not expired.
func (s *Store) ActiveSnoozes(ctx context.Context, deviceID int64, now time.Time) ([]Snooze, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, device_id, rule_key, until_ts, reason, created_at FROM alert_snoozes
		WHERE device_id = ? AND until_ts > ? ORDER BY until_ts`, deviceID, ms(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Snooze
	for rows.Next() {
		var sn Snooze
		var until, created int64
		if err := rows.Scan(&sn.ID, &sn.DeviceID, &sn.RuleKey, &until, &sn.Reason, &created); err != nil {
			return nil, err
		}
		sn.Until, sn.CreatedAt = fromMS(until), fromMS(created)
		out = append(out, sn)
	}
	return out, rows.Err()
}

// DeleteSnooze ends a snooze early.
func (s *Store) DeleteSnooze(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM alert_snoozes WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
