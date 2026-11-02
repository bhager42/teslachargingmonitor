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

// GetSetting decodes the JSON value stored under key into dst. It returns
// ErrNotFound when the key is not set.
func (s *Store) GetSetting(ctx context.Context, key string, dst any) error {
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key = ?", key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), dst)
}

// SetSetting stores v as JSON under key.
func (s *Store) SetSetting(ctx context.Context, key string, v any, now time.Time) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
		key, string(b), ms(now))
	return err
}

const retentionKey = "retention"

// KeepForever as a retention value disables pruning for that data class.
const KeepForever = 0

// Retention is the per-data-class retention policy in days (owner decision
// D15: adjustable in the GUI, readings default 2 years). 0 keeps forever.
type Retention struct {
	ReadingsDays    int `json:"readings_days"`
	RawPayloadsDays int `json:"raw_payloads_days"`
	RollupsDays     int `json:"rollups_days"`
	EventsDays      int `json:"events_days"` // device events and alert history
	PollLogDays     int `json:"poll_log_days"`
}

// DefaultRetention is used until the owner changes it.
func DefaultRetention() Retention {
	return Retention{
		ReadingsDays:    730,
		RawPayloadsDays: 90,
		RollupsDays:     KeepForever,
		EventsDays:      730,
		PollLogDays:     90,
	}
}

// MaxRetentionDays bounds custom values (100 years).
const MaxRetentionDays = 36500

// Validate checks every value is KeepForever or 1..MaxRetentionDays.
func (r Retention) Validate() error {
	for name, d := range map[string]int{
		"readings": r.ReadingsDays, "raw payloads": r.RawPayloadsDays, "rollups": r.RollupsDays,
		"events": r.EventsDays, "poll log": r.PollLogDays,
	} {
		if d < 0 || d > MaxRetentionDays {
			return fmt.Errorf("%s retention must be 0 (keep forever) or 1-%d days", name, MaxRetentionDays)
		}
	}
	return nil
}

// Retention returns the stored policy, or the default.
func (s *Store) Retention(ctx context.Context) (Retention, error) {
	r := DefaultRetention()
	err := s.GetSetting(ctx, retentionKey, &r)
	if errors.Is(err, ErrNotFound) {
		return DefaultRetention(), nil
	}
	if err != nil {
		return r, err
	}
	return r, r.Validate()
}

// SetRetention validates and stores a policy.
func (s *Store) SetRetention(ctx context.Context, r Retention, now time.Time) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return s.SetSetting(ctx, retentionKey, r, now)
}
